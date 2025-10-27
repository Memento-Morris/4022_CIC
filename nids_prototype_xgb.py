import pandas as pd
import numpy as np
import tkinter as tk
from tkinter import scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import joblib
import time
import threading
import datetime
import os
import re
import csv
import json
import netifaces
import warnings
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, Raw

# Suppress sklearn version warnings
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

# Get the default gateway
gateways = netifaces.gateways()  
default_gateway = gateways.get('default', {})

# Constants
try:
    INTERFACE = default_gateway[netifaces.AF_INET][1]
except:
    raise Exception("Could not determine the default interface. Please specify the interface manually.")

TIME_WINDOW = 30  # Reduced from 60 for quicker detection
ACTIVITY_TIMEOUT = 5
CLEANUP_INTERVAL = 120
DEFAULT_MIN_PACKETS_FOR_ML = 5  # Default minimum packets for ML detection
DEFAULT_DETECTION_COOLDOWN = 300  # Default: 5 minutes cooldown per attack type

nids_script_dir = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(nids_script_dir,'../ml_models/supervised/xgboost.joblib')
RULES_PATH = os.path.join(nids_script_dir, 'ids_rules.json')

# Flow keys to whitelist
WHITELIST_PATTERNS = [
    re.compile(r"^0\.0\.0\.0:68->255\.255\.255\.255:67-UDP$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}:\d+->255\.255\.255\.255:68-UDP$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}:\d+->224\.0\.0\.251:5353-UDP$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}:\d+->\d+\.\d+\.\d+\.\d+:\d+-UDP$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}:\d+->\d+\.\d+\.\d+\.\d+:\d+-TCP$"),
]

class RuleBasedIDS:
    def __init__(self, rules_file):
        self.rules = self.load_rules(rules_file)
        self.compiled_patterns = self._compile_patterns()
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'start_time': None})
        self.rate_limit_tracker = defaultdict(lambda: deque(maxlen=100))
    
    def _compile_patterns(self):
        """Pre-compile all regex patterns for better performance"""
        compiled = {}
        for i, rule in enumerate(self.rules):
            if 'conditions' in rule and 'payload_patterns' in rule['conditions']:
                compiled[i] = []
                for pattern in rule['conditions']['payload_patterns']:
                    try:
                        compiled[i].append(re.compile(pattern, re.IGNORECASE))
                    except re.error:
                        pass
        return compiled
        
    def load_rules(self, rules_file):
        """Load IDS rules from JSON file"""
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                loaded_rules = []
                
                for rule in data.get('rules', []):
                    if not rule.get('enabled', True):
                        continue
                    
                    if 'conditions' in rule and 'payload_patterns' in rule['conditions']:
                        valid_patterns = []
                        for pattern in rule['conditions']['payload_patterns']:
                            try:
                                re.compile(pattern, re.IGNORECASE)
                                valid_patterns.append(pattern)
                            except re.error as e:
                                print(f"Skipping invalid pattern in rule '{rule.get('name', 'Unknown')}': {pattern}")
                                print(f"  Error: {e}")
                        
                        if valid_patterns or 'payload_patterns' not in rule['conditions']:
                            if valid_patterns:
                                rule['conditions']['payload_patterns'] = valid_patterns
                            loaded_rules.append(rule)
                    else:
                        loaded_rules.append(rule)
                
                print(f"Loaded {len(loaded_rules)} valid rules")
                return loaded_rules
                
        except FileNotFoundError:
            print(f"Rules file not found: {rules_file}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error parsing rules file: {e}")
            return []
    
    def reload_rules(self, rules_file):
        """Reload rules from file"""
        self.rules = self.load_rules(rules_file)
        self.compiled_patterns = self._compile_patterns()
        print(f"Reloaded {len(self.rules)} rules")
    
    def check_payload_patterns(self, payload, rule_index):
        """Check if payload matches any of the pre-compiled regex patterns"""
        if not payload or rule_index not in self.compiled_patterns:
            return False
        
        try:
            payload_str = str(payload)
            for compiled_pattern in self.compiled_patterns[rule_index]:
                try:
                    if compiled_pattern.search(payload_str):
                        return True
                except Exception as e:
                    print(f"Error matching pattern: {e}")
                    continue
        except Exception as e:
            print(f"Error checking payload patterns: {e}")
        return False
    
    def check_port_scan(self, src_ip, dst_port, threshold_config):
        """Detect port scanning activity"""
        current_time = time.time()
        tracker = self.port_scan_tracker[src_ip]
        
        if tracker['start_time'] is None:
            tracker['start_time'] = current_time
        
        if current_time - tracker['start_time'] > threshold_config['time_window']:
            tracker['ports'].clear()
            tracker['start_time'] = current_time
        
        tracker['ports'].add(dst_port)
        
        return len(tracker['ports']) >= threshold_config['unique_ports']
    
    def check_rate_limit(self, flow_key, dst_port, threshold_config):
        """Detect rate-based attacks"""
        if dst_port != threshold_config.get('dst_port'):
            return False
        
        current_time = time.time()
        tracker = self.rate_limit_tracker[flow_key]
        tracker.append(current_time)
        
        if len(tracker) < 2:
            return False
        
        recent_requests = sum(1 for t in tracker if current_time - t <= 1.0)
        return recent_requests > threshold_config['requests_per_second']
    
    def check_packet(self, packet, flow_key):
        """Check packet against all enabled rules"""
        alerts = []
        
        try:
            if IP not in packet:
                return alerts
            
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            dst_port = None
            protocol = None
            if TCP in packet:
                dst_port = packet[TCP].dport
                protocol = 'TCP'
            elif UDP in packet:
                dst_port = packet[UDP].dport
                protocol = 'UDP'
            
            payload = None
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    try:
                        payload = packet[Raw].load.hex()
                    except Exception:
                        payload = None
            
            packet_size = len(packet)
            
            for i, rule in enumerate(self.rules):
                try:
                    matched = False
                    rule_name = rule.get('name', 'Unknown Rule')
                    conditions = rule.get('conditions', {})
                    
                    if 'payload_patterns' in conditions and payload:
                        if self.check_payload_patterns(payload, i):
                            matched = True
                    
                    if 'port_scan_threshold' in conditions and dst_port:
                        if self.check_port_scan(ip_src, dst_port, conditions['port_scan_threshold']):
                            matched = True
                    
                    if 'rate_limit' in conditions and dst_port:
                        if self.check_rate_limit(flow_key, dst_port, conditions['rate_limit']):
                            matched = True
                    
                    if 'packet_size_threshold' in conditions:
                        if packet_size >= conditions['packet_size_threshold']:
                            matched = True
                    
                    if matched:
                        alert = {
                            'flow': flow_key,
                            'attack_type': f"Rule-Based: {rule.get('category', 'Unknown')}",
                            'rule_name': rule_name,
                            'severity': rule.get('severity', 'medium'),
                            'timestamp': datetime.datetime.now().isoformat(),
                            'src': f"{ip_src}:{dst_port if dst_port else 'N/A'}",
                            'dst': f"{ip_dst}:{dst_port if dst_port else 'N/A'}",
                            'protocol': protocol or 'Unknown',
                            'details': f"{rule_name} detected in flow {flow_key}",
                            'detection_method': 'rule-based'
                        }
                        alerts.append(alert)
                except Exception as e:
                    print(f"Error processing rule '{rule.get('name', 'Unknown')}': {e}")
                    continue
        
        except Exception as e:
            print(f"Error in check_packet: {e}")
        
        return alerts

class NetworkAnomalyDetector:
    def __init__(self, model_path, threshold=0.7, rules_file=None):
        # Load the pre-trained XGBoost model
        with open(model_path, 'rb') as f:
            self.model = joblib.load(f)
        self.capture_running = False
        
        # Detection threshold (global default)
        self.threshold = threshold
        
        # XGBoost-specific thresholds per attack class
        self.XGB_THRESHOLDS = {
            'Normal Traffic': 0.7,      # High threshold - reduce false positives on majority class
            'Bots': 0.25,               # Very low - Botnet is rare and hard to detect
            'Web Attacks': 0.35,        # Low - SQL Injection, XSS are subtle
            'Brute Force': 0.4,         # Medium-low - FTP/SSH Brute Force
            'Port Scanning': 0.3,       # Low - PortScan is common but varied patterns
            'DDoS': 0.5,                # Medium - LOIC DDoS is easier to detect
            'DoS': 0.45                 # Medium - DoS attacks like Hulk, GoldenEye
        }
        
        # Configurable parameters
        self.min_packets_for_ml = DEFAULT_MIN_PACKETS_FOR_ML
        self.detection_cooldown = DEFAULT_DETECTION_COOLDOWN
        
        # Rule-based IDS
        self.rule_based_ids = RuleBasedIDS(rules_file) if rules_file else None
        
        # Traffic statistics for feature extraction
        self.flow_stats = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'last_detection_time': None,
            'detected_attacks': set(),  # Track which attacks were already detected
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_packet_sizes': deque(maxlen=1000),
            'bwd_packet_sizes': deque(maxlen=1000),
            'packet_sizes': deque(maxlen=1000),
            'fwd_iat': deque(maxlen=1000),
            'bwd_iat': deque(maxlen=1000),
            'flow_iat': deque(maxlen=1000),
            'fwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'fin_flags': 0,
            'syn_flags': 0,
            'rst_flags': 0,
            'psh_flags': 0,
            'ack_flags': 0,
            'urg_flags': 0,
            'ece_flags': 0,
            'fwd_header_bytes': 0,
            'bwd_header_bytes': 0,
            'fwd_win_bytes': None,
            'bwd_win_bytes': None,
            'active_times': deque(maxlen=100),
            'idle_times': deque(maxlen=100),
            'last_active_time': None,
            'last_idle_time': None,
            'active_start': None,
            'idle_start': None,
            'last_packet_time': None,
            'last_fwd_packet_time': None,
            'last_bwd_packet_time': None,
            'min_seg_size_forward': float('inf'),
            'active': False,
            'fwd_data_packets': 0,
        })
        
        # Time window for flow aggregation (in seconds)
        self.time_window = TIME_WINDOW
        
        # Activity timeout (in seconds)
        self.activity_timeout = ACTIVITY_TIMEOUT
        
        # Alert system
        self.alerts = []
        self.alert_callback = None
        
        # Flow cache cleanup timer
        self.last_cleanup = time.time()
        self.cleanup_interval = CLEANUP_INTERVAL
        
        # Total packet count
        self.total_packets_processed = 0
        
        # Debug mode
        self.debug_mode = True
    
    def get_xgb_confidence_level(self, prediction, confidence_score):
        """XGBoost-specific confidence level classification based on attack type characteristics"""
        if prediction == 'Bots':
            # Botnet is rare and hard to detect - more lenient thresholds
            if confidence_score >= 0.5:
                return "VERY HIGH"
            elif confidence_score >= 0.3:
                return "HIGH"
            elif confidence_score >= 0.2:
                return "MEDIUM"
            else:
                return "LOW"
        
        elif prediction == 'Web Attacks':
            # SQL Injection, XSS are subtle - adjusted thresholds
            if confidence_score >= 0.6:
                return "VERY HIGH"
            elif confidence_score >= 0.4:
                return "HIGH"
            elif confidence_score >= 0.3:
                return "MEDIUM"
            else:
                return "LOW"
        
        elif prediction == 'Port Scanning':
            # PortScan has varied patterns - moderate thresholds
            if confidence_score >= 0.5:
                return "VERY HIGH"
            elif confidence_score >= 0.35:
                return "HIGH"
            elif confidence_score >= 0.25:
                return "MEDIUM"
            else:
                return "LOW"
        
        else:  # DDoS, DoS, Brute Force - easier to detect with clearer patterns
            if confidence_score >= 0.7:
                return "VERY HIGH"
            elif confidence_score >= 0.5:
                return "HIGH"
            elif confidence_score >= 0.4:
                return "MEDIUM"
            else:
                return "LOW"
    
    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback
    
    def validate_features(self, features):
        """Validate if features are reasonable for ML prediction"""
        if features is None:
            return False
            
        # Check for minimum data requirements
        total_packets = features.get('Total Fwd Packets', 0) + features.get('Total Bwd Packets', 0)
        if total_packets < 2:
            if self.debug_mode:
                print(f"[DEBUG] Insufficient packets: {total_packets}")
            return False
        
        # Check flow duration
        if features.get('Flow Duration', 0) < 0.1:  # At least 0.1ms
            if self.debug_mode:
                print(f"[DEBUG] Flow duration too short: {features.get('Flow Duration', 0)}")
            return False
        
        # Check for extreme outliers that might indicate bad feature calculation
        if features.get('Flow Bytes/s', 0) > 1e9:  # > 1 GB/s is unrealistic
            if self.debug_mode:
                print(f"[DEBUG] Unrealistic flow bytes/s: {features.get('Flow Bytes/s', 0)}")
            return False
            
        return True
    
    def process_packet(self, packet):
        """Process a single packet and update flow statistics"""
        try:
            if IP not in packet:
                return
            
            self.total_packets_processed += 1
            
            # Extract IP addresses
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Determine protocol and ports
            if TCP in packet:
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                header_length = len(packet[TCP])
                
                # Extract window size
                if hasattr(packet[TCP], 'window'):
                    window_size = packet[TCP].window
                else:
                    window_size = 0
                    
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                header_length = len(packet[UDP])
                window_size = 0
            
            else:
                # Skip non-TCP/UDP packets
                return
            
            # Create directional flow keys (src->dst and dst->src)
            forward_key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{protocol}"
            backward_key = f"{ip_dst}:{dst_port}-{ip_src}:{src_port}-{protocol}"
            
            # Rule-based detection (runs on every packet)
            if self.rule_based_ids:
                try:
                    rule_alerts = self.rule_based_ids.check_packet(packet, forward_key)
                    for alert in rule_alerts:
                        self.alerts.append(alert)
                        if self.alert_callback:
                            self.alert_callback(alert)
                except Exception as e:
                    print(f"Error in rule-based detection: {e}")
            
            # Determine flow direction
            packet_size = len(packet)
            current_time = time.time()
            is_forward = True
            
            # Check if this is part of an existing flow
            if forward_key in self.flow_stats:
                flow_key = forward_key
            elif backward_key in self.flow_stats:
                flow_key = backward_key
                is_forward = False
            else:
                # New flow, use forward key
                flow_key = forward_key
            
            # Get flow statistics
            flow = self.flow_stats[flow_key]
            
            # Initialize flow if this is the first packet
            if flow['start_time'] is None:
                flow['start_time'] = current_time
                flow['active_start'] = current_time
                flow['active'] = True
            
            # Update flow end time
            flow['end_time'] = current_time
            
            # Calculate and store inter-arrival time
            if flow['last_packet_time'] is not None:
                iat = current_time - flow['last_packet_time']
                flow['flow_iat'].append(iat)
                
                # Check if it is needed to update active/idle times
                if iat > self.activity_timeout:
                    if flow['active_start'] is not None:
                        active_time = flow['last_packet_time'] - flow['active_start']
                        flow['active_times'].append(active_time)
                        flow['active_start'] = None
                        flow['idle_start'] = flow['last_packet_time']
                    
                    if flow['idle_start'] is not None:
                        idle_time = current_time - flow['idle_start']
                        flow['idle_times'].append(idle_time)
                        flow['idle_start'] = None
                    
                    flow['active_start'] = current_time
                    flow['active'] = True
                
            flow['last_packet_time'] = current_time
            
            # Update direction-specific statistics
            if is_forward:
                flow['fwd_packets'] += 1
                flow['fwd_bytes'] += packet_size
                flow['packet_sizes'].append(packet_size)
                flow['fwd_packet_sizes'].append(packet_size)
                
                if protocol == 'TCP':
                    if packet[TCP].flags & 0x08:  # PSH flag
                        flow['fwd_psh_flags'] += 1
                        flow['psh_flags'] += 1
                    
                    if packet[TCP].flags & 0x20:  # URG flag
                        flow['fwd_urg_flags'] += 1
                        flow['urg_flags'] += 1
                    
                    if hasattr(packet[TCP], 'flags'):
                        if packet[TCP].flags & 0x01:  # FIN flag
                            flow['fin_flags'] += 1
                        if packet[TCP].flags & 0x02:  # SYN flag
                            flow['syn_flags'] += 1
                        if packet[TCP].flags & 0x04:  # RST flag
                            flow['rst_flags'] += 1
                        if packet[TCP].flags & 0x10:  # ACK flag
                            flow['ack_flags'] += 1
                        if packet[TCP].flags & 0x40:  # ECE flag
                            flow['ece_flags'] += 1
                    
                    # Update min_seg_size_forward
                    if hasattr(packet[TCP], 'options'):
                        mss = next((x[1] for x in packet[TCP].options if x[0] == 'MSS'), None)
                        if mss is not None and mss < flow['min_seg_size_forward']:
                            flow['min_seg_size_forward'] = mss
                
                flow['fwd_header_bytes'] += header_length
                
                # Store initial window size
                if flow['fwd_win_bytes'] is None and window_size > 0:
                    flow['fwd_win_bytes'] = window_size
                
                # Check if this is a data packet
                if TCP in packet and len(packet[TCP].payload) > 0:
                    flow['fwd_data_packets'] += 1
                
                # Update IAT for forward packets
                if flow['last_fwd_packet_time'] is not None:
                    flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
                flow['last_fwd_packet_time'] = current_time
                
            else:
                flow['bwd_packets'] += 1
                flow['bwd_bytes'] += packet_size
                flow['packet_sizes'].append(packet_size)
                flow['bwd_packet_sizes'].append(packet_size)
                flow['bwd_header_bytes'] += header_length
                
                # Store initial window size
                if flow['bwd_win_bytes'] is None and window_size > 0:
                    flow['bwd_win_bytes'] = window_size
                
                # Update IAT for backward packets
                if flow['last_bwd_packet_time'] is not None:
                    flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
                flow['last_bwd_packet_time'] = current_time
            
            # ML-based detection with improved logic
            total_packets = flow['fwd_packets'] + flow['bwd_packets']
            
            # More frequent detection attempts
            should_detect = False
            
            # First detection: after minimum packets OR time window
            if (flow['last_detection_time'] is None and 
                (total_packets >= self.min_packets_for_ml or 
                 current_time - flow['start_time'] >= self.time_window)):
                should_detect = True
            
            # Subsequent detections: periodic re-evaluation
            elif (flow['last_detection_time'] is not None and 
                  current_time - flow['last_detection_time'] >= self.time_window and 
                  total_packets >= 2):  # Reduced minimum for updates
                should_detect = True

            if should_detect:
                self.detect_anomalies(flow_key)
            
            # Periodically clean up old flows
            if current_time - self.last_cleanup > self.cleanup_interval:
                self.cleanup_old_flows()
                self.last_cleanup = current_time
        
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def extract_features(self, flow_key):
        """Extract features from flow statistics that match CICIDS2017 features"""
        flow = self.flow_stats[flow_key]
        
        # Skip flows with too few packets
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        if total_packets < 2:
            if self.debug_mode:
                print(f"[DEBUG] Not enough packets for features: {total_packets}")
            return None
        
        # Calculate flow duration
        duration = flow['end_time'] - flow['start_time']
        if duration <= 0:  # Avoid division by zero
            duration = 0.001
        
        # Initialize features dictionary
        features = {}
        
        # Get destination port from flow key
        parts = flow_key.split('-')
        if len(parts) >= 2:
            try:
                dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
                features['Destination Port'] = int(dst_part)
            except:
                features['Destination Port'] = 0
        else:
            features['Destination Port'] = 0
            
        # Basic flow features
        features['Flow Duration'] = duration * 1000  # Convert to milliseconds
        features['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration if duration > 0 else 0
        features['Flow Packets/s'] = total_packets / duration if duration > 0 else 0
        
        # Forward packet features
        features['Total Fwd Packets'] = flow['fwd_packets']
        features['Total Length of Fwd Packets'] = flow['fwd_bytes']
        
        # Robust statistics for small samples
        if flow['fwd_packet_sizes']:
            features['Fwd Packet Length Min'] = min(flow['fwd_packet_sizes'])
            features['Fwd Packet Length Max'] = max(flow['fwd_packet_sizes'])
            features['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_sizes'])
            features['Fwd Packet Length Std'] = np.std(flow['fwd_packet_sizes']) if len(flow['fwd_packet_sizes']) > 1 else 0
        else:
            features['Fwd Packet Length Min'] = 0
            features['Fwd Packet Length Max'] = 0
            features['Fwd Packet Length Mean'] = 0
            features['Fwd Packet Length Std'] = 0
            
        features['Fwd Packets/s'] = flow['fwd_packets'] / duration if duration > 0 else 0
        features['Fwd Header Length'] = flow['fwd_header_bytes']
        
        # Backward packet features
        features['Bwd Packets/s'] = flow['bwd_packets'] / duration if duration > 0 else 0
        
        if flow['bwd_packet_sizes']:
            features['Bwd Packet Length Min'] = min(flow['bwd_packet_sizes'])
            features['Bwd Packet Length Max'] = max(flow['bwd_packet_sizes'])
            features['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_sizes'])
            features['Bwd Packet Length Std'] = np.std(flow['bwd_packet_sizes']) if len(flow['bwd_packet_sizes']) > 1 else 0
        else:
            features['Bwd Packet Length Min'] = 0
            features['Bwd Packet Length Max'] = 0
            features['Bwd Packet Length Mean'] = 0
            features['Bwd Packet Length Std'] = 0
            
        features['Bwd Header Length'] = flow['bwd_header_bytes']
        
        # Packet length features
        if flow['packet_sizes']:
            features['Min Packet Length'] = min(flow['packet_sizes'])
            features['Max Packet Length'] = max(flow['packet_sizes'])
            features['Packet Length Mean'] = np.mean(flow['packet_sizes'])
            features['Packet Length Std'] = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
            features['Packet Length Variance'] = np.var(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        else:
            features['Min Packet Length'] = 0
            features['Max Packet Length'] = 0
            features['Packet Length Mean'] = 0
            features['Packet Length Std'] = 0
            features['Packet Length Variance'] = 0
        
        # Average packet size
        if total_packets > 0:
            features['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_packets
        else:
            features['Average Packet Size'] = 0
        
        # IAT (Inter Arrival Time) features with robust handling
        if flow['flow_iat']:
            features['Flow IAT Mean'] = np.mean(flow['flow_iat'])
            features['Flow IAT Std'] = np.std(flow['flow_iat']) if len(flow['flow_iat']) > 1 else 0
            features['Flow IAT Max'] = max(flow['flow_iat'])
            features['Flow IAT Min'] = min(flow['flow_iat'])
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0
        
        # Forward IAT
        if flow['fwd_iat']:
            features['Fwd IAT Total'] = sum(flow['fwd_iat'])
            features['Fwd IAT Mean'] = np.mean(flow['fwd_iat'])
            features['Fwd IAT Std'] = np.std(flow['fwd_iat']) if len(flow['fwd_iat']) > 1 else 0
            features['Fwd IAT Max'] = max(flow['fwd_iat'])
            features['Fwd IAT Min'] = min(flow['fwd_iat'])
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0
        
        # Backward IAT
        if flow['bwd_iat']:
            features['Bwd IAT Total'] = sum(flow['bwd_iat'])
            features['Bwd IAT Mean'] = np.mean(flow['bwd_iat'])
            features['Bwd IAT Std'] = np.std(flow['bwd_iat']) if len(flow['bwd_iat']) > 1 else 0
            features['Bwd IAT Max'] = max(flow['bwd_iat'])
            features['Bwd IAT Min'] = min(flow['bwd_iat'])
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0
        
        # Flag counts
        features['PSH Flag Count'] = flow['psh_flags']
        features['FIN Flag Count'] = flow['fin_flags']
        features['ACK Flag Count'] = flow['ack_flags']
        
        # Window features
        features['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] if flow['fwd_win_bytes'] is not None else 0
        features['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] if flow['bwd_win_bytes'] is not None else 0
        
        # Active and idle time statistics
        if flow['active_times']:
            features['Active Mean'] = np.mean(flow['active_times'])
            features['Active Max'] = max(flow['active_times'])
            features['Active Min'] = min(flow['active_times'])
        else:
            features['Active Mean'] = 0
            features['Active Max'] = 0
            features['Active Min'] = 0
        
        if flow['idle_times']:
            features['Idle Mean'] = np.mean(flow['idle_times'])
            features['Idle Max'] = max(flow['idle_times'])
            features['Idle Min'] = min(flow['idle_times'])
        else:
            features['Idle Mean'] = 0
            features['Idle Max'] = 0
            features['Idle Min'] = 0
        
        # Additional features
        features['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
        features['act_data_pkt_fwd'] = flow['fwd_data_packets']
        
        # Calculate Subflow statistics
        features['Subflow Fwd Bytes'] = flow['fwd_bytes']
        
        if self.debug_mode:
            print(f"[DEBUG] Extracted features for {flow_key}:")
            print(f"  Packets: {total_packets}, Duration: {features['Flow Duration']:.2f}ms")
            print(f"  Bytes/s: {features['Flow Bytes/s']:.2f}")
            
        return features
    
    def is_whitelisted(self, flow_key):
        for pattern in WHITELIST_PATTERNS:
            if pattern.match(flow_key):
                return True
        return False
    
    def detect_anomalies(self, flow_key):
        """Detect anomalies in a flow using the XGBoost model"""
        if self.is_whitelisted(flow_key):
            return

        features = self.extract_features(flow_key)
        if features is None:
            return
        
        # Validate features before ML prediction
        if not self.validate_features(features):
            if self.debug_mode:
                print(f"[DEBUG] Feature validation failed for {flow_key}")
            return
        
        flow = self.flow_stats[flow_key]
        current_time = time.time()
        
        # Create a DataFrame with the extracted features
        df = pd.DataFrame([features])
        
        # Make sure all required features are present
        model_features = self.model.get_booster().feature_names
        if not model_features:
            print("Using hardcoded feature list!")
            model_features = [
                'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
            ]
               
        # Add missing features with default values
        df = df.reindex(columns=model_features, fill_value=0)

        # Define class names for readability (according to the what was defined during training)
        class_names = ['Normal Traffic', 'DoS', 'DDoS', 'Port Scanning', 'Brute Force', 'Web Attacks', 'Bots']
        
        # Make prediction
        try:
            # Predict anomaly
            predicted_class_idx = self.model.predict(df)[0]
            predicted_class = class_names[predicted_class_idx]
            
            # Get the predicted class probabilities
            probabilities = self.model.predict_proba(df)
            confidence_score = probabilities[0][predicted_class_idx]
            
            # Debug logs
            total_packets = flow['fwd_packets'] + flow['bwd_packets']
            if self.debug_mode:
                confidence_level = self.get_xgb_confidence_level(predicted_class, confidence_score)
                print(f"[ML DEBUG] Flow: {flow_key}")
                print(f"[ML DEBUG] Predicted: {predicted_class} ({confidence_score:.4f}) - {confidence_level}")
                print(f"[ML DEBUG] Total packets: {total_packets}, Duration: {features['Flow Duration']:.2f}ms")

            # Check if the prediction is anything other than Normal Traffic and above the class-specific threshold
            class_threshold = self.XGB_THRESHOLDS.get(predicted_class, self.threshold)
            
            if predicted_class != 'Normal Traffic' and confidence_score >= class_threshold:
                # Check cooldown for this specific attack type
                cooldown_key = f'cooldown_{predicted_class}'
                last_alert_time = flow.get(cooldown_key, 0)
                
                if current_time - last_alert_time < self.detection_cooldown:
                    if self.debug_mode:
                        print(f"[ML DEBUG] Cooldown active for {predicted_class}, skipping alert")
                    flow['last_detection_time'] = current_time
                    return
                
                # Update cooldown
                flow[cooldown_key] = current_time
                
                # Get confidence level
                confidence_level = self.get_xgb_confidence_level(predicted_class, confidence_score)
                
                parts = flow_key.split('-')
                src_part = parts[0]
                dst_part = parts[1]
                protocol = parts[2] if len(parts) > 2 else "Unknown"
                
                ip_src = src_part.rsplit(':', 1)[0]
                port_src = src_part.rsplit(':', 1)[1]
                ip_dst = dst_part.rsplit(':', 1)[0]
                port_dst = dst_part.rsplit(':', 1)[1]
                
                alert = {
                    'flow': flow_key,
                    'attack_type': f"ML-Based: {predicted_class}",
                    'confidence': float(confidence_score),
                    'confidence_level': confidence_level,
                    'threshold_used': class_threshold,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'src': f"{ip_src}:{port_src}",
                    'dst': f"{ip_dst}:{port_dst}",
                    'protocol': protocol,
                    'details': f"{predicted_class} detected in flow {ip_src}:{port_src} -> {ip_dst}:{port_dst} [{protocol}] with confidence {confidence_score:.4f} ({confidence_level}) (packets: {total_packets})",
                    'detection_method': 'ml-based'
                }
                self.alerts.append(alert)
                
                print(f"[ML ALERT] Generated alert for {predicted_class}")
                
                # Call the alert callback if set
                if self.alert_callback:
                    self.alert_callback(alert)
        
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            import traceback
            traceback.print_exc()
        
        # Update detection time
        self.flow_stats[flow_key]['last_detection_time'] = current_time
    
    def cleanup_old_flows(self):
        """Remove flows that have been inactive for too long"""
        current_time = time.time()
        to_remove = []
        
        for flow_key, flow in self.flow_stats.items():
            if flow['last_packet_time'] is not None and current_time - flow['last_packet_time'] > self.cleanup_interval:               
                # Mark for removal since it's inactive
                to_remove.append(flow_key)
        
        # Remove inactive flows
        for flow_key in to_remove:
            del self.flow_stats[flow_key]
        
        if to_remove and self.debug_mode:
            print(f"[CLEANUP] Removed {len(to_remove)} inactive flows")
    
    def start_capture(self, interface=None, filter=None):
        """Start packet capture in a separate thread"""
        self.capture_running = True
        def capture_thread():
            try:
                while self.capture_running:
                    sniff(
                        iface=interface,
                        filter=filter,
                        prn=self.process_packet,
                        store=0,
                        timeout=1,  # Sniff in short increments
                        stop_filter=lambda x: not self.capture_running
                    )
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.capture_running = False # Reset
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
        return thread

    def get_total_packets(self):
        """Get the total number of packets processed"""
        return self.total_packets_processed
    
    def get_alert_stats(self):
        """Get attack type counts for graphing"""
        attack_counts = defaultdict(int)
        for alert in self.alerts:
            attack_counts[alert['attack_type']] += 1
        return dict(attack_counts)

class NetworkAnomalyGUI:
    def __init__(self, detector):
        self.detector = detector
        self.root = tk.Tk()
        self.root.title("Hybrid Network IDS - Rule-Based + XGBoost ML Detection")
        self.root.geometry("1200x750")
        
        self.setup_ui()
        
        # Set the alert callback
        self.detector.set_alert_callback(self.add_alert)
    
    def setup_ui(self):
        # Control frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Interface selection
        tk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar(value=INTERFACE)
        interface_entry = tk.Entry(control_frame, textvariable=self.interface_var, width=10)
        interface_entry.pack(side=tk.LEFT, padx=5)
        
        # Filter
        tk.Label(control_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_entry = tk.Entry(control_frame, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        # Start/Stop button
        self.running = False
        self.start_stop_btn = tk.Button(control_frame, text="Start", command=self.toggle_capture, bg="green", fg="white")
        self.start_stop_btn.pack(side=tk.LEFT, padx=20)
        
        # Clear button
        tk.Button(control_frame, text="Clear Alerts", command=self.clear_alerts).pack(side=tk.LEFT, padx=5)
        
        # Reload rules button
        tk.Button(control_frame, text="Reload Rules", command=self.reload_rules).pack(side=tk.LEFT, padx=5)
        
        # XGBoost-specific controls frame
        xgb_frame = tk.LabelFrame(self.root, text="XGBoost Configuration", padx=10, pady=5)
        xgb_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Class-specific threshold controls
        thresholds_frame = tk.Frame(xgb_frame)
        thresholds_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(thresholds_frame, text="Attack-Specific Thresholds:", font=("Arial", 9, "bold")).grid(row=0, column=0, columnspan=8, sticky=tk.W, pady=2)
        
        # Bots threshold
        tk.Label(thresholds_frame, text="Bots:", font=("Arial", 8)).grid(row=1, column=0, sticky=tk.W, padx=2)
        self.bots_threshold_var = tk.DoubleVar(value=self.detector.XGB_THRESHOLDS['Bots'])
        bots_entry = tk.Entry(thresholds_frame, textvariable=self.bots_threshold_var, width=5, font=("Arial", 8))
        bots_entry.grid(row=1, column=1, padx=2)
        
        # Web Attacks threshold
        tk.Label(thresholds_frame, text="Web:", font=("Arial", 8)).grid(row=1, column=2, sticky=tk.W, padx=2)
        self.web_threshold_var = tk.DoubleVar(value=self.detector.XGB_THRESHOLDS['Web Attacks'])
        web_entry = tk.Entry(thresholds_frame, textvariable=self.web_threshold_var, width=5, font=("Arial", 8))
        web_entry.grid(row=1, column=3, padx=2)
        
        # Brute Force threshold
        tk.Label(thresholds_frame, text="Brute Force:", font=("Arial", 8)).grid(row=1, column=4, sticky=tk.W, padx=2)
        self.brute_threshold_var = tk.DoubleVar(value=self.detector.XGB_THRESHOLDS['Brute Force'])
        brute_entry = tk.Entry(thresholds_frame, textvariable=self.brute_threshold_var, width=5, font=("Arial", 8))
        brute_entry.grid(row=1, column=5, padx=2)
        
        # Port Scanning threshold
        tk.Label(thresholds_frame, text="Port Scan:", font=("Arial", 8)).grid(row=2, column=0, sticky=tk.W, padx=2)
        self.portscan_threshold_var = tk.DoubleVar(value=self.detector.XGB_THRESHOLDS['Port Scanning'])
        portscan_entry = tk.Entry(thresholds_frame, textvariable=self.portscan_threshold_var, width=5, font=("Arial", 8))
        portscan_entry.grid(row=2, column=1, padx=2)
        
        # DDoS threshold
        tk.Label(thresholds_frame, text="DDoS:", font=("Arial", 8)).grid(row=2, column=2, sticky=tk.W, padx=2)
        self.ddos_threshold_var = tk.DoubleVar(value=self.detector.XGB_THRESHOLDS['DDoS'])
        ddos_entry = tk.Entry(thresholds_frame, textvariable=self.ddos_threshold_var, width=5, font=("Arial", 8))
        ddos_entry.grid(row=2, column=3, padx=2)
        
        # DoS threshold
        tk.Label(thresholds_frame, text="DoS:", font=("Arial", 8)).grid(row=2, column=4, sticky=tk.W, padx=2)
        self.dos_threshold_var = tk.DoubleVar(value=self.detector.XGB_THRESHOLDS['DoS'])
        dos_entry = tk.Entry(thresholds_frame, textvariable=self.dos_threshold_var, width=5, font=("Arial", 8))
        dos_entry.grid(row=2, column=5, padx=2)
        
        # Apply thresholds button
        tk.Button(thresholds_frame, text="Apply Thresholds", command=self.apply_xgb_thresholds, 
                 font=("Arial", 8), bg='#3498db', fg='white').grid(row=2, column=6, padx=10)
        
        # Detection parameters frame
        params_frame = tk.Frame(xgb_frame)
        params_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(params_frame, text="Detection Parameters:", font=("Arial", 9, "bold")).grid(row=0, column=0, columnspan=6, sticky=tk.W, pady=2)
        
        # Min packets for ML
        tk.Label(params_frame, text="Min Packets:", font=("Arial", 8)).grid(row=1, column=0, sticky=tk.W, padx=2)
        self.min_packets_var = tk.IntVar(value=self.detector.min_packets_for_ml)
        min_packets_entry = tk.Entry(params_frame, textvariable=self.min_packets_var, width=5, font=("Arial", 8))
        min_packets_entry.grid(row=1, column=1, padx=2)
        
        # Cooldown period
        tk.Label(params_frame, text="Cooldown (sec):", font=("Arial", 8)).grid(row=1, column=2, sticky=tk.W, padx=2)
        self.cooldown_var = tk.IntVar(value=self.detector.detection_cooldown)
        cooldown_entry = tk.Entry(params_frame, textvariable=self.cooldown_var, width=6, font=("Arial", 8))
        cooldown_entry.grid(row=1, column=3, padx=2)
        
        # Apply parameters button
        tk.Button(params_frame, text="Apply Parameters", command=self.apply_detection_params, 
                 font=("Arial", 8), bg='#2ecc71', fg='white').grid(row=1, column=4, padx=10)
        
        # Main content frame
        content_frame = tk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left side - Alert log
        left_frame = tk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(left_frame, text="Detection Alerts:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        self.alert_log = scrolledtext.ScrolledText(left_frame, height=20, width=60)
        self.alert_log.pack(fill=tk.BOTH, expand=True)
        
        # Right side - Graph
        right_frame = tk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        tk.Label(right_frame, text="Attack Types Distribution:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(5, 4), dpi=80)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=right_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize empty graph
        self.update_graph()
        
        # Statistics frame
        stats_frame = tk.Frame(self.root)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="Packets Processed:", font=("Arial", 9)).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.packets_var = tk.StringVar(value="0")
        tk.Label(stats_frame, textvariable=self.packets_var, font=("Arial", 9, "bold")).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        tk.Label(stats_frame, text="Total Alerts:", font=("Arial", 9)).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.alerts_var = tk.StringVar(value="0")
        tk.Label(stats_frame, textvariable=self.alerts_var, font=("Arial", 9, "bold"), fg="red").grid(row=0, column=3, sticky=tk.W, padx=5)
        
        tk.Label(stats_frame, text="Rule-Based:", font=("Arial", 9)).grid(row=0, column=4, sticky=tk.W, padx=5)
        self.rule_alerts_var = tk.StringVar(value="0")
        tk.Label(stats_frame, textvariable=self.rule_alerts_var, font=("Arial", 9, "bold"), fg="orange").grid(row=0, column=5, sticky=tk.W, padx=5)
        
        tk.Label(stats_frame, text="ML-Based:", font=("Arial", 9)).grid(row=0, column=6, sticky=tk.W, padx=5)
        self.ml_alerts_var = tk.StringVar(value="0")
        tk.Label(stats_frame, textvariable=self.ml_alerts_var, font=("Arial", 9, "bold"), fg="purple").grid(row=0, column=7, sticky=tk.W, padx=5)
        
        tk.Label(stats_frame, text="Min Packets:", font=("Arial", 9)).grid(row=0, column=8, sticky=tk.W, padx=5)
        self.min_packets_display = tk.StringVar(value=str(self.detector.min_packets_for_ml))
        tk.Label(stats_frame, textvariable=self.min_packets_display, font=("Arial", 9, "bold")).grid(row=0, column=9, sticky=tk.W, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready | Rule-Based IDS: Active | ML Thresholds: Optimized")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Start statistics update
        self.update_statistics()
    
    def reload_rules(self):
        """Reload IDS rules from file"""
        if self.detector.rule_based_ids:
            self.detector.rule_based_ids.reload_rules(RULES_PATH)
            self.add_log_message(f"Rules reloaded from {RULES_PATH}")
            self.status_var.set(f"Rules reloaded | {len(self.detector.rule_based_ids.rules)} active rules")
        else:
            self.add_log_message("Rule-based IDS not initialized")
    
    def apply_xgb_thresholds(self):
        """Apply custom XGBoost thresholds"""
        try:
            self.detector.XGB_THRESHOLDS['Bots'] = self.bots_threshold_var.get()
            self.detector.XGB_THRESHOLDS['Web Attacks'] = self.web_threshold_var.get()
            self.detector.XGB_THRESHOLDS['Brute Force'] = self.brute_threshold_var.get()
            self.detector.XGB_THRESHOLDS['Port Scanning'] = self.portscan_threshold_var.get()
            self.detector.XGB_THRESHOLDS['DDoS'] = self.ddos_threshold_var.get()
            self.detector.XGB_THRESHOLDS['DoS'] = self.dos_threshold_var.get()
            
            self.add_log_message("XGBoost thresholds updated successfully")
            self.status_var.set(f"Thresholds applied | Bots: {self.detector.XGB_THRESHOLDS['Bots']}, Web: {self.detector.XGB_THRESHOLDS['Web Attacks']}")
        except Exception as e:
            self.add_log_message(f"Error applying thresholds: {e}")
    
    def apply_detection_params(self):
        """Apply detection parameters"""
        try:
            self.detector.min_packets_for_ml = self.min_packets_var.get()
            self.detector.detection_cooldown = self.cooldown_var.get()
            
            # Update display
            self.min_packets_display.set(str(self.detector.min_packets_for_ml))
            
            self.add_log_message(f"Detection parameters updated: Min Packets={self.detector.min_packets_for_ml}, Cooldown={self.detector.detection_cooldown}s")
            self.status_var.set(f"Parameters applied | Min Packets: {self.detector.min_packets_for_ml} | Cooldown: {self.detector.detection_cooldown}s")
        except Exception as e:
            self.add_log_message(f"Error applying parameters: {e}")
    
    def update_graph(self):
        """Update the attack types bar graph"""
        self.ax.clear()
        
        attack_stats = self.detector.get_alert_stats()
        
        if attack_stats:
            attacks = list(attack_stats.keys())
            counts = list(attack_stats.values())
            
            # Color code by detection method
            colors = []
            for attack in attacks:
                if 'Rule-Based' in attack:
                    colors.append('#ff8c42')  # Orange for rule-based
                elif 'ML-Based' in attack:
                    colors.append('#9b59b6')  # Purple for ML-based
                else:
                    colors.append('#e74c3c')  # Red for others
            
            bars = self.ax.bar(range(len(attacks)), counts, color=colors)
            
            self.ax.set_xlabel('Attack Type', fontsize=9)
            self.ax.set_ylabel('Count', fontsize=9)
            self.ax.set_title('Detected Attacks (Orange=Rule | Purple=ML)', fontsize=9, fontweight='bold')
            self.ax.set_xticks(range(len(attacks)))
            self.ax.set_xticklabels(attacks, rotation=45, ha='right', fontsize=7)
            self.ax.grid(axis='y', alpha=0.3)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                self.ax.text(bar.get_x() + bar.get_width()/2., height,
                           f'{int(height)}',
                           ha='center', va='bottom', fontsize=8)
        else:
            self.ax.text(0.5, 0.5, 'No attacks detected yet', 
                        ha='center', va='center', transform=self.ax.transAxes,
                        fontsize=12, color='gray')
            self.ax.set_xlim(0, 1)
            self.ax.set_ylim(0, 1)
        
        self.fig.tight_layout()
        self.canvas.draw()
    
    def toggle_capture(self):
        if not self.running:
            # Start capture
            interface = self.interface_var.get() if self.interface_var.get() else None
            filter_str = self.filter_var.get() if self.filter_var.get() else None
            
            try:
                self.capture_thread = self.detector.start_capture(interface=interface, filter=filter_str)
                self.running = True
                self.start_stop_btn.config(text="Stop", bg="red")
                rules_count = len(self.detector.rule_based_ids.rules) if self.detector.rule_based_ids else 0
                self.status_var.set(f"Capturing on {interface or 'default interface'} | {rules_count} rules | Min packets: {self.detector.min_packets_for_ml} | Cooldown: {self.detector.detection_cooldown}s")
                self.add_log_message(f"Started capture on {interface or 'default interface'}")
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
        else:
            self.detector.capture_running = False # Set flag to stop.
            self.running = False
            self.start_stop_btn.config(text="Start", bg="green")
            self.status_var.set("Capture stopped")
            self.add_log_message("Stopped capture")
    
    def add_alert(self, alert):
        """Add an alert to the log and update graph"""
        timestamp = alert.get('timestamp', datetime.datetime.now().isoformat())
        attack_type = alert.get('attack_type', 'Unknown')
        src = alert.get('src', 'N/A')
        dst = alert.get('dst', 'N/A')
        protocol = alert.get('protocol', 'Unknown')
        detection_method = alert.get('detection_method', 'unknown')
        
        # Add prefix indicator and confidence info
        prefix = "[R]" if detection_method == 'rule-based' else "[M]"
        confidence_info = ""
        if detection_method == 'ml-based':
            confidence = alert.get('confidence', 0)
            confidence_level = alert.get('confidence_level', 'N/A')
            threshold_used = alert.get('threshold_used', 0)
            confidence_info = f" | Conf: {confidence:.3f} ({confidence_level}) [T: {threshold_used}]"
        
        # Format and display alert
        alert_message = f"{prefix} [{timestamp}] {attack_type}{confidence_info}\n  {src} -> {dst} [{protocol}]\n"
        self.alert_log.insert(tk.END, alert_message)
        self.alert_log.see(tk.END)
        # Update alert counts
        self.alerts_var.set(str(len(self.detector.alerts)))
        
        rule_based_count = sum(1 for a in self.detector.alerts if a.get('detection_method') == 'rule-based')
        ml_based_count = sum(1 for a in self.detector.alerts if a.get('detection_method') == 'ml-based')
        self.rule_alerts_var.set(str(rule_based_count))
        self.ml_alerts_var.set(str(ml_based_count))
        
        # Update graph
        self.update_graph()
        
        # Save to CSV
        os.makedirs("nids_alerts", exist_ok=True)
        csv_file = os.path.join("nids_alerts", "hybrid_ids_xgboost_alerts.csv")
        
        try:
            csv_exists = os.path.exists(csv_file)
            
            with open(csv_file, "a", newline='') as csvfile:
                fieldnames = [
                    "timestamp", 
                    "attack_type", 
                    "detection_method",
                    "confidence",
                    "confidence_level",
                    "threshold_used",
                    "severity",
                    "source_ip", 
                    "destination_ip", 
                    "protocol", 
                    "details"
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                
                if not csv_exists:
                    writer.writeheader()
                
                alert_data = {
                    "timestamp": timestamp,
                    "attack_type": attack_type,
                    "detection_method": detection_method,
                    "confidence": alert.get('confidence', 'N/A'),
                    "confidence_level": alert.get('confidence_level', 'N/A'),
                    "threshold_used": alert.get('threshold_used', 'N/A'),
                    "severity": alert.get('severity', 'medium'),
                    "source_ip": src,
                    "destination_ip": dst,
                    "protocol": protocol,
                    "details": alert.get('details', 'No additional details')
                }
                
                writer.writerow(alert_data)
        
        except Exception as e:
            print(f"Error logging alert to CSV: {e}")
    
    def add_log_message(self, message):
        """Add a regular log message to the alert log"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_text = f"[{timestamp}] INFO: {message}\n"
        self.alert_log.insert(tk.END, log_text)
        self.alert_log.see(tk.END)
    
    def clear_alerts(self):
        """Clear the alert log and graph"""
        self.alert_log.delete(1.0, tk.END)
        self.detector.alerts = []
        self.alerts_var.set("0")
        self.rule_alerts_var.set("0")
        self.ml_alerts_var.set("0")
        self.update_graph()
    
    def update_statistics(self):
        """Update statistics periodically"""
        if self.running:
            # Count total packets processed
            total_packets = self.detector.get_total_packets()
            self.packets_var.set(str(total_packets))
        
        # Schedule next update
        self.root.after(1000, self.update_statistics)
    
    def run(self):
        """Run the GUI main loop"""
        self.root.mainloop()

def main():
    # Path to the pre-trained XGBoost model
    model_path = MODEL_PATH
    
    # Create detector and GUI
    detector = NetworkAnomalyDetector(model_path, rules_file=RULES_PATH)
    gui = NetworkAnomalyGUI(detector)
    
    # Run the application
    gui.run()

if __name__ == "__main__":
    main()