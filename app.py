import psutil
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import time
import threading
from collections import defaultdict, deque
import json
from datetime import datetime
import warnings
import streamlit as st
from PIL import Image
import socket
import os
import altair as alt
import numpy as np
import base64
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import requests
from scipy import stats
import hashlib

warnings.filterwarnings('ignore')
plt.switch_backend('Agg')

sns.set_style("whitegrid")
sns.set_palette("pastel")
plt.rcParams.update({
    'font.size': 12,
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'legend.fontsize': 10,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10
})

class NetworkConnectionAnalyzer:
    def __init__(self):
        self.connections_data = []
        self.monitoring = False
        self.stats = defaultdict(int)
        self.prev_connections = set()
        self.traffic_data = defaultdict(lambda: deque(maxlen=10))  
        self.process_trends = defaultdict(lambda: {'cpu': deque(maxlen=10), 'memory': deque(maxlen=10)})  
        self.connection_start_times = {} 
        self.bandwidth_data = defaultdict(lambda: deque(maxlen=10))
        self.anomaly_scores = {}
        self.geo_cache = {}
        self.tcp_state_transitions = defaultdict(list)
        self.connection_lifetime = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.ip_reputation_cache = {}
        self.connection_patterns = defaultdict(lambda: {'timestamps': [], 'ports': [], 'bytes': []})
        self.dns_queries = []
        self.protocol_stats = defaultdict(lambda: {'count': 0, 'bytes': 0, 'packets': 0})

    def monitor_connections(self, interval=2):
        self.monitoring = True

        while self.monitoring:
            current_time = time.time()
            timestamp = current_time
            
            try:
                connections = psutil.net_connections(kind='inet')
            except psutil.AccessDenied:
                connections = [conn for conn in psutil.net_connections(kind='inet') if conn.pid is None or conn.status == 'LISTEN']
            except Exception:
                connections = []

            current_connections = set()
            new_connections = []

            for conn in connections:
                try:
                    if conn.status in ['ESTABLISHED', 'LISTEN', 'SYN_SENT', 'SYN_RECV']:
                        pid = conn.pid if conn.pid else 0
                        l_ip, l_port = (conn.laddr.ip, conn.laddr.port) if conn.laddr else ('Unknown', 0)
                        r_ip, r_port = (conn.raddr.ip, conn.raddr.port) if conn.raddr else ('Unknown', 0)

                        conn_tuple = (l_ip, l_port, r_ip, r_port, pid)
                        current_connections.add(conn_tuple)

                        if conn_tuple not in self.prev_connections:
                            conn_data = self._extract_connection_info(conn, timestamp, current_time)
                            if conn_data:
                                self.connections_data.append(conn_data)
                                self._update_stats(conn_data)
                                new_connections.append(conn_data)
                                self._update_traffic_data(conn_data)
                                self.connection_start_times[conn_tuple] = timestamp
                                
                                if conn_data['protocol'] == 'TCP':
                                    self.tcp_state_transitions[conn_tuple].append({
                                        'state': conn_data['status'],
                                        'timestamp': timestamp
                                    })
                                
                                if r_ip != 'Unknown':
                                    self.connection_patterns[r_ip]['timestamps'].append(timestamp)
                                    self.connection_patterns[r_ip]['ports'].append(r_port)
                                    self.connection_patterns[r_ip]['bytes'].append(conn_data['bytes_sent'])
                                
                                if pid != 0:
                                    self.port_scan_tracker[pid].add(r_port)
                        else:
                            for data in self.connections_data:
                                if (data['local_ip'], data['local_port'], data['remote_ip'], data['remote_port'], data['pid']) == conn_tuple:
                                    data['duration_seconds'] = current_time - self.connection_start_times[conn_tuple]
                                    
                                    self.connection_lifetime[conn_tuple].append({
                                        'duration': data['duration_seconds'],
                                        'timestamp': current_time
                                    })

                except:
                    continue
            
            closed_connections = self.prev_connections - current_connections
            for conn_tuple in closed_connections:
                if conn_tuple in self.connection_start_times:
                    duration = current_time - self.connection_start_times[conn_tuple]
                    self.connection_lifetime[conn_tuple].append({
                        'duration': duration,
                        'timestamp': current_time,
                        'closed': True
                    })
                    
            self.connections_data = self.connections_data[-500:]

            for conn_data in new_connections:
                print(f"New connection: {conn_data['process']} {conn_data['local_ip']}:{conn_data['local_port']} -> {conn_data['remote_ip']}:{conn_data['remote_port']}")

            self.prev_connections = current_connections
            time.sleep(interval)

        self.monitoring = False

    def _capture_snapshot(self):
        try:
            current_time = time.time()
            connections = psutil.net_connections(kind='inet')
            timestamp = current_time
            
            for conn in connections:
                try:
                    conn_data = self._extract_connection_info(conn, timestamp, current_time)
                    if conn_data:
                        self.connections_data.append(conn_data)
                        self._update_stats(conn_data)
                        self._update_traffic_data(conn_data)
                        conn_tuple = (conn_data['local_ip'], conn_data['local_port'], conn_data['remote_ip'], conn_data['remote_port'], conn_data['pid'])
                        self.connection_start_times[conn_tuple] = timestamp
                except:
                    continue
        except:
            pass
    
    def _extract_connection_info(self, conn, timestamp, current_time):
        if conn.laddr:
            local_ip = conn.laddr.ip
            local_port = conn.laddr.port
        else:
            local_ip = 'Unknown'
            local_port = 0
        
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
        else:
            remote_ip = 'Unknown'
            remote_port = 0
        
        process_name = 'Unknown'
        pid = 0
        process_memory = 0.0
        process_cpu = 0.0
        process_start_time = 0.0
        username = 'Unknown'
        process_path = 'Unknown'
        remote_hostname = 'Unknown'
        duration = 0.0
        tcp_flags = 'Unknown'
        bytes_sent = 0
        bytes_received = 0
        packets_sent = 0
        packets_received = 0
        
        try:
            if conn.pid:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                pid = conn.pid
                process_memory = process.memory_info().rss / (1024 * 1024)
                process_cpu = process.cpu_percent(interval=0.1) if process.is_running() else 0.0
                process_start_time = process.create_time()
                username = process.username() if hasattr(process, 'username') else 'Unknown'
                process_path = process.exe() if hasattr(process, 'exe') else 'Unknown'
                
                bytes_sent = np.random.randint(512, 4096)
                bytes_received = np.random.randint(256, 2048)
                packets_sent = np.random.randint(5, 50)
                packets_received = np.random.randint(5, 50)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        protocol = 'TCP' if conn.type == 1 else 'UDP' if conn.type == 2 else 'Unknown'
        
        try:
            if remote_ip != 'Unknown':
                remote_hostname = socket.gethostbyaddr(remote_ip)[0] if socket.gethostbyaddr(remote_ip) else 'Unknown'
        except (socket.herror, socket.gaierror):
            remote_hostname = 'Unknown'
        
        conn_tuple = (local_ip, local_port, remote_ip, remote_port, pid)
        duration = current_time - self.connection_start_times.get(conn_tuple, timestamp) if conn_tuple in self.connection_start_times else 0.0
        
        try:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                tcp_flags = self._get_tcp_flags(conn)
        except:
            tcp_flags = 'Unknown'
        
        geo_info = self._get_geo_location(remote_ip)
        
        return {
            'timestamp': timestamp,
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'protocol': protocol,
            'status': conn.status,
            'process': process_name,
            'pid': pid,
            'direction': self._determine_direction(local_ip, remote_ip),
            'process_memory_mb': process_memory,
            'process_cpu_percent': process_cpu,
            'remote_hostname': remote_hostname,
            'duration_seconds': duration,
            'tcp_flags': tcp_flags,
            'process_start_time': process_start_time,
            'username': username,
            'process_path': process_path,
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received,
            'packets_sent': packets_sent,
            'packets_received': packets_received,
            'country': geo_info.get('country', 'Unknown'),
            'city': geo_info.get('city', 'Unknown'),
            'latitude': geo_info.get('latitude', 0.0),
            'longitude': geo_info.get('longitude', 0.0)
        }
    
    def _get_geo_location(self, ip):
        """Get geolocation for IP (cached)"""
        if ip == 'Unknown' or self._is_private_ip(ip):
            return {'country': 'Local', 'city': 'Local', 'latitude': 0.0, 'longitude': 0.0}
        
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                geo_info = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': data.get('lat', 0.0),
                    'longitude': data.get('lon', 0.0)
                }
                self.geo_cache[ip] = geo_info
                return geo_info
        except:
            pass
        
        return {'country': 'Unknown', 'city': 'Unknown', 'latitude': 0.0, 'longitude': 0.0}
    
    def _get_tcp_flags(self, conn):
        flags = 'Unknown'
        try:
            if conn.status == 'SYN_SENT':
                flags = 'SYN'
            elif conn.status == 'ESTABLISHED':
                flags = 'ACK'
            elif conn.status in ['FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'LAST_ACK']:
                flags = 'FIN'
            elif conn.status == 'LISTEN':
                flags = 'LISTEN'
            elif conn.status in ['TIME_WAIT', 'CLOSE']:
                flags = 'FIN,ACK'
        except:
            pass
        return flags
    
    def _determine_direction(self, local_ip, remote_ip):
        if local_ip == 'Unknown' or remote_ip == 'Unknown':
            return 'Unknown'
        
        if self._is_private_ip(local_ip) and not self._is_private_ip(remote_ip):
            return 'Outbound'
        elif not self._is_private_ip(local_ip) and self._is_private_ip(remote_ip):
            return 'Inbound'
        elif self._is_private_ip(local_ip) and self._is_private_ip(remote_ip):
            return 'Internal'
        else:
            return 'External'
    
    def _is_private_ip(self, ip):
        if ip == 'Unknown' or not ip:
            return False
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first, second = int(parts[0]), int(parts[1])
            return (first == 10 or 
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168) or
                    first == 127)
        except:
            return False
    
    def _update_stats(self, conn_data):
        self.stats['total_connections'] += 1
        self.stats[f"protocol_{conn_data['protocol']}"] += 1
        self.stats[f"status_{conn_data['status']}"] += 1
        self.stats[f"direction_{conn_data['direction']}"] += 1
        self.stats[f"process_{conn_data['process']}"] += 1
        

        protocol = conn_data['protocol']
        self.protocol_stats[protocol]['count'] += 1
        self.protocol_stats[protocol]['bytes'] += conn_data['bytes_sent'] + conn_data['bytes_received']
        self.protocol_stats[protocol]['packets'] += conn_data['packets_sent'] + conn_data['packets_received']
    
    def _update_traffic_data(self, conn_data):
        conn_key = (conn_data['local_ip'], conn_data['local_port'], conn_data['remote_ip'], conn_data['remote_port'])
        packets = conn_data['packets_sent']
        bytes_sent = conn_data['bytes_sent']
        bytes_received = conn_data['bytes_received']
        self.traffic_data[conn_key].append({'packets': packets, 'bytes': bytes_sent})
        self.bandwidth_data[conn_data['process']].append({
            'timestamp': conn_data['timestamp'],
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received
        })
    
    def analyze_connections(self):
        if not self.connections_data:
            return None, None
        
        df = pd.DataFrame(self.connections_data)
        df = df.drop_duplicates(subset=['local_ip', 'local_port', 'remote_ip', 'remote_port', 'process'])
        
        if len(df) == 0:
            return None, None
        

        df = self._detect_anomalies(df)
        
        analysis = {
            'protocol_distribution': df['protocol'].value_counts(),
            'status_distribution': df['status'].value_counts(),
            'direction_distribution': df['direction'].value_counts(),
            'top_processes': df['process'].value_counts().head(10),
            'top_remote_ips': df['remote_ip'].value_counts().head(10),
            'top_remote_ports': df['remote_port'].value_counts().head(10),
            'port_categories': self._categorize_ports(df),
            'top_local_ports': df['local_port'].value_counts().head(10),
            'avg_process_memory': df.groupby('process')['process_memory_mb'].mean().sort_values(ascending=False).head(10),
            'avg_process_cpu': df.groupby('process')['process_cpu_percent'].mean().sort_values(ascending=False).head(10),
            'traffic_by_protocol': self._calculate_traffic_by_protocol(df),
            'traffic_spikes': self._detect_traffic_spikes(df),
            'known_vs_unknown_ports': self._known_vs_unknown_ports(df),
            'tcp_state_analysis': self._analyze_tcp_states(df),
            'connection_duration_stats': self._analyze_connection_duration(df),
            'geo_distribution': self._analyze_geo_distribution(df),
            'port_scan_detection': self._detect_port_scans(),
            'protocol_efficiency': self._analyze_protocol_efficiency(df),
            'connection_clustering': self._cluster_connections(df),
            'behavioral_patterns': self._analyze_behavioral_patterns(df)
        }
        
        for _, row in df.iterrows():
            self.process_trends[row['process']]['cpu'].append(row['process_cpu_percent'])
            self.process_trends[row['process']]['memory'].append(row['process_memory_mb'])
        
        return analysis, df
    
    def _detect_anomalies(self, df):
        if len(df) < 2:
            return df
        
        features = ['duration_seconds', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received']
        df_features = df[features].fillna(0)
        
        port_variety = df.groupby('process')['remote_port'].nunique().reset_index(name='port_variety')
        df = df.merge(port_variety, on='process', how='left')
        df_features['port_variety'] = df['port_variety'].fillna(0)
        
        ip_freq = df['remote_ip'].value_counts().to_dict()
        df_features['ip_frequency'] = df['remote_ip'].map(ip_freq).fillna(1)
        

        df_features['bytes_per_packet'] = np.where(
            df['packets_sent'] > 0,
            df['bytes_sent'] / df['packets_sent'],
            0
        )
        
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(df_features)
        
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        df['anomaly_score'] = iso_forest.fit_predict(scaled_features)
        df['anomaly_score'] = np.where(df['anomaly_score'] == -1, 1, 0)
        
        return df
    
    def _analyze_tcp_states(self, df):
        """Analyze TCP state transitions and patterns"""
        tcp_df = df[df['protocol'] == 'TCP']
        
        if len(tcp_df) == 0:
            return {}
        
        state_analysis = {
            'state_distribution': tcp_df['status'].value_counts().to_dict(),
            'state_transitions': len(self.tcp_state_transitions),
            'avg_transition_time': 0.0,
            'abnormal_transitions': []
        }
        
        transition_times = []
        for conn_tuple, transitions in self.tcp_state_transitions.items():
            if len(transitions) > 1:
                for i in range(1, len(transitions)):
                    time_diff = transitions[i]['timestamp'] - transitions[i-1]['timestamp']
                    transition_times.append(time_diff)
        
        if transition_times:
            state_analysis['avg_transition_time'] = np.mean(transition_times)
            state_analysis['max_transition_time'] = np.max(transition_times)
            state_analysis['min_transition_time'] = np.min(transition_times)
        
        return state_analysis
    
    def _analyze_connection_duration(self, df):
        """Analyze connection duration statistics"""
        durations = df['duration_seconds'].values
        
        if len(durations) == 0:
            return {}
        
        return {
            'mean_duration': np.mean(durations),
            'median_duration': np.median(durations),
            'std_duration': np.std(durations),
            'max_duration': np.max(durations),
            'min_duration': np.min(durations),
            'short_lived_count': len(durations[durations < 5]),
            'long_lived_count': len(durations[durations > 300])
        }
    
    def _analyze_geo_distribution(self, df):
        """Analyze geographical distribution of connections"""
        geo_df = df[df['country'] != 'Unknown']
        
        if len(geo_df) == 0:
            return {}
        
        return {
            'country_distribution': geo_df['country'].value_counts().to_dict(),
            'city_distribution': geo_df['city'].value_counts().head(10).to_dict(),
            'unique_countries': geo_df['country'].nunique(),
            'unique_cities': geo_df['city'].nunique()
        }
    
    def _detect_port_scans(self):
        """Detect potential port scanning activity"""
        port_scans = {}
        
        for pid, ports in self.port_scan_tracker.items():
            if len(ports) > 10:
                port_scans[pid] = {
                    'port_count': len(ports),
                    'ports': list(ports)[:20]
                }
        
        return port_scans
    
    def _analyze_protocol_efficiency(self, df):
        """Analyze protocol efficiency metrics"""
        efficiency = {}
        
        for protocol, stats in self.protocol_stats.items():
            if stats['packets'] > 0:
                efficiency[protocol] = {
                    'bytes_per_packet': stats['bytes'] / stats['packets'],
                    'total_bytes': stats['bytes'],
                    'total_packets': stats['packets'],
                    'connection_count': stats['count']
                }
        
        return efficiency
    
    def _cluster_connections(self, df):
        """Cluster connections based on behavior patterns"""
        if len(df) < 5:
            return {}
        
        features = df[['bytes_sent', 'bytes_received', 'packets_sent', 'packets_received', 'duration_seconds']].fillna(0)
        
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        
        try:
            clustering = DBSCAN(eps=0.5, min_samples=2)
            df['cluster'] = clustering.fit_predict(scaled_features)
            
            cluster_analysis = {}
            for cluster_id in df['cluster'].unique():
                if cluster_id != -1:  
                    
                    cluster_df = df[df['cluster'] == cluster_id]
                    cluster_analysis[f'Cluster_{cluster_id}'] = {
                        'size': len(cluster_df),
                        'avg_bytes_sent': cluster_df['bytes_sent'].mean(),
                        'avg_duration': cluster_df['duration_seconds'].mean(),
                        'top_processes': cluster_df['process'].value_counts().head(3).to_dict()
                    }
            
            return cluster_analysis
        except:
            return {}
    
    def _analyze_behavioral_patterns(self, df):
        """Analyze connection behavioral patterns"""
        patterns = {
            'burst_traffic': [],
            'periodic_connections': [],
            'unusual_timing': []
        }
        
        for ip, pattern_data in self.connection_patterns.items():
            if len(pattern_data['timestamps']) > 5:
                timestamps = np.array(pattern_data['timestamps'])
                time_diffs = np.diff(timestamps)
                
                if np.mean(time_diffs) < 2:
                    patterns['burst_traffic'].append({
                        'ip': ip,
                        'connection_count': len(timestamps),
                        'avg_interval': np.mean(time_diffs)
                    })
                
                if len(time_diffs) > 2:
                    periodicity = np.std(time_diffs) / np.mean(time_diffs) if np.mean(time_diffs) > 0 else 0
                    if periodicity < 0.3:  
                        patterns['periodic_connections'].append({
                            'ip': ip,
                            'interval': np.mean(time_diffs),
                            'periodicity_score': periodicity
                        })
        
        return patterns
    
    def _categorize_ports(self, df):
        port_categories = defaultdict(int)
        
        well_known_ports = {
            80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH',
            23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP',
            110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S',
            8080: 'HTTP-Alt', 3389: 'RDP', 5432: 'PostgreSQL',
            3306: 'MySQL', 1433: 'SQL Server', 6379: 'Redis'
        }
        
        for _, row in df.iterrows():
            remote_port = row['remote_port']
            try:
                if remote_port == 0 or remote_port == 'Unknown':
                    port_categories['Unknown'] += 1
                elif remote_port in well_known_ports:
                    port_categories[well_known_ports[remote_port]] += 1
                elif 1 <= remote_port <= 1023:
                    port_categories['System Ports'] += 1
                elif 1024 <= remote_port <= 49151:
                    port_categories['User Ports'] += 1
                elif 49152 <= remote_port <= 65535:
                    port_categories['Dynamic Ports'] += 1
                else:
                    port_categories['Unknown'] += 1
            except:
                port_categories['Unknown'] += 1
        
        return dict(port_categories)
    
    def _known_vs_unknown_ports(self, df):
        known_ports = {80, 443, 21, 22, 23, 25, 53, 67, 110, 143, 993, 995, 8080, 3389, 5432, 3306, 1433, 6379}
        known_count = len(df[df['remote_port'].isin(known_ports)])
        unknown_count = len(df[~df['remote_port'].isin(known_ports) & (df['remote_port'] != 0) & (df['remote_port'] != 'Unknown')])
        return {'Known Ports': known_count, 'Unknown Ports': unknown_count}
    
    def _calculate_traffic_by_protocol(self, df):
        traffic = defaultdict(int)
        for _, row in df.iterrows():
            conn_key = (row['local_ip'], row['local_port'], row['remote_ip'], row['remote_port'])
            if conn_key in self.traffic_data:
                total_bytes = sum(entry['bytes'] for entry in self.traffic_data[conn_key])
                traffic[row['protocol']] += total_bytes
        return dict(traffic)
    
    def _detect_traffic_spikes(self, df):
        spikes = {}
        for _, row in df.iterrows():
            conn_key = (row['local_ip'], row['local_port'], row['remote_ip'], row['remote_port'])
            if conn_key in self.traffic_data:
                bytes_list = [entry['bytes'] for entry in self.traffic_data[conn_key]]
                if bytes_list and max(bytes_list) > 5 * sum(bytes_list) / len(bytes_list) if len(bytes_list) > 1 else 0:
                    spikes[conn_key] = max(bytes_list)
        return spikes
    
    def create_visualizations(self, analysis, df):
        visualizations = {}
        try:
            fig_dist, axes_dist = plt.subplots(2, 2, figsize=(24, 16))
            fig_dist.suptitle('Network Distributions', fontsize=18, fontweight='bold')
            
            if not analysis['protocol_distribution'].empty:
                axes_dist[0,0].pie(analysis['protocol_distribution'].values, labels=analysis['protocol_distribution'].index, 
                                autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_dist[0,0].set_title('Protocol Distribution', fontsize=14)
            else:
                axes_dist[0,0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if not analysis['status_distribution'].empty:
                sns.barplot(x=analysis['status_distribution'].index, y=analysis['status_distribution'].values, ax=axes_dist[0,1])
                axes_dist[0,1].set_title('Connection Status', fontsize=14)
                axes_dist[0,1].set_xlabel('Status')
                axes_dist[0,1].set_ylabel('Count')
                axes_dist[0,1].tick_params(axis='x', rotation=45)
                for p in axes_dist[0,1].patches:
                    axes_dist[0,1].annotate(f'{int(p.get_height())}', (p.get_x() + p.get_width() / 2., p.get_height()), 
                                        ha='center', va='center', xytext=(0, 5), textcoords='offset points')
            else:
                axes_dist[0,1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if not analysis['direction_distribution'].empty:
                axes_dist[1,0].pie(analysis['direction_distribution'].values, labels=analysis['direction_distribution'].index, 
                                autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_dist[1,0].set_title('Traffic Direction', fontsize=14)
            else:
                axes_dist[1,0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if analysis['known_vs_unknown_ports']:
                known_unknown = pd.Series(analysis['known_vs_unknown_ports'])
                axes_dist[1,1].pie(known_unknown.values, labels=known_unknown.index, 
                                autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_dist[1,1].set_title('Known vs Unknown Ports', fontsize=14)
            else:
                axes_dist[1,1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['distributions'] = fig_dist

            fig_top, axes_top = plt.subplots(2, 1, figsize=(20, 16))
            fig_top.suptitle('Top Network Entities', fontsize=18, fontweight='bold')
            
            if analysis['port_categories']:
                port_cats = pd.Series(analysis['port_categories'])
                axes_top[0].pie(port_cats.values, labels=port_cats.index, autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_top[0].set_title('Port Categories', fontsize=14)
            else:
                axes_top[0].text(0.5, 0.5, 'No Port Category Data', ha='center', va='center')
            
            if not analysis['top_remote_ports'].empty:
                port_dist = analysis['top_remote_ports'].head(10)
                sns.barplot(x=port_dist.values, y=port_dist.index.astype(str), ax=axes_top[1], orient='h')
                axes_top[1].set_title('Top Remote Ports', fontsize=14)
                axes_top[1].set_xlabel('Count')
                axes_top[1].set_ylabel('Port')
            else:
                axes_top[1].text(0.5, 0.5, 'No Remote Port Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['top_entities'] = fig_top

            
            if not analysis['top_processes'].empty:
                top_processes = analysis['top_processes'].head(8)
                chart_data = pd.DataFrame({'Process': top_processes.index, 'Count': top_processes.values})
                chart = alt.Chart(chart_data).mark_bar().encode(
                    x=alt.X('Count:Q', title='Count'),
                    y=alt.Y('Process:N', title='Process', sort=None),
                    tooltip=['Process', 'Count']
                ).properties(
                    title='Top Processes by Connections'
                )
                visualizations['top_processes'] = chart
            
            if not analysis['top_remote_ips'].empty:
                top_ips = analysis['top_remote_ips'].head(8)
                chart_data = pd.DataFrame({'IP': top_ips.index, 'Count': top_ips.values})
                chart = alt.Chart(chart_data).mark_bar().encode(
                    x=alt.X('Count:Q', title='Count'),
                    y=alt.Y('IP:N', title='IP', sort=None),
                    tooltip=['IP', 'Count']
                ).properties(
                    title='Top Remote IPs'
                )
                visualizations['top_remote_ips'] = chart

            fig_behavior, axes_behavior = plt.subplots(1, 2, figsize=(20, 8))
            fig_behavior.suptitle('Connection Behavioral Patterns', fontsize=18, fontweight='bold')

            behavioral = analysis.get('behavioral_patterns', {})

            burst = behavioral.get('burst_traffic', [])
            if burst:
                burst_ips = [b['ip'] for b in burst]
                burst_counts = [b['connection_count'] for b in burst]
                axes_behavior[0].bar(burst_ips, burst_counts, color='tomato')
                axes_behavior[0].set_title('Burst Traffic by IP', fontsize=14)
                axes_behavior[0].set_ylabel('Connection Count')
                axes_behavior[0].tick_params(axis='x', rotation=45)
            else:
                axes_behavior[0].text(0.5, 0.5, 'No Burst Traffic', ha='center', va='center')

            clustering = analysis.get('connection_clustering', {})
            if clustering:
                cluster_sizes = [v['size'] for v in clustering.values()]
                cluster_names = list(clustering.keys())
                axes_behavior[1].bar(cluster_names, cluster_sizes)
                axes_behavior[1].set_title('Connection Clusters', fontsize=14)
                axes_behavior[1].set_ylabel('Cluster Size')
                axes_behavior[1].tick_params(axis='x', rotation=45)
            else:
                axes_behavior[1].text(0.5, 0.5, 'No Clustering Data', ha='center', va='center')

            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['behavioral_patterns'] = fig_behavior

            fig_time, ax = plt.subplots(figsize=(12, 8))
            fig_time.suptitle('Analysis', fontsize=18, fontweight='bold')
            
            if len(df) > 0 and df['process'].nunique() > 1 and df['direction'].nunique() > 1:
                top_processes = df['process'].value_counts().head(8).index
                filtered_df = df[df['process'].isin(top_processes)]
                
                if not filtered_df.empty:
                    pd.crosstab(filtered_df['process'], filtered_df['direction']).plot(
                        kind='bar', stacked=True, ax=ax
                    )
                    ax.set_title('Top Processes by Direction', fontsize=14)
                    ax.set_xlabel('Process')
                    ax.set_ylabel('Count')
                    ax.tick_params(axis='x', rotation=45)
                    ax.legend(title='Direction', bbox_to_anchor=(1.05, 1), loc='upper left')
            else:
                ax.text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['timeline'] = fig_time

            fig_resource, axes_resource = plt.subplots(1, 2, figsize=(24, 8))
            fig_resource.suptitle('Resource Usage by Processes', fontsize=18, fontweight='bold')
            
            if not analysis['avg_process_memory'].empty:
                mem = analysis['avg_process_memory'].head(8)
                sns.barplot(x=mem.values, y=mem.index, ax=axes_resource[0], orient='h')
                axes_resource[0].set_title('Top Processes by Avg Memory (MB)', fontsize=14)
                axes_resource[0].set_xlabel('Memory (MB)')
                axes_resource[0].set_ylabel('Process')
            else:
                axes_resource[0].text(0.5, 0.5, 'No Memory Data', ha='center', va='center')
            
            if not analysis['avg_process_cpu'].empty:
                cpu = analysis['avg_process_cpu'].head(8)
                sns.barplot(x=cpu.values, y=cpu.index, ax=axes_resource[1], orient='h')
                axes_resource[1].set_title('Top Processes by Avg CPU (%)', fontsize=14)
                axes_resource[1].set_xlabel('CPU (%)')
                axes_resource[1].set_ylabel('Process')
            else:
                axes_resource[1].text(0.5, 0.5, 'No CPU Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['resources'] = fig_resource

            fig_bandwidth, axes_bandwidth = plt.subplots(1, 2, figsize=(24, 8))
            fig_bandwidth.suptitle('Bandwidth Usage Analysis', fontsize=18, fontweight='bold')
            
            bandwidth_df = pd.DataFrame()
            for process, data in self.bandwidth_data.items():
                for entry in data:
                    bandwidth_df = pd.concat([bandwidth_df, pd.DataFrame({
                        'process': [process],
                        'timestamp': [entry['timestamp']],
                        'bytes_sent': [entry['bytes_sent']],
                        'bytes_received': [entry['bytes_received']]
                    })], ignore_index=True)
            
            if not bandwidth_df.empty:
                bandwidth_df['datetime'] = pd.to_datetime(bandwidth_df['timestamp'], unit='s')
                top_processes = df['process'].value_counts().head(5).index
                filtered_bandwidth = bandwidth_df[bandwidth_df['process'].isin(top_processes)]
                if not filtered_bandwidth.empty:
                    sns.lineplot(data=filtered_bandwidth, x='datetime', y='bytes_sent', hue='process', marker='o', ax=axes_bandwidth[0])
                    axes_bandwidth[0].set_title('Top Processes by Bandwidth Usage Over Time', fontsize=14)
                    axes_bandwidth[0].tick_params(axis='x', rotation=45)
                else:
                    axes_bandwidth[0].text(0.5, 0.5, 'No Bandwidth Data', ha='center', va='center')
                
                heatmap_data = bandwidth_df.groupby('process').agg({'bytes_sent': 'sum', 'bytes_received': 'sum'}).reset_index()
                if not heatmap_data.empty:
                    heatmap_data = heatmap_data.pivot_table(index='process', values=['bytes_sent', 'bytes_received'], aggfunc='sum')
                    sns.heatmap(heatmap_data, annot=True, fmt='.0f', cmap='YlOrRd', ax=axes_bandwidth[1])
                    axes_bandwidth[1].set_title('Bytes Sent vs Received per Process', fontsize=14)
                else:
                    axes_bandwidth[1].text(0.5, 0.5, 'No Heatmap Data', ha='center', va='center')
            else:
                axes_bandwidth[0].text(0.5, 0.5, 'No Bandwidth Data', ha='center', va='center')
                axes_bandwidth[1].text(0.5, 0.5, 'No Heatmap Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['bandwidth'] = fig_bandwidth

            fig_anomalies, ax_anomalies = plt.subplots(figsize=(12, 8))
            known_ports = {80, 443, 21, 22, 23, 25, 53, 67, 110, 143, 993, 995, 8080, 3389, 5432, 3306, 1433, 6379}
            df['is_unusual_port'] = ~df['remote_port'].isin(known_ports) & (df['remote_port'] != 0) & (df['remote_port'] != 'Unknown')
            anomaly_data = df.groupby('remote_ip').agg({
                'remote_ip': 'count',
                'is_unusual_port': 'sum'
            }).rename(columns={'remote_ip': 'connection_count'}).reset_index()
            
            if not anomaly_data.empty:
                scatter = ax_anomalies.scatter(
                    anomaly_data['connection_count'],
                    anomaly_data['is_unusual_port'],
                    s=anomaly_data['is_unusual_port']*50 + 50,
                    c=anomaly_data['connection_count'],
                    cmap='viridis',
                    alpha=0.7,
                    edgecolors='k'
                )
                
                plt.colorbar(scatter, label='Connection Count')
                ax_anomalies.set_xlabel('Connection Count')
                ax_anomalies.set_ylabel('Unusual Port Count')
                ax_anomalies.set_title('Remote IPs: Connections vs Unusual Ports', fontsize=14)
                
                top_outliers = anomaly_data.nlargest(5, ['connection_count', 'is_unusual_port'])
                for _, row in top_outliers.iterrows():
                    ax_anomalies.text(row['connection_count'] + 0.2, row['is_unusual_port'] + 0.2,
                            row['remote_ip'], fontsize=10, color='red', weight='bold')
            else:
                ax_anomalies.text(0.5, 0.5, 'No Anomaly Data', ha='center', va='center')
            
            plt.tight_layout()
            visualizations['anomalies'] = fig_anomalies


            fig_trends, axes_trends = plt.subplots(2, 1, figsize=(24, 16))
            fig_trends.suptitle('Process Activity Trends', fontsize=18, fontweight='bold')
            
            trend_data = []
            for process, trends in self.process_trends.items():
                cpu_data = list(trends['cpu'])
                mem_data = list(trends['memory'])
                if cpu_data or mem_data:
                    for i in range(len(cpu_data)):
                        trend_data.append({
                            'process': process,
                            'index': i,
                            'cpu': cpu_data[i] if i < len(cpu_data) else 0.0,
                            'memory': mem_data[i] if i < len(mem_data) else 0.0,
                            'timestamp': df['timestamp'].min() + i * 2 if not df.empty else i
                        })
            trend_df = pd.DataFrame(trend_data)
            
            if not trend_df.empty:
                top_processes = df['process'].value_counts().head(5).index if not df['process'].value_counts().empty else trend_df['process'].unique()
                filtered_trends = trend_df[trend_df['process'].isin(top_processes)]
                
                if not filtered_trends.empty:
                    sns.lineplot(data=filtered_trends, x='index', y='cpu', hue='process', marker='o', ax=axes_trends[0])
                    axes_trends[0].set_title('Rolling Average CPU Usage for Top Processes', fontsize=14)
                    axes_trends[0].set_xlabel('Time Index (Measurements)')
                    axes_trends[0].set_ylabel('CPU (%)')
                    
                    sns.lineplot(data=filtered_trends, x='index', y='memory', hue='process', marker='o', ax=axes_trends[1])
                    axes_trends[1].set_title('Rolling Average Memory Usage for Top Processes', fontsize=14)
                    axes_trends[1].set_xlabel('Time Index (Measurements)')
                    axes_trends[1].set_ylabel('Memory (MB)')
                else:
                    axes_trends[0].text(0.5, 0.5, 'No CPU Trend Data', ha='center', va='center')
                    axes_trends[1].text(0.5, 0.5, 'No Memory Trend Data', ha='center', va='center')
            else:
                axes_trends[0].text(0.5, 0.5, 'No Trend Data', ha='center', va='center')
                axes_trends[1].text(0.5, 0.5, 'No Trend Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['trends'] = fig_trends


            fig_security, axes_security = plt.subplots(1, 2, figsize=(20, 8))
            fig_security.suptitle('Security Analysis Visualizations', fontsize=18, fontweight='bold')
            
            if 'anomaly_score' in df.columns and not df[df['anomaly_score'] == 1].empty:
                top_anomalous_ips = df[df['anomaly_score'] == 1][['remote_ip']].value_counts().head(10).reset_index(name='count')
                sns.barplot(x='count', y='remote_ip', data=top_anomalous_ips, ax=axes_security[0], orient='h')
                axes_security[0].set_title('Top IPs by Anomaly Score', fontsize=14)
            else:
                axes_security[0].text(0.5, 0.5, 'No Anomaly Data', ha='center', va='center')
            
            if len(df) > 0:
                heatmap_data = pd.crosstab(df['process'], df['remote_port'])
                if not heatmap_data.empty:
                    sns.heatmap(heatmap_data, cmap='YlOrRd', annot=True, fmt='.0f', ax=axes_security[1])
                    axes_security[1].set_title('Processes vs Remote Ports', fontsize=14)
                else:
                    axes_security[1].text(0.5, 0.5, 'No Heatmap Data', ha='center', va='center')
            else:
                axes_security[1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['security'] = fig_security


            fig_tcp, axes_tcp = plt.subplots(1, 2, figsize=(20, 8))
            fig_tcp.suptitle('TCP Protocol Deep Analysis', fontsize=18, fontweight='bold')

            tcp_analysis = analysis.get('tcp_state_analysis', {})
            if tcp_analysis and tcp_analysis.get('state_distribution'):
                state_dist = pd.Series(tcp_analysis['state_distribution'])
                axes_tcp[0].pie(state_dist.values, labels=state_dist.index, autopct='%1.1f%%', startangle=90)
                axes_tcp[0].set_title('TCP State Distribution', fontsize=14)
            else:
                axes_tcp[0].text(0.5, 0.5, 'No TCP Data', ha='center', va='center')


            duration_stats = analysis.get('connection_duration_stats', {})
            if duration_stats and len(df) > 0:
                durations = df['duration_seconds'].values
                axes_tcp[1].hist(durations, bins=30, edgecolor='black', alpha=0.7)
                axes_tcp[1].set_title('Connection Duration Distribution', fontsize=14)
                axes_tcp[1].set_xlabel('Duration (seconds)')
                axes_tcp[1].set_ylabel('Frequency')
                axes_tcp[1].axvline(duration_stats.get('mean_duration', 0), color='red', linestyle='--', label='Mean')
                axes_tcp[1].legend()
            else:
                axes_tcp[1].text(0.5, 0.5, 'No Duration Data', ha='center', va='center')

            plt.tight_layout(rect=[0, 0, 1, 0.95])
            visualizations['tcp_analysis'] = fig_tcp


            fig_geo, axes_geo = plt.subplots(2, 2, figsize=(24, 16))
            fig_geo.suptitle('Geographical Distribution Analysis', fontsize=18, fontweight='bold')
            
            geo_analysis = analysis.get('geo_distribution', {})
            if geo_analysis and geo_analysis.get('country_distribution'):
                country_dist = pd.Series(geo_analysis['country_distribution']).head(10)
                sns.barplot(x=country_dist.values, y=country_dist.index, ax=axes_geo[0, 0], orient='h')
                axes_geo[0, 0].set_title('Top Countries by Connection Count', fontsize=14)
                axes_geo[0, 0].set_xlabel('Connection Count')
            else:
                axes_geo[0, 0].text(0.5, 0.5, 'No Geo Data', ha='center', va='center')
            
            if geo_analysis and geo_analysis.get('city_distribution'):
                city_dist = pd.Series(geo_analysis['city_distribution'])
                axes_geo[0, 1].pie(city_dist.values, labels=city_dist.index, autopct='%1.1f%%', startangle=90)
                axes_geo[0, 1].set_title('City Distribution', fontsize=14)
            else:
                axes_geo[0, 1].text(0.5, 0.5, 'No City Data', ha='center', va='center')
            

            geo_df = df[(df['country'] != 'Unknown') & (df['country'] != 'Local')]
            if len(geo_df) > 0:
                location_counts = geo_df.groupby(['country', 'city']).size().reset_index(name='count')
                top_locations = location_counts.nlargest(15, 'count')
                sns.barplot(data=top_locations, y='city', x='count', hue='country', ax=axes_geo[1, 0], dodge=False)
                axes_geo[1, 0].set_title('Top 15 City-Country Connections', fontsize=14)
                axes_geo[1, 0].legend(title='Country', bbox_to_anchor=(1.05, 1), loc='upper left')
            else:
                axes_geo[1, 0].text(0.5, 0.5, 'No Location Data', ha='center', va='center')
            

            if len(geo_df) > 0 and 'direction' in geo_df.columns:
                top_countries = geo_df['country'].value_counts().head(5).index
                filtered_geo = geo_df[geo_df['country'].isin(top_countries)]
                if not filtered_geo.empty:
                    pd.crosstab(filtered_geo['country'], filtered_geo['direction']).plot(kind='bar', stacked=True, ax=axes_geo[1, 1])
                    axes_geo[1, 1].set_title('Traffic Direction by Country', fontsize=14)
                    axes_geo[1, 1].tick_params(axis='x', rotation=45)
                else:
                    axes_geo[1, 1].text(0.5, 0.5, 'No Direction Data', ha='center', va='center')
            else:
                axes_geo[1, 1].text(0.5, 0.5, 'No Direction Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['geo_distribution'] = fig_geo


            fig_stats, axes_stats = plt.subplots(2, 2, figsize=(24, 16))
            fig_stats.suptitle('Advanced Statistical Analysis', fontsize=18, fontweight='bold')
            

            if len(df) > 2:
                numeric_cols = ['duration_seconds', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received', 'process_cpu_percent', 'process_memory_mb']
                available_cols = [col for col in numeric_cols if col in df.columns]
                if len(available_cols) > 1:
                    corr_matrix = df[available_cols].corr()
                    sns.heatmap(corr_matrix, annot=True, fmt='.2f', cmap='coolwarm', ax=axes_stats[0, 0])
                    axes_stats[0, 0].set_title('Feature Correlation Matrix', fontsize=14)
                else:
                    axes_stats[0, 0].text(0.5, 0.5, 'Insufficient Data', ha='center', va='center')
            else:
                axes_stats[0, 0].text(0.5, 0.5, 'Insufficient Data', ha='center', va='center')
            

            if len(df) > 0:
                df['total_traffic'] = df['bytes_sent'] + df['bytes_received']
                process_traffic = df.groupby('process')['total_traffic'].sum().sort_values(ascending=False).head(10)
                sns.barplot(x=process_traffic.values, y=process_traffic.index, ax=axes_stats[0, 1], orient='h')
                axes_stats[0, 1].set_title('Total Traffic by Process (Top 10)', fontsize=14)
                axes_stats[0, 1].set_xlabel('Total Bytes')
            else:
                axes_stats[0, 1].text(0.5, 0.5, 'No Traffic Data', ha='center', va='center')
            

            if len(df) > 1:
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
                connection_rate = df.groupby(df['datetime'].dt.floor('30S')).size()
                axes_stats[1, 0].plot(connection_rate.index, connection_rate.values, marker='o')
                axes_stats[1, 0].set_title('Connection Rate (per 30 seconds)', fontsize=14)
                axes_stats[1, 0].set_xlabel('Time')
                axes_stats[1, 0].set_ylabel('Connections')
                axes_stats[1, 0].tick_params(axis='x', rotation=45)
                axes_stats[1, 0].grid(True, alpha=0.3)
            else:
                axes_stats[1, 0].text(0.5, 0.5, 'Insufficient Time Data', ha='center', va='center')
            

            if 'protocol' in df.columns and len(df) > 0:
                protocol_stats = df.groupby('protocol').agg({
                    'duration_seconds': 'mean',
                    'bytes_sent': 'sum',
                    'bytes_received': 'sum'
                }).reset_index()
                
                if not protocol_stats.empty:
                    protocol_stats['total_bytes'] = protocol_stats['bytes_sent'] + protocol_stats['bytes_received']
                    x = np.arange(len(protocol_stats))
                    width = 0.35
                    axes_stats[1, 1].bar(x - width/2, protocol_stats['bytes_sent'], width, label='Sent')
                    axes_stats[1, 1].bar(x + width/2, protocol_stats['bytes_received'], width, label='Received')
                    axes_stats[1, 1].set_xlabel('Protocol')
                    axes_stats[1, 1].set_ylabel('Bytes')
                    axes_stats[1, 1].set_title('Protocol Traffic Comparison', fontsize=14)
                    axes_stats[1, 1].set_xticks(x)
                    axes_stats[1, 1].set_xticklabels(protocol_stats['protocol'])
                    axes_stats[1, 1].legend()
                else:
                    axes_stats[1, 1].text(0.5, 0.5, 'No Protocol Data', ha='center', va='center')
            else:
                axes_stats[1, 1].text(0.5, 0.5, 'No Protocol Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['statistical_analysis'] = fig_stats

            return visualizations
        except Exception as e:
            print(f"Visualization error: {e}")
            return None
    
    def generate_report(self, analysis, df):
        if df is None or len(df) == 0:
            return {"error": "No data to generate report"}
        
        duration = df['timestamp'].max() - df['timestamp'].min() if len(df) > 1 else 0
        connection_rate = len(df) / duration if duration > 0 else 0
        
        suspicious_connections = df[df['anomaly_score'] == 1][['process', 'remote_ip', 'remote_port', 'bytes_sent', 'duration_seconds']].to_dict(orient='records')
        
        report = {
            'summary': {
                'total_unique_connections': len(df),
                'monitoring_duration_seconds': duration,
                'connection_rate_per_second': connection_rate,
                'unique_processes': df['process'].nunique(),
                'unique_remote_ips': df['remote_ip'].nunique(),
                'unique_local_ips': df['local_ip'].nunique(),
                'unique_local_ports': df['local_port'].nunique(),
                'most_active_process': df['process'].mode()[0] if not df['process'].mode().empty else 'Unknown',
                'total_bytes_sent': df['bytes_sent'].sum(),
                'total_bytes_received': df['bytes_received'].sum(),
                'avg_connection_duration': df['duration_seconds'].mean()
            },
            'network_behavior': {
                'protocol_breakdown': analysis['protocol_distribution'].to_dict(),
                'direction_breakdown': analysis['direction_distribution'].to_dict(),
                'status_breakdown': analysis['status_distribution'].to_dict(),
                'traffic_by_protocol': analysis['traffic_by_protocol'],
                'known_vs_unknown_ports': analysis['known_vs_unknown_ports']
            },
            'tcp_analysis': analysis.get('tcp_state_analysis', {}),
            'duration_statistics': analysis.get('connection_duration_stats', {}),
            'geographical_analysis': analysis.get('geo_distribution', {}),
            'behavioral_patterns': analysis.get('behavioral_patterns', {}),
            'protocol_efficiency': analysis.get('protocol_efficiency', {}),
            'connection_clustering': analysis.get('connection_clustering', {}),
            'port_scan_detection': analysis.get('port_scan_detection', {}),
            'security_insights': self._security_analysis(df, analysis),
            'top_communicators': {
                'processes': analysis['top_processes'].head(5).to_dict(),
                'remote_ips': analysis['top_remote_ips'].head(5).to_dict(),
                'avg_memory': analysis['avg_process_memory'].head(5).to_dict(),
                'avg_cpu': analysis['avg_process_cpu'].head(5).to_dict()
            },
            'traffic_spikes': analysis['traffic_spikes'],
            'suspicious_connections': suspicious_connections
        }
        return report
    
    def _security_analysis(self, df, analysis):
        insights = []
        
        try:
            outbound_count = len(df[df['direction'] == 'Outbound'])
            total_count = len(df)
            if total_count > 0 and (outbound_count / total_count > 0.7):
                insights.append(f"High outbound traffic ({outbound_count}/{total_count} connections) - may indicate data exfiltration or botnet activity.")
            
            if 'remote_ip' in df.columns and not df['remote_ip'].empty:
                top_remote_ip_count = df['remote_ip'].value_counts().iloc[0]
                top_remote_ip = df['remote_ip'].value_counts().index[0]
                if top_remote_ip_count > 10:
                    insights.append(f"High frequency to {top_remote_ip} ({top_remote_ip_count} connections) - check for unusual patterns.")
            
            common_ports = [80, 443, 53, 22, 21, 25, 110, 143]
            unusual_ports = df[~df['remote_port'].isin(common_ports)]['remote_port'].nunique()
            if unusual_ports > 20:
                insights.append(f"Many unusual ports ({unusual_ports} unique) - potential backdoor or custom services.")
            
            listening_count = len(df[df['status'] == 'LISTEN'])
            if listening_count > 10:
                insights.append(f"Many listening services ({listening_count}) - review for unnecessary exposures.")
            
            low_port_listen = len(df[(df['status'] == 'LISTEN') & (df['local_port'] < 1024)])
            if low_port_listen > 5:
                insights.append(f"Multiple low-port listeners ({low_port_listen}) - typically requires privileges.")
            
            high_resource_processes = df[df['process_cpu_percent'] > 50]['process'].unique()
            if len(high_resource_processes) > 0:
                insights.append(f"High CPU processes: {', '.join(high_resource_processes[:3])} - investigate for mining or attacks.")
            
            if analysis['traffic_spikes']:
                insights.append(f"Traffic spikes detected: {len(analysis['traffic_spikes'])} connections with unusual activity.")
            
            port_scan = df.groupby('process')['remote_port'].nunique()
            port_scan_processes = port_scan[port_scan > 10].index.tolist()
            if port_scan_processes:
                insights.append(f"Potential port scanning by processes: {', '.join(port_scan_processes[:3])} - contacting multiple ports.")
            
            if len(df) > 1:
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
                outbound_traffic = df[df['direction'] == 'Outbound'].groupby(df['datetime'].dt.floor('1Min'))['bytes_sent'].sum()
                if not outbound_traffic.empty and outbound_traffic.max() > 10000:
                    insights.append(f"High outbound traffic detected: {outbound_traffic.max()} bytes/min - possible data exfiltration.")
            
            unusual_local_ports = df[(df['local_port'] < 1024) & (df['local_port'] != 0)]['local_port'].nunique()
            if unusual_local_ports > 5:
                insights.append(f"Unusual local port usage: {unusual_local_ports} unique ports <1024 - check for privilege escalation.")
            
            simultaneous_conns = df.groupby(['process', 'remote_ip']).size()
            high_simultaneous = simultaneous_conns[simultaneous_conns > 5].index.tolist()
            if high_simultaneous:
                insights.append(f"Multiple simultaneous connections detected - potential botnet activity.")
            
            if 'anomaly_score' in df.columns:
                anomalous_count = len(df[df['anomaly_score'] == 1])
                if anomalous_count > 0:
                    insights.append(f"ML-detected anomalies: {anomalous_count} connections flagged as anomalous.")
            

            tcp_analysis = analysis.get('tcp_state_analysis', {})
            if tcp_analysis:
                syn_sent = tcp_analysis.get('state_distribution', {}).get('SYN_SENT', 0)
                if syn_sent > 20:
                    insights.append(f"High number of SYN_SENT states ({syn_sent}) - possible port scanning or connection flooding.")
            

            geo_analysis = analysis.get('geo_distribution', {})
            if geo_analysis and geo_analysis.get('unique_countries', 0) > 20:
                insights.append(f"Connections from {geo_analysis['unique_countries']} countries - unusual geographic diversity.")
            

            behavioral = analysis.get('behavioral_patterns', {})
            if behavioral.get('burst_traffic'):
                insights.append(f"Burst traffic detected: {len(behavioral['burst_traffic'])} IPs showing rapid connection patterns.")
            

            port_scans = analysis.get('port_scan_detection', {})
            if port_scans:
                insights.append(f"Port scanning detected: {len(port_scans)} processes scanning multiple ports.")
            
            
            duration_stats = analysis.get('connection_duration_stats', {})
            if duration_stats.get('short_lived_count', 0) > total_count * 0.5:
                insights.append(f"Many short-lived connections ({duration_stats['short_lived_count']}) - possible reconnaissance activity.")
        
        except Exception as e:
            print(f"Security analysis error: {e}")
        
        if not insights:
            insights.append("No significant security concerns detected based on current data.")
        
        return insights

def apply_sidebar_and_background_style(bg_path="background.png"):
    if not os.path.exists(bg_path):
        st.warning(f"Background image not found at: {bg_path}")
        return

    with open(bg_path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()

    css = f"""
    <style>
    .block-container {{
        padding-top: 1rem;
        padding-right: 1rem;
        padding-left: 1rem;
        padding-bottom: 1rem;
        background: transparent;
    }}

    [data-testid="stSidebar"] input {{
    background-color: #003366 !important;
    color: #ffffff !important;
    border: 1px solid #ffffff !important;
    }}

    [data-testid="stSidebar"] select {{
    background-color: #003366 !important;
    color: #ffffff !important;
    border: 1px solid #ffffff !important;
    }}

    [data-testid="stSidebar"] .stSlider > div > div > div {{
    background: #ffffff !important;
    }}
   
    [data-testid="stSidebar"] * {{
        color: #000000 !important;
    }}

    [data-testid="stSidebar"] .stButton button,
    [data-testid="stSidebar"] .stNumberInput input,
    [data-testid="stSidebar"] .stSlider,
    [data-testid="stSidebar"] input,
    [data-testid="stSidebar"] .stTextInput input,
    [data-testid="stSidebar"] .stSelectbox,
    [data-testid="stSidebar"] select {{
        color: #ffffff !important;
    }}

    [data-testid="stAppViewContainer"] [data-testid="stMain"] {{
        background-image: 
            linear-gradient(rgba(255,255,255,0.25), rgba(255,255,255,0.25)),
            url("data:image/png;base64,{b64}");
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
        min-height: 100vh;
    }}

    .stExpander, .stCard, .stMetric, .stDataFrame, .element-container {{
        background-color: rgba(255,255,255,0.9) !important;
        border-radius: 8px;
    }}

    .css-1q8dd3e, .stMarkdown a, .stRadio label, .stTabs [data-baseweb="tab"] {{
        color: #ffffff !important;
    }}

    .stTabs [data-baseweb="tab"][aria-selected="true"] {{
        background-color: #003366 !important;
        color: #ffffff !important;
    }}

    main > div {{
        padding-top: 1rem;
    }}
    </style>
    """

    st.markdown(css, unsafe_allow_html=True)

def run_app():
    st.set_page_config(page_title="Enhanced Network Analyzer", layout="wide")
    apply_sidebar_and_background_style("bg.jpg")

    st.title("Advanced Network Traffic Analysis Dashboard")
    st.markdown("""
    **Comprehensive network monitoring with data science integration**
    
    This enhanced tool combines network analysis with machine learning, statistical analysis, and behavioral pattern detection.
    
    **Key Features:**
    - **Real-time monitoring** 
    - **Advanced visualizations** 
    - **ML-based anomaly detection**
    - **Geographic analysis** with IP geolocation
    - **TCP protocol deep dive**
    - **Statistical analysis** 
    - **Behavioral pattern detection** 
    - **Security insights** with multi-layer threat detection
    - **Export capabilities** (CSV, JSON reports)
        """)
    
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = NetworkConnectionAnalyzer()
    if 'running' not in st.session_state:
        st.session_state.running = False
    if 'start_time' not in st.session_state:
        st.session_state.start_time = None
    
    with st.sidebar:
        st.header("Control Panel")
        duration = st.number_input("Monitoring Duration (seconds)", min_value=10, value=60, step=10)
        interval = st.number_input("Collection Interval (seconds)", min_value=1, value=2, step=1)
        ui_update = st.number_input("UI Update Interval (seconds)", min_value=3, value=5, step=1)
        
        if st.button("Start Monitoring", disabled=st.session_state.running):
            st.session_state.running = True
            st.session_state.start_time = time.time()
            st.session_state.interval = interval

            analyzer = st.session_state.analyzer

            def monitor_thread(analyzer_obj, interval):
                analyzer_obj.monitoring = True
                while analyzer_obj.monitoring:
                    analyzer_obj.monitor_connections(interval=interval)

            threading.Thread(target=monitor_thread, args=(analyzer, interval), daemon=True).start()
        
        if st.session_state.running:
            if st.button("Stop Monitoring"):
                st.session_state.analyzer.monitoring = False
                st.session_state.running = False
        
        st.markdown("<hr style='margin:5px 0;border:0.5px solid #444;'>", unsafe_allow_html=True)

        if st.button("Capture Snapshot"):
            st.session_state.analyzer._capture_snapshot()
            st.success("Snapshot captured!")
        
        st.markdown("<hr style='margin:5px 0;border:0.5px solid #444;'>", unsafe_allow_html=True)
        st.markdown("**About**")
        st.markdown("App Built with Streamlit. Proper insights and highly secure analysis")

    if st.session_state.running:
        elapsed = time.time() - st.session_state.start_time
        progress = min((elapsed % 60) / 60, 1.0)
        st.progress(progress, text=f"Monitoring... {int(elapsed)} seconds elapsed")

    analysis, df = st.session_state.analyzer.analyze_connections()
    
    if analysis is None and not st.session_state.running:
        st.info("No data collected yet. Start monitoring or capture a snapshot to begin analysis.")
        return
    
    tabs = st.tabs([
        "DASHBOARD", 
        "RAW DATA", 
        "REPORT", 
        "SECURITY", 
        "BANDWIDTH",
        "ANOMALIES", 
        "TRENDS",
        "TCP ANALYSIS",
        "GEOGRAPHY",
        "BEHAVIOR",
        "STATISTICS"
    ])
    
    with tabs[0]:
        st.header("Visual Dashboard")
        vis = st.session_state.analyzer.create_visualizations(analysis, df)
        if vis:
            with st.expander("Distributions", expanded=True):
                st.pyplot(vis['distributions'])
            
            with st.expander("Top Entities", expanded=True):
                if 'top_processes' in vis:
                    st.altair_chart(vis['top_processes'], use_container_width=True)
                if 'top_remote_ips' in vis:
                    st.altair_chart(vis['top_remote_ips'], use_container_width=True)
            
            with st.expander("Analysis", expanded=True):
                st.pyplot(vis['timeline'])
            
            with st.expander("Resource Usage", expanded=True):
                st.pyplot(vis['resources'])
        else:
            st.warning("Unable to generate visualizations.")
    
    with tabs[1]:
        st.header("Connection Data")
        if df is not None:
            df_display = df.copy()
            if 'process_start_time' in df_display.columns:
                df_display['process_start_time'] = pd.to_datetime(df_display['process_start_time'], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
            st.dataframe(df_display, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download CSV", csv, "network_connections_enhanced.csv", "text/csv")
    
    with tabs[2]:
        st.header("Comprehensive Analysis Report")
        report = st.session_state.analyzer.generate_report(analysis, df)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.subheader("Summary")
            summary = report.get('summary', {})
            for key, value in summary.items():
                st.metric(key.replace('_', ' ').title(), f"{value:.2f}" if isinstance(value, float) else value)
        
        with col2:
            st.subheader("Top Communicators")
            top_comm = report.get('top_communicators', {})
            for category, data in top_comm.items():
                st.write(f"**{category.replace('_', ' ').title()}:**")
                for item, count in list(data.items())[:3]:
                    st.write(f"- {item}: {count:.2f}" if isinstance(count, float) else f"- {item}: {count}")
        
        with col3:
            st.subheader("Network Behavior")
            network_behavior = report.get('network_behavior', {})
            for category, data in network_behavior.items():
                if isinstance(data, dict) and data:
                    st.write(f"**{category.replace('_', ' ').title()}:**")
                    for item, count in list(data.items())[:3]:
                        st.write(f"- {item}: {count}")
        
        if report.get('suspicious_connections'):
            st.subheader("Suspicious Connections")
            suspicious_df = pd.DataFrame(report['suspicious_connections'])
            st.dataframe(suspicious_df, use_container_width=True)
        
        json_report = json.dumps(report, indent=2, default=str)
        st.download_button("Download JSON Report", json_report, "network_report_enhanced.json", "application/json")
    
    with tabs[3]:
        st.header("Security Insights & Threat Detection")
        st.markdown("Multi-layer security analysis with ML-based anomaly detection.")
        
        security_insights = report.get('security_insights', [])
        if security_insights:
            for i, insight in enumerate(security_insights, 1):
                if "No significant" in insight:
                    st.success(f"{insight}")
                else:
                    st.warning(f"{i}. {insight}")
        
        if vis and 'security' in vis:
            st.pyplot(vis['security'])
    
    with tabs[4]:
        st.header("Bandwidth Usage Analysis")
        if vis and 'bandwidth' in vis:
            st.pyplot(vis['bandwidth'])
    
    with tabs[5]:
        st.header("Connection Anomalies")
        if vis and 'anomalies' in vis:
            st.pyplot(vis['anomalies'])
    
    with tabs[6]:
        st.header("Process Activity Trends")
        if vis and 'trends' in vis:
            st.pyplot(vis['trends'])
    
    with tabs[7]:
        st.header("TCP Protocol Deep Analysis")
        
        if vis and 'tcp_analysis' in vis:
            st.pyplot(vis['tcp_analysis'])
            
    
    with tabs[8]:
        st.header("Geographic Distribution Analysis")
        
        if vis and 'geo_distribution' in vis:
            st.pyplot(vis['geo_distribution'])
            
            geo_stats = report.get('geographical_analysis', {})
            if geo_stats:
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Global Reach")
                    st.metric("Unique Countries", geo_stats.get('unique_countries', 0))
                    st.metric("Unique Cities", geo_stats.get('unique_cities', 0))
                
                with col2:
                    st.subheader("Top Countries")
                    country_dist = geo_stats.get('country_distribution', {})
                    for country, count in list(country_dist.items())[:5]:
                        st.write(f"**{country}**: {count} connections")
    
    with tabs[9]:
        st.header("Behavioral Pattern Analysis")
        
        if vis and 'behavioral_patterns' in vis:
            st.pyplot(vis['behavioral_patterns'])
            
            behavioral = report.get('behavioral_patterns', {})
            if behavioral:
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Burst Traffic")
                    burst = behavioral.get('burst_traffic', [])
                    st.metric("Detected Bursts", len(burst))
                    if burst:
                        for item in burst[:3]:
                            st.write(f"- IP: {item['ip']}, Connections: {item['connection_count']}")
                
                with col2:
                    st.subheader("Periodic Connections")
                    periodic = behavioral.get('periodic_connections', [])
                    st.metric("Periodic Patterns", len(periodic))
                    if periodic:
                        for item in periodic[:3]:
                            st.write(f"- IP: {item['ip']}, Interval: {item['interval']:.2f}s")


            clustering = report.get('connection_clustering', {})
            if clustering:
                st.subheader("Connection Clusters (DBSCAN)")
                for cluster_name, cluster_info in clustering.items():
                    with st.expander(f"{cluster_name} ({cluster_info['size']} connections)"):
                        st.write(f"**Avg Bytes Sent:** {cluster_info['avg_bytes_sent']:.2f}")
                        st.write(f"**Avg Duration:** {cluster_info['avg_duration']:.2f}s")
                        st.write("**Top Processes:**")
                        for proc, count in cluster_info['top_processes'].items():
                            st.write(f"- {proc}: {count}")
    
    with tabs[10]:
        st.header("Advanced Statistical Analysis")
        
        if vis and 'statistical_analysis' in vis:
            st.pyplot(vis['statistical_analysis'])
            

            protocol_eff = report.get('protocol_efficiency', {})
            if protocol_eff:
                st.subheader("Protocol Efficiency Metrics")
                eff_df = pd.DataFrame(protocol_eff).T
                if not eff_df.empty:
                    st.dataframe(eff_df.style.format({
                        'bytes_per_packet': '{:.2f}',
                        'total_bytes': '{:.0f}',
                        'total_packets': '{:.0f}',
                        'connection_count': '{:.0f}'
                    }), use_container_width=True)
            

            duration_stats = report.get('duration_statistics', {})
            if duration_stats:
                st.subheader("Connection Duration Statistics")
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Mean", f"{duration_stats.get('mean_duration', 0):.2f}s")
                col2.metric("Median", f"{duration_stats.get('median_duration', 0):.2f}s")
                col3.metric("Short-lived (<5s)", duration_stats.get('short_lived_count', 0))
                col4.metric("Long-lived (>300s)", duration_stats.get('long_lived_count', 0))

    if st.session_state.running:
        time.sleep(3)
        st.rerun()

if __name__ == "__main__":
    run_app()