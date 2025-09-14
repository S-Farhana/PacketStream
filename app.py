import psutil
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import time
import threading
from collections import defaultdict
import json
from datetime import datetime
import warnings
import streamlit as st
from PIL import Image

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
        
    def monitor_connections(self, interval=2):
        self.monitoring = True

        while self.monitoring:
            timestamp = time.time()
            
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
                            conn_data = self._extract_connection_info(conn, timestamp)
                            if conn_data:
                                self.connections_data.append(conn_data)
                                self._update_stats(conn_data)
                                new_connections.append(conn_data)

                except:
                    continue
                    
            self.connections_data = self.connections_data[-200:]

            for conn_data in new_connections:
                print(f"New connection: {conn_data['process']} {conn_data['local_ip']}:{conn_data['local_port']} -> {conn_data['remote_ip']}:{conn_data['remote_port']}")

            self.prev_connections = current_connections
            time.sleep(interval)

        self.monitoring = False

    def _capture_snapshot(self):
        try:
            connections = psutil.net_connections(kind='inet')
            timestamp = time.time()
            
            for conn in connections:
                try:
                    conn_data = self._extract_connection_info(conn, timestamp)
                    if conn_data:
                        self.connections_data.append(conn_data)
                        self._update_stats(conn_data)
                except:
                    continue
        except:
            pass
    
    def _extract_connection_info(self, conn, timestamp):
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
        try:
            if conn.pid:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                pid = conn.pid
                process_memory = process.memory_info().rss / (1024 * 1024)  # MB
                process_cpu = process.cpu_percent(interval=0.01)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        protocol = 'TCP' if conn.type == 1 else 'UDP' if conn.type == 2 else 'Unknown'
        
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
            'process_cpu_percent': process_cpu
        }
    
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
    
    def analyze_connections(self):
        if not self.connections_data:
            return None, None
        
        df = pd.DataFrame(self.connections_data)
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['local_ip', 'local_port', 'remote_ip', 'remote_port', 'process'])
        
        if len(df) == 0:
            return None, None
        
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
            'avg_process_cpu': df.groupby('process')['process_cpu_percent'].mean().sort_values(ascending=False).head(10)
        }
        
        return analysis, df
    
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
    
    def create_visualizations(self, analysis, df):
        visualizations = {}
        try:
            fig_dist, axes_dist = plt.subplots(1, 3, figsize=(24, 8))
            fig_dist.suptitle('Network Distributions', fontsize=18, fontweight='bold')
            
            if not analysis['protocol_distribution'].empty:
                axes_dist[0].pie(analysis['protocol_distribution'].values, labels=analysis['protocol_distribution'].index, 
                                 autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_dist[0].set_title('Protocol Distribution', fontsize=14)
            else:
                axes_dist[0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if not analysis['status_distribution'].empty:
                sns.barplot(x=analysis['status_distribution'].index, y=analysis['status_distribution'].values, ax=axes_dist[1])
                axes_dist[1].set_title('Connection Status', fontsize=14)
                axes_dist[1].set_xlabel('Status')
                axes_dist[1].set_ylabel('Count')
                axes_dist[1].tick_params(axis='x', rotation=45)
                for p in axes_dist[1].patches:
                    axes_dist[1].annotate(f'{int(p.get_height())}', (p.get_x() + p.get_width() / 2., p.get_height()), 
                                          ha='center', va='center', xytext=(0, 5), textcoords='offset points')
            else:
                axes_dist[1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if not analysis['direction_distribution'].empty:
                axes_dist[2].pie(analysis['direction_distribution'].values, labels=analysis['direction_distribution'].index, 
                                 autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_dist[2].set_title('Traffic Direction', fontsize=14)
            else:
                axes_dist[2].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['distributions'] = fig_dist

            fig_top, axes_top = plt.subplots(2, 3, figsize=(24, 16))
            fig_top.suptitle('Top Network Entities', fontsize=18, fontweight='bold')
            
            if not analysis['top_processes'].empty:
                top_processes = analysis['top_processes'].head(8)
                sns.barplot(x=top_processes.values, y=top_processes.index, ax=axes_top[0,0], orient='h')
                axes_top[0,0].set_title('Top 8 Processes by Connections', fontsize=14)
                axes_top[0,0].set_xlabel('Count')
                axes_top[0,0].set_ylabel('Process')
                for p in axes_top[0,0].patches:
                    axes_top[0,0].annotate(f'{int(p.get_width())}', (p.get_width(), p.get_y() + p.get_height() / 2.), 
                                           xytext=(5, 0), textcoords='offset points', ha='left', va='center')
            else:
                axes_top[0,0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if not analysis['top_remote_ips'].empty:
                top_ips = analysis['top_remote_ips'].head(8)
                sns.barplot(x=top_ips.values, y=top_ips.index, ax=axes_top[0,1], orient='h')
                axes_top[0,1].set_title('Top Remote IPs', fontsize=14)
                axes_top[0,1].set_xlabel('Count')
                axes_top[0,1].set_ylabel('IP')
                for p in axes_top[0,1].patches:
                    axes_top[0,1].annotate(f'{int(p.get_width())}', (p.get_width(), p.get_y() + p.get_height() / 2.), 
                                           xytext=(5, 0), textcoords='offset points', ha='left', va='center')
            else:
                axes_top[0,1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if analysis['port_categories']:
                port_cats = pd.Series(analysis['port_categories'])
                axes_top[0,2].pie(port_cats.values, labels=port_cats.index, autopct='%1.1f%%', startangle=90, shadow=True, textprops={'fontsize': 12})
                axes_top[0,2].set_title('Port Categories', fontsize=14)
            else:
                axes_top[0,2].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if not analysis['top_remote_ports'].empty:
                port_dist = analysis['top_remote_ports'].head(10)
                sns.barplot(x=port_dist.values, y=port_dist.index.astype(str), ax=axes_top[1,0], orient='h')
                axes_top[1,0].set_title('Top 10 Remote Ports', fontsize=14)
                axes_top[1,0].set_xlabel('Count')
                axes_top[1,0].set_ylabel('Port')
                for p in axes_top[1,0].patches:
                    axes_top[1,0].annotate(f'{int(p.get_width())}', (p.get_width(), p.get_y() + p.get_height() / 2.), 
                                           xytext=(5, 0), textcoords='offset points', ha='left', va='center')
            else:
                axes_top[1,0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            
            if not analysis['top_local_ports'].empty:
                local_ports = analysis['top_local_ports'].head(10)
                sns.barplot(x=local_ports.values, y=local_ports.index.astype(str), ax=axes_top[1,1], orient='h')
                axes_top[1,1].set_title('Top 10 Local Ports', fontsize=14)
                axes_top[1,1].set_xlabel('Count')
                axes_top[1,1].set_ylabel('Port')
                for p in axes_top[1,1].patches:
                    axes_top[1,1].annotate(f'{int(p.get_width())}', (p.get_width(), p.get_y() + p.get_height() / 2.), 
                                           xytext=(5, 0), textcoords='offset points', ha='left', va='center')
            else:
                axes_top[1,1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            axes_top[1,2].axis('off')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['top_entities'] = fig_top

            fig_time, axes_time = plt.subplots(1, 2, figsize=(24, 8))
            fig_time.suptitle('Timeline and Cross-Analysis', fontsize=18, fontweight='bold')
            
            if len(df) > 1:
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
                timeline = df.groupby(df['datetime'].dt.floor('1Min')).size()
                if not timeline.empty:
                    sns.lineplot(x=timeline.index, y=timeline.values, marker='o', ax=axes_time[0])
                    axes_time[0].set_title('Connections Over Time (per minute)', fontsize=14)
                    axes_time[0].set_xlabel('Time')
                    axes_time[0].set_ylabel('Count')
                    axes_time[0].tick_params(axis='x', rotation=45)
                else:
                    axes_time[0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            else:
                axes_time[0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            if len(df) > 0 and df['process'].nunique() > 1 and df['direction'].nunique() > 1:
                top_processes = df['process'].value_counts().head(8).index
                filtered_df = df[df['process'].isin(top_processes)]
                if not filtered_df.empty:
                    pd.crosstab(filtered_df['process'], filtered_df['direction']).plot(kind='bar', stacked=True, ax=axes_time[1])
                    axes_time[1].set_title('Top Processes by Direction', fontsize=14)
                    axes_time[1].set_xlabel('Process')
                    axes_time[1].set_ylabel('Count')
                    axes_time[1].tick_params(axis='x', rotation=45)
                    axes_time[1].legend(title='Direction', bbox_to_anchor=(1.05, 1), loc='upper left')
            else:
                axes_time[1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
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
                for p in axes_resource[0].patches:
                    axes_resource[0].annotate(f'{p.get_width():.2f}', (p.get_width(), p.get_y() + p.get_height() / 2.), 
                                              xytext=(5, 0), textcoords='offset points', ha='left', va='center')
            else:
                axes_resource[0].text(0.5, 0.5, 'No Data', ha='center', va='center')
            

            if not analysis['avg_process_cpu'].empty:
                cpu = analysis['avg_process_cpu'].head(8)
                sns.barplot(x=cpu.values, y=cpu.index, ax=axes_resource[1], orient='h')
                axes_resource[1].set_title('Top Processes by Avg CPU (%)', fontsize=14)
                axes_resource[1].set_xlabel('CPU (%)')
                axes_resource[1].set_ylabel('Process')
                for p in axes_resource[1].patches:
                    axes_resource[1].annotate(f'{p.get_width():.2f}', (p.get_width(), p.get_y() + p.get_height() / 2.), 
                                              xytext=(5, 0), textcoords='offset points', ha='left', va='center')
            else:
                axes_resource[1].text(0.5, 0.5, 'No Data', ha='center', va='center')
            
            plt.tight_layout(rect=[0, 0.03, 1, 0.95])
            visualizations['resources'] = fig_resource

            return visualizations
        except Exception as e:
            print(f"Visualization error: {e}")
            return None
    
    def generate_report(self, analysis, df):
        if df is None or len(df) == 0:
            return {"error": "No data to generate report"}
        
        duration = df['timestamp'].max() - df['timestamp'].min() if len(df) > 1 else 0
        connection_rate = len(df) / duration if duration > 0 else 0
        
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
            },
            'network_behavior': {
                'protocol_breakdown': analysis['protocol_distribution'].to_dict(),
                'direction_breakdown': analysis['direction_distribution'].to_dict(),
                'status_breakdown': analysis['status_distribution'].to_dict()
            },
            'security_insights': self._security_analysis(df),
            'top_communicators': {
                'processes': analysis['top_processes'].head(5).to_dict(),
                'remote_ips': analysis['top_remote_ips'].head(5).to_dict(),
                'avg_memory': analysis['avg_process_memory'].head(5).to_dict(),
                'avg_cpu': analysis['avg_process_cpu'].head(5).to_dict()
            }
        }
        return report
    
    def _security_analysis(self, df):
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
                insights.append(f"Multiple low-port listeners ({low_port_listen}) - typically requires privileges, but detected.")
            
            high_resource_processes = df[df['process_cpu_percent'] > 50]['process'].unique()
            if len(high_resource_processes) > 0:
                insights.append(f"High CPU processes: {', '.join(high_resource_processes)} - investigate for mining or attacks.")
        except:
            pass
        
        if not insights:
            insights.append("No significant security concerns detected based on current data.")
        
        return insights


import base64, os, pathlib

def apply_sidebar_and_background_style(bg_path="background.png"):
    if not os.path.exists(bg_path):
        st.warning(f"Background image not found at: {bg_path}")
        return

    with open(bg_path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()

    css = f"""
    <style>
    /* remove block container paddings so background shows edge-to-edge */
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
    background: #ffffff !important;  /* slider track */
    }}
   
    /* Make sidebar controls text white too */
    [data-testid="stSidebar"] * {{
        color: #000000 !important;
    }}

    /* Buttons/inputs keep normal look but text white */
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
            linear-gradient(rgba(255,255,255,0.25), rgba(255,255,255,0.25)),  /* white transparent overlay */
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
        color: #ffffff !important;   /* make white */
    }}

    /* Active tab highlight background */
    .stTabs [data-baseweb="tab"][aria-selected="true"] {{
        background-color: #003366 !important;  /* dark blue active tab */
        color: #ffffff !important;
    }}

    main > div {{
        padding-top: 1rem;
    }}
    </style>
    """

    st.markdown(css, unsafe_allow_html=True)



def run_app():
    st.set_page_config(page_title="Live Network Analyzer", layout="wide")
    apply_sidebar_and_background_style("bg.jpg")

    st.title("Live Network Traffic Dashboard")
    st.markdown("""
    This tool provides real-time monitoring and analysis of network connections. It captures data securely and presents insights in a dashboard.
    
    **Key Features:**
    - Live dynamic updates during monitoring
    - Visualizations and insights
    - Resource usage analysis
    - Generates Report in json format
    - Raw data export in csv format 
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
        st.info("No data collected yet. Start monitoring or capture a snapshot.")
        return
    
    tabs = st.tabs(["DASHBOARD", "RAW DATA", "REPORT", "SECURITY INSIGHTS"])
    
    with tabs[0]:
        st.header("Visual Dashboard")
        st.markdown("""
        This dashboard is divided into segregated sections for better understanding:
        - **Distributions**: Breakdowns of protocols, statuses, and directions.
        - **Top Entities**: Most active processes, IPs, and ports.
        - **Timeline & Cross-Analysis**: Time-based trends and relationships.
        - **Resource Usage**: CPU and memory consumption by processes.
        """)
        
        vis = st.session_state.analyzer.create_visualizations(analysis, df)
        if vis:
            with st.expander("Distributions", expanded=True):
                st.pyplot(vis['distributions'])
                st.markdown("**Explanation**: These charts show the proportional breakdown of different network aspects for quick overview.")
            
            with st.expander("Top Entities", expanded=True):
                st.pyplot(vis['top_entities'])
                st.markdown("**Explanation**: Highlights the most frequently occurring elements in your network traffic.")
            
            with st.expander("Timeline & Cross-Analysis", expanded=True):
                st.pyplot(vis['timeline'])
                st.markdown("**Explanation**: Tracks changes over time and relationships between processes and traffic directions.")
            
            with st.expander("Resource Usage", expanded=True):
                st.pyplot(vis['resources'])
                st.markdown("**Explanation**: Monitors how much CPU and memory are used by processes involved in connections.")
        else:
            st.warning("Unable to generate visualizations.")
    
    with tabs[1]:
        st.header("Raw Connection Data")
        st.markdown("""
        Detailed table of all unique connections captured. 
        - Use the search and sort features to explore.
        - Export to CSV for further analysis.
        """)
        if df is not None:
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download CSV", csv, "network_connections.csv", "text/csv")
    
    with tabs[2]:
        st.header("Analysis Report")
        st.markdown("""
        Structured summary of key metrics and behaviors:
        - **Summary**: Overall statistics.
        - **Top Communicators**: Highest activity entities.
        - **Network Behavior**: Breakdowns of protocols, directions, and statuses.
        - Download the full report as JSON.
        """)
        report = st.session_state.analyzer.generate_report(analysis, df)
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Summary")
            
            summary = report.get('summary')
            if summary:
                for key, value in summary.items():
                    st.metric(key.replace('_', ' ').title(), f"{value:.2f}" if isinstance(value, float) else value)
            else:
                st.warning("No summary available in the report.")

        top_communicators = report.get('top_communicators')

        if top_communicators:
            with col2:
                st.subheader("Top Communicators")
                for category, data in top_communicators.items():
                    st.write(f"**{category.replace('_', ' ').title()}:**")
                    for item, count in data.items():
                        st.write(f"- {item}: {count:.2f}" if isinstance(count, float) else f"- {item}: {count}")
        else:
            with col2:
                st.subheader("Top Communicators")
                st.warning("No top communicator data available.")

        network_behavior = report.get('network_behavior')
        if network_behavior:
            st.subheader("Network Behavior")
            cols = st.columns(len(network_behavior))
            for i, (category, data) in enumerate(network_behavior.items()):
                with cols[i]:
                    st.write(f"**{category.replace('_', ' ').title()}:**")
                    for item, count in data.items():
                        st.write(f"- {item}: {count}")
        
        json_report = json.dumps(report, indent=2, default=str)
        st.download_button("Download JSON Report", json_report, "network_report.json", "application/json")
    

    with tabs[3]:
        st.header("Security Insights")
        st.markdown("""
        Automated detection of potential issues based on patterns:
        - **High Outbound Traffic**: Possible data leak.
        - **Frequent IPs**: Concentrated traffic.
        - **Unusual Ports**: Non-standard services.
        - **Listening Services**: Potential entry points.
        - **High Resources**: Suspicious activity.
        """)
        security_insights = report.get('security_insights')

        if security_insights:
            for insight in security_insights:
                st.warning(insight)
        else:
            st.success("No issues detected.")

    if st.session_state.running:
        time.sleep(3)
        st.rerun()


if __name__ == "__main__":
    run_app()