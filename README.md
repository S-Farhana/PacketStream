# Advanced Network Traffic Analyzer Dashboard

**Real-time • Anomaly detection • Behavioral patterns • Security insights • Rich visualizations**

A powerful, interactive network monitoring tool built with **Streamlit**, **psutil**, **pandas**, **scikit-learn**, **seaborn**, **matplotlib**, **altair** and **IP geolocation**.

## Key Features

- Live monitoring of all TCP/UDP internet connections
- Process ↔ connection mapping (name, PID, memory, CPU usage)
- **Machine learning anomaly detection** (Isolation Forest)
- **Behavioral pattern recognition**  
  - burst traffic  
  - periodic/repeating connections  
- Potential **port scan** detection
- Remote IP **geolocation** (country / city via ip-api.com)
- TCP state transition tracking
- Connection duration statistics (short-lived vs long-lived)
- Traffic direction classification (inbound / outbound / internal)
- Protocol efficiency metrics (bytes per packet, etc.)
- DBSCAN-based connection clustering
- Multi-tab rich visualization dashboard
- Rule-based + ML-powered **security insights**
- CSV and structured JSON report export

## Screenshots

*(Add 4–6 screenshots here later)*

- Main dashboard with distributions & top entities  
- Security insights & anomaly flags  
- Geographic country/city views  
- Behavioral burst & clustering patterns  
- TCP state & duration histograms  
- Process CPU/memory trends over time  

## Quick Start

### Requirements

- Python 3.8 – 3.11
- Works best on **Linux**, acceptable on macOS, more limited on Windows

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer

# Create & activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate          # Linux / macOS
# or
.\venv\Scripts\activate           # Windows

# Install dependencies
pip install streamlit psutil pandas numpy matplotlib seaborn altair scikit-learn pillow requests


