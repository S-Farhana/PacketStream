# Advanced Network Traffic Analyzer Dashboard

**Real-time • Anomaly detection • Behavioral patterns • Security insights • Rich visualizations**

A powerful, interactive network monitoring tool built with **Streamlit**, **psutil**, **pandas**, **scikit-learn**, **seaborn**, **matplotlib**, **altair** and **IP geolocation**.

## ✨ Key Features

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

## 📸 Screenshots

*(Add 4–6 screenshots here later)*

- Main dashboard with distributions & top entities  
- Security insights & anomaly flags  
- Geographic country/city views  
- Behavioral burst & clustering patterns  
- TCP state & duration histograms  
- Process CPU/memory trends over time  

## 🚀 Quick Start

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


Run the application
Bashstreamlit run app.py
# or whatever you named your main file
→ Open browser: http://localhost:8501
🛠️ Platform Notes & Limitations















































FeatureWindowsmacOSLinuxComment / RequirementProcess usernameOften missingUsually worksWorks wellWindows privacy restrictionsListening sockets PIDFrequently NoneUsually visibleNormally visibleAdmin/root rights often neededPer-connection bytes/packetsSimulatedSimulatedSimulatedpsutil does not provide real countersGeolocationWorksWorksWorksNeeds internet (ip-api.com – free, rate-limited)Performance (many connections)SlowMediumFastestMemory usage grows quickly above ~800–1000 connections
🔐 Recommended Privileges
Linux
Bashsudo streamlit run app.py
# or more safely:
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
streamlit run app.py
Windows
Run PowerShell / CMD as Administrator if you want to see more listening ports and accurate process information.
⚠️ Security & Privacy Notes

This tool does not capture packet contents
It does not perform deep packet inspection
It reveals real network activity from your machine
Be careful when sharing screenshots, CSV exports, or JSON reports
Geolocation queries go to a free third-party API (ip-api.com)

📊 Available Dashboard Tabs





















































TabPurpose / Main ContentDASHBOARDKey pie charts, bar plots, top processes & IPsRAW DATAFull connection table + CSV downloadREPORTStructured metrics + JSON exportSECURITYThreat hypotheses, anomaly list, ML flagsBANDWIDTHSent vs received bytes per process (heatmap + lines)ANOMALIESScatter: connection count vs unusual portsTRENDSRolling CPU & memory usage per top processTCP ANALYSISTCP states distribution + duration histogramGEOGRAPHYCountry & city breakdown, direction by countryBEHAVIORBurst traffic, periodic patterns, DBSCAN clustersSTATISTICSCorrelation matrix, traffic rate, protocol comparison
🛠️ Tech Stack Highlights

Streamlit – interactive UI
psutil – system & network information
pandas / numpy – data handling
scikit-learn – Isolation Forest + DBSCAN
matplotlib / seaborn / altair – visualization layers
requests – IP geolocation API calls
