# 🌐 Advanced Network Traffic Analysis Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Streamlit-1.x-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white"/>
  <img src="https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
</p>

<p align="center">
  A real-time network monitoring and security analysis dashboard that combines <br/>
  systems programming, machine learning, and interactive data visualization <br/>
  into a single powerful tool.
</p>

---

##  Dashboard Preview

> **11 interactive tabs** — Dashboard · Raw Data · Report · Security · Bandwidth · Anomalies · Trends · TCP Analysis · Geography · Behavior · Statistics

---

##  Features

| Feature | Description |
|---|---|
| 🔴 **Real-time Monitoring** | Continuously captures active TCP/UDP connections using `psutil` |
| 🤖 **ML Anomaly Detection** | Isolation Forest flags statistically unusual connections |
| 📊 **DBSCAN Clustering** | Groups connections by behavioral patterns |
| 🌍 **IP Geolocation** | Maps remote IPs to country and city in real time |
| 🔒 **Security Insights** | 15+ rule-based threat detection checks |
| 📡 **TCP State Analysis** | Tracks TCP state transitions and detects SYN floods |
| 🗺️ **Geographic Distribution** | Visualizes global connection reach |
| 📈 **Bandwidth Analysis** | Per-process bandwidth usage over time |
| 🔍 **Port Scan Detection** | Flags processes contacting unusually many ports |
| 💡 **Behavioral Patterns** | Detects burst traffic and periodic beaconing |
| 📤 **Export** | Download raw data as CSV or full report as JSON |
| 🎨 **Custom UI** | Background image theming with custom CSS injection |

---

##  Tech Stack

### Core Language
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)

### Frontend / Dashboard
| Library | Version | Purpose |
|---|---|---|
| `streamlit` | 1.x | Interactive web dashboard |
| `altair` | 4.x+ | Responsive interactive charts |
| `matplotlib` | 3.x | Multi-panel static visualizations |
| `seaborn` | 0.x | Statistical heatmaps and bar plots |
| `Pillow (PIL)` | 9.x+ | Image handling for background |

### Data & Analysis
| Library | Version | Purpose |
|---|---|---|
| `pandas` | 1.x+ | Data manipulation and DataFrames |
| `numpy` | 1.x+ | Numerical operations and array math |
| `scipy` | 1.x+ | Statistical analysis |

### Machine Learning
| Library | Version | Purpose |
|---|---|---|
| `scikit-learn` | 1.x | Isolation Forest, DBSCAN, StandardScaler |

### System & Networking
| Library | Version | Purpose |
|---|---|---|
| `psutil` | 5.x+ | System-level network & process data |
| `socket` | stdlib | Reverse DNS hostname resolution |
| `threading` | stdlib | Background monitoring thread |
| `requests` | 2.x | IP geolocation API calls |

### Utilities
| Library | Purpose |
|---|---|
| `collections` (defaultdict, deque) | Rolling windows & frequency counting |
| `hashlib` | Hashing utilities |
| `json` | Report serialization |
| `base64` | Background image encoding for CSS injection |
| `datetime` | Timestamp formatting |

---

##  Project Structure

```
network-analyzer/
│
├── app.py                  # Main application entry point
├── bg.jpg                  # Background image for dashboard UI
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
│
└── exports/                # Auto-generated export files
    ├── network_connections_enhanced.csv
    └── network_report_enhanced.json
```

---

##  Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the App
```bash
streamlit run app.py
```

>  **Note:** On Linux/macOS, run with `sudo` for full connection visibility:
> ```bash
> sudo streamlit run app.py
> ```

---

##  Requirements

Create a `requirements.txt` with the following:

```txt
streamlit>=1.20.0
psutil>=5.9.0
pandas>=1.5.0
numpy>=1.23.0
matplotlib>=3.6.0
seaborn>=0.12.0
altair>=4.2.0
scikit-learn>=1.1.0
scipy>=1.9.0
requests>=2.28.0
Pillow>=9.0.0
```

---

##  How to Use

### Step 1 — Configure in the Sidebar
- Set **Monitoring Duration** (seconds)
- Set **Collection Interval** (how often to poll connections)
- Set **UI Update Interval** (dashboard refresh rate)

### Step 2 — Start Monitoring
- Click **"Start Monitoring"** to begin continuous real-time capture
- Or click **"Capture Snapshot"** for a one-time point-in-time capture

### Step 3 — Explore the Dashboard
Navigate through the 11 tabs:

| Tab | What You'll Find |
|---|---|
| **DASHBOARD** | Protocol distribution, traffic direction, top processes & IPs |
| **RAW DATA** | Full connection table with CSV download |
| **REPORT** | Summary metrics, network behavior, JSON export |
| **SECURITY** | Threat insights, anomaly heatmaps |
| **BANDWIDTH** | Per-process bandwidth over time |
| **ANOMALIES** | Scatter plot of unusual IPs and ports |
| **TRENDS** | Rolling CPU and memory usage per process |
| **TCP ANALYSIS** | State distribution, connection duration histogram |
| **GEOGRAPHY** | Country/city distribution, direction by country |
| **BEHAVIOR** | Burst traffic, periodic patterns, DBSCAN clusters |
| **STATISTICS** | Correlation matrix, connection rate, protocol comparison |

### Step 4 — Export
- Download **CSV** from the Raw Data tab
- Download **JSON Report** from the Report tab

---

##  Machine Learning Components

### Isolation Forest (Anomaly Detection)
- **Algorithm:** Isolation Forest (`sklearn.ensemble.IsolationForest`)
- **Features:** duration, bytes sent/received, packets sent/received, port variety, IP frequency, bytes-per-packet ratio
- **Contamination:** 10% (flags top 10% outliers)
- **Output:** Binary anomaly label per connection (0 = normal, 1 = anomalous)

### DBSCAN (Connection Clustering)
- **Algorithm:** Density-Based Spatial Clustering (`sklearn.cluster.DBSCAN`)
- **Parameters:** eps=0.5, min_samples=2
- **Purpose:** Groups similar connections; noise points (label=-1) indicate truly unusual behavior
- **Features:** Same normalized feature space as anomaly detection

---

##  Security Detection Rules

The engine runs **15+ checks**, including:

- 🚨 High outbound traffic ratio → possible data exfiltration
- 🚨 High connection frequency to single IP → C2 communication
- 🚨 Unusual port diversity → backdoor or custom service
- 🚨 Many short-lived connections → reconnaissance scanning
- 🚨 High SYN_SENT count → port scan or SYN flood
- 🚨 High CPU process → cryptomining or exploit
- 🚨 Multi-country connections → unusual geographic reach
- 🚨 Burst traffic patterns → DDoS or aggressive retry
- 🚨 Port scan detection → process contacting 10+ unique ports
- ✅ ML-flagged anomalies from Isolation Forest

---

##  Known Limitations

- Per-connection **bandwidth data is simulated** — `psutil` does not expose per-connection byte counts. True per-connection data requires packet capture (`scapy` / `libpcap`)
- Requires **elevated privileges** on Linux for full visibility (`sudo`)
- Geolocation depends on the **free ip-api.com** API (rate limited at 45 req/min)
- **No persistent storage** — data is lost when the session ends
- No built-in **authentication** — do not expose publicly without a proxy layer

---

##  Future Improvements

- [ ] Real packet capture with `scapy` for accurate bandwidth data
- [ ] SQLite / PostgreSQL backend for persistent historical storage
- [ ] Async geolocation queue to avoid any blocking
- [ ] Offline MaxMind GeoIP2 database integration
- [ ] Slack / Email alerting on security threshold breach
- [ ] Docker container with proper Linux `NET_ADMIN` capability
- [ ] Authentication layer (Basic Auth or OAuth)
- [ ] WebSocket-based live updates instead of `st.rerun()` polling

---

##  Analysis Capabilities

```
Network Layer          → Protocol distribution, TCP state tracking, port categorization
Process Layer          → Per-process CPU, memory, bandwidth, connection count
Security Layer         → 15+ threat rules + ML anomaly detection
Geographic Layer       → Country/city mapping, direction by geography
Behavioral Layer       → Burst traffic, periodic beaconing, DBSCAN clusters
Statistical Layer      → Correlation matrix, connection rate, duration stats
