from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import time
from collections import deque
import threading

app = Flask(__name__)
CORS(app)

# Store recent data points for visualization
MAX_DATA_POINTS = 60
packet_counts = deque(maxlen=MAX_DATA_POINTS)
bandwidth_in = deque(maxlen=MAX_DATA_POINTS)
bandwidth_out = deque(maxlen=MAX_DATA_POINTS)
timestamps = deque(maxlen=MAX_DATA_POINTS)

def collect_network_data():
    """Collect network data every second"""
    last_time = time.time()
    last_bytes_sent = psutil.net_io_counters().bytes_sent
    last_bytes_recv = psutil.net_io_counters().bytes_recv
    last_packets_sent = psutil.net_io_counters().packets_sent
    last_packets_recv = psutil.net_io_counters().packets_recv

    while True:
        time.sleep(1)
        current_time = time.time()
        io_counters = psutil.net_io_counters()
        
        # Calculate rates
        bytes_sent = io_counters.bytes_sent
        bytes_recv = io_counters.bytes_recv
        packets_sent = io_counters.packets_sent
        packets_recv = io_counters.packets_recv
        
        # Calculate bandwidth (KB/s)
        time_diff = current_time - last_time
        bandwidth_in_rate = (bytes_recv - last_bytes_recv) / time_diff / 1024
        bandwidth_out_rate = (bytes_sent - last_bytes_sent) / time_diff / 1024
        packet_rate = ((packets_sent - last_packets_sent) + (packets_recv - last_packets_recv)) / time_diff
        
        # Update deques
        packet_counts.append(packet_rate)
        bandwidth_in.append(bandwidth_in_rate)
        bandwidth_out.append(bandwidth_out_rate)
        timestamps.append(time.strftime("%H:%M:%S"))
        
        # Update last values
        last_bytes_sent = bytes_sent
        last_bytes_recv = bytes_recv
        last_packets_sent = packets_sent
        last_packets_recv = packets_recv
        last_time = current_time

# Start data collection in a separate thread
threading.Thread(target=collect_network_data, daemon=True).start()

@app.route('/')
def index():
    with open('templates/index.html', 'r') as file:
        return file.read()

@app.route('/network_data')
def get_network_data():
    return jsonify({
        'timestamps': list(timestamps),
        'packet_counts': list(packet_counts),
        'bandwidth_in': list(bandwidth_in),
        'bandwidth_out': list(bandwidth_out)
    })

if __name__ == '__main__':
    app.run(debug=True)