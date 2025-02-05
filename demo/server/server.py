from flask import Flask
from flask import request
import time

app = Flask(__name__)

# Default values
dos_attack_status = False
controller_stage = "NORMAL"
packet_rate_controller = []
packet_rate_pqm = []
threshold = 400 # Default. Unit is 1/s.

MAX_LENGTH_PACKET_RATE_LIST = 10000 # We keep at max this many data points in memory


@app.route("/")
def hello_world():
    return 'Hello World'

@app.route("/threshold", methods=['GET'])
def get_threshold():
    return {"threshold": threshold}

@app.route("/threshold", methods=['POST'])
def post_threshold():
    global threshold
    global dos_attack_status
    threshold = request.json
    if (threshold == 9999999): # hardcode for inactive defense
        dos_attack_status = "OFF"
    return ""

@app.route("/controller_stage", methods=['GET'])
def get_controller_stage():
    return {"stage": controller_stage}

@app.route("/controller_stage", methods=['POST'])
def post_controller_stage():
    global controller_stage
    controller_stage = request.json
    return ""

@app.route("/attack_status", methods=['GET'])
def get_attack_status():
    global dos_attack_status
    return {"status": dos_attack_status}

@app.route("/attack_status", methods=['POST'])
def set_attack_status():
    global dos_attack_status
    dos_attack_status = request.json

@app.route('/packet_rate', methods=['GET'])
def packet_rates_get():
    return {"controller": packet_rate_controller, "pqm": packet_rate_pqm}

@app.route('/packet_rate_pqm', methods=['POST'])
def packet_rates_pqm_post():
    packet_rate_pqm.append({"x": time.time(), "y": request.json}) 
    while (len(packet_rate_pqm) > MAX_LENGTH_PACKET_RATE_LIST):
        packet_rate_pqm.pop(0)
    return ""

@app.route('/packet_rate_controller', methods=['POST'])
def packet_rates_controller_post():
    packet_rate_controller.append({"x": time.time(), "y": request.json})
    while (len(packet_rate_controller) > MAX_LENGTH_PACKET_RATE_LIST):
        packet_rate_controller.pop(0)
    return ""

@app.route('/packet_rate_reset', methods=['POST'])
def packet_rates_reset():
    global packet_rate_controller, packet_rate_pqm
    packet_rate_controller = []
    packet_rate_pqm = []
    return ""
