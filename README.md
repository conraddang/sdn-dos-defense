# Multi-stage DoS attack mitigation

This project proposes and implements a concept for mitigating Denial of Service (DoS) 
attacks against the control plane. Please refer to the report and the authors for more
background information. This document shows how to set up the system.

### System setup

#### Overview
The system consists of a mininet network, a controller and the packet queue manager (PQM). 
The controller is then attacked and defends itself against the DoS attack.

#### How to setup the system
1. (optional) start demo components (flask server and GUI), see below for instructions
2. navigate to project folder /sdn
3. start mininet with: `sudo mn --custom topology.py --topo mytopo --controller=remote --mac`
4. start controller with: `ryu-manager --enable-debugger --observe-links controller.py`
5. (optional) to see active flows on switch 1: `watch --interval 1 sudo ovs-ofctl dump-flows s1` 
6. start PQM and attacker hosts: `xterm pcm att1`
7. on pcm-xterm, run: `sudo python3 packet_caching_module.py`
8. on att1-xterm, run: `sudo python3 dos_attack.py`, type a high amount of packets to be sent
when prompted (1000000) and press Enter
9. switch to GUI tab in browser
10. the attacker will send packets until e.g. 1000000 packets are reached. If
you want to continue the attack, rerun dos_attack.py on att1-xterm

### Demo

#### Demo server (Flask)

A flask server is the middlware between the webapp and the controller.

##### Installation
`pip install Flask`

##### Run server
`export FLASK_APP=server`

In `demo/server`

Run `flask run` or `python3 -m flask run`


#### GUI

React webapp allows interaction which controller and display rate of packets reaching controller and PQM. 

##### Install depencies

Install NPM. (In the provided VM we had some problems with npm. The installation of npm worked using nvm and `nvm install --lts`)

In `demo/gui` run `npm install`

##### Start GUI
In `demo/gui` run `npm start`

Visit GUI in http://localhost:3000
