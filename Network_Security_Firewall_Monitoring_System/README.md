# Network Security and Firewall Monitoring System

A faculty-demo-ready educational project that demonstrates firewall rule filtering,
network traffic classification, suspicious activity detection, security logs, and alerts.

## Features
- Dashboard with total / allowed / blocked / suspicious traffic counters
- Add firewall rules by source IP, destination port, protocol, and action
- Simulate traffic using the sample traffic generator
- Submit custom traffic for testing
- Default-deny behavior when no rule matches
- Security event log and suspicious-activity alerts
- Clear demo logs

## Important
This project uses **simulated traffic**. It does not sniff live packets, modify your
operating-system firewall, or attack networks. This makes it safe and reliable for
a classroom demonstration without administrator privileges.

## Requirements
- Python 3.9+
- Internet connection only for the first-time Flask installation

## Run on Windows
1. Extract the ZIP.
2. Open the project folder in VS Code.
3. Open Terminal and run:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python app.py
   ```

4. Open: http://127.0.0.1:5000

If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## Demo plan for faculty
1. Open the dashboard and explain the counters.
2. Click **Simulate Sample Traffic** to generate permitted and blocked requests.
3. Show the event log and alert panel.
4. Add a rule: source `192.168.1.50`, port `8080`, protocol `TCP`, action `ALLOW`.
5. Test custom traffic with the same values. It should be allowed.
6. Change the rule to BLOCK or delete it, then test again.
7. Test port 22 or 3389 to show suspicious blocked activity.
8. Clear logs and start a fresh demonstration.

## Architecture
Browser UI -> Flask routes -> Rule Engine -> Traffic Classification -> Event Log / Alert Engine -> Dashboard.

## Project modules
- `app.py`: Flask application, firewall rule engine, traffic simulator, logs and alerts
- `templates/index.html`: dashboard interface
- `static/style.css`: responsive styling
- `static/app.js`: custom traffic submission and live refresh

## Limitations
This is an educational prototype with simulated packets. Production monitoring would
require packet capture, authentication, persistent storage, stronger rule validation,
and deployment hardening.
