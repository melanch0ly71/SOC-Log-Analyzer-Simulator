**SOC Log Analyzer Simulator**
**Description**
A Python tool that simulates basic SOC (Security Operations Center) monitoring by analyzing SSH authentication logs. It detects suspicious activity like repeated failed login attempts and generates alerts to help you understand how a SOC analyst monitors systems.
**Features**
1. Parses SSH-style authentication logs
2. Detects brute-force attacks (multiple failed logins from the same IP)
3. Tracks usernames and IPs for suspicious activity
4. Saves alerts with timestamps to alerts/alerts.txt
5. Handles large log files efficiently
**Setup**
1. Clone this repository:
  git clone https://github.com/melanch0ly71/SOC-Log-Analyzer-Simulator
  cd SOC_Log_Analyzer_Simulator
2. Make sure you have python3 installed.
3. Place your log files in the logs/ folder (sample provided: sample_auth.log).
**Usage**
Run the analyzer with:
    _python soc_log_analyzer.py_
