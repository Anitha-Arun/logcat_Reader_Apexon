import re
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for
import os
from datetime import datetime
import json

app = Flask(__name__)

class LogcatEntry:
    def __init__(self, date, time, pid, tid, level, tag, message):
        self.date = date
        self.time = time
        self.pid = pid
        self.tid = tid
        self.level = level
        self.tag = tag
        self.message = message
        self.timestamp = f"{date} {time}"

    def __str__(self):
        return f"{self.timestamp} {self.pid} {self.tid} {self.level} {self.tag}: {self.message}"

def parse_line(line):
    pattern = r"(\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([IWEDV])\s+([^:]+):\s+(.+)"
    match = re.match(pattern, line.strip())
    if match:
        return LogcatEntry(*match.groups())
    
    parts = line.strip().split()
    if len(parts) >= 6 and re.match(r"\d{2}-\d{2}", parts[0]) and re.match(r"\d{2}:\d{2}:\d{2}\.\d{3}", parts[1]):
        date, time = parts[0], parts[1]
        pid, tid = parts[2], parts[3]
        level = parts[4] if parts[4] in "IWEDV" else "I"
        tag = parts[5].rstrip(":")
        message = " ".join(parts[6:])
        return LogcatEntry(date, time, pid, tid, level, tag, message)
    
    return None

def parse_logcat(file_path):
    logs = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            log = parse_line(line)
            if log:
                logs.append(log)
    return logs

import re

def extract_versions(message):
    """Extract software versions from log message as a dictionary."""
    versions = {}
    
    # Pattern for flat format: "key":"value"
    flat_pattern = r'"(\w+Version(?:Name)?)":"([^"]*)"'
    flat_matches = re.findall(flat_pattern, message)
    print(f"Flat matches: {flat_matches}")  # Debug
    
    for key, value in flat_matches:
        key_lower = key.lower()
        if "adminagent" in key_lower:
            versions["adminAgent_" + ("name" if "name" in key_lower else "code")] = value
        elif "companyportal" in key_lower:
            versions["companyPortal_" + ("name" if "name" in key_lower else "code")] = value
        elif "teamsapp" in key_lower:
            versions["teamsApp_" + ("name" if "name" in key_lower else "code")] = value
        elif "oemagent" in key_lower or "partneragent" in key_lower:
            versions["partnerAgent_" + ("name" if "name" in key_lower else "code")] = value
        elif "osversion" in key_lower or "firmware" in key_lower:
            versions["firmware_" + ("name" if "name" in key_lower else "code")] = value
        elif "ngmsapp" in key_lower:
            versions["ngmsApp_" + ("name" if "name" in key_lower else "code")] = value
        elif "authenticatorapp" in key_lower:
            versions["authenticatorApp_" + ("name" if "name" in key_lower else "code")] = value
    
    # Pattern for nested format: "softwareVersions":{...}
    nested_pattern = r'"softwareVersions":\s*{([^}]*?(?:{[^}]*}[^}]*?)*)}'
    nested_match = re.search(nested_pattern, message)
    if nested_match:
        nested_content = nested_match.group(1)
        # Extract each app's version info
        app_pattern = r'"(\w+)":\s*{"versionName":"([^"]*)","versionCode":([^}]*)}'
        nested_matches = re.findall(app_pattern, nested_content)
        print(f"Nested matches: {nested_matches}")  # Debug
        
        for app, name, code in nested_matches:
            app_lower = app.lower()
            if "adminagent" in app_lower:
                versions["adminAgent_name"] = name
                versions["adminAgent_code"] = code.strip().replace('"', '')
            elif "companyportal" in app_lower:
                versions["companyPortal_name"] = name
                versions["companyPortal_code"] = code.strip().replace('"', '')
            elif "teamsapp" in app_lower:
                versions["teamsApp_name"] = name
                versions["teamsApp_code"] = code.strip().replace('"', '')
            elif "partneragent" in app_lower or "oemagent" in app_lower:
                versions["partnerAgent_name"] = name
                versions["partnerAgent_code"] = code.strip().replace('"', '')
            elif "firmware" in app_lower or "osversion" in app_lower:
                versions["firmware_name"] = name
                versions["firmware_code"] = code.strip().replace('"', '')
            elif "ngmsapp" in app_lower:
                versions["ngmsApp_name"] = name
                versions["ngmsApp_code"] = code.strip().replace('"', '')
            elif "authenticatorapp" in app_lower:
                versions["authenticatorApp_name"] = name
                versions["authenticatorApp_code"] = code.strip().replace('"', '')
    
    print(f"Extracted versions: {versions}")  # Debug
    return versions

def versions_to_string(versions):
    """Convert versions dict to a sorted string for comparison."""
    return "\n".join(f"{k}: {v}" for k, v in sorted(versions.items()))

import re
import json

def summarize_logs(logs):
    """Summarize log data into a structured dictionary."""
    summary = {
        "total_lines": len(logs),
        "errors": [],
        "warnings": [],
        "info_count": 0,
        "boot_time": None,
        "device_info": {
            "model": None,
            "manufacturer": None,
            "serial": None,
            "flavor": None,
            "user_type": None,
            "device_ids": [],  # List of {"id": "...", "timestamp": "..."}
            "teams_ids": [],   # List of {"id": "...", "timestamp": "..."}
            "software_versions": [],
            "sign_in_history": [],
            "mac_addresses": [],
            "ip_address": []
        }
    }
    version_counts = {}

    for log in logs:
        timestamp = f"{log.date} {log.time}"
        
        # Extract Device ID (from uniqueId, oemSerialNumber, or deviceId)
        device_id_match = re.search(r"(?:uniqueId|oemSerialNumber)='([^']*)'", log.message) or \
                          re.search(r'"(?:deviceId|uniqueId|oemSerialNumber)":"([^"]*)"', log.message)
        if device_id_match:
            device_id = device_id_match.group(1)
            summary["device_info"]["device_ids"].append({"id": device_id, "timestamp": timestamp})
        
        # Extract Teams ID (from teamsIdentifier)
        teams_id_match = re.search(r'"teamsIdentifier":"([^"]*)"', log.message)
        if teams_id_match:
            try:
                teams_data = json.loads(teams_id_match.group(1))
                teams_id = teams_data.get("deviceId", None)
                if teams_id:
                    summary["device_info"]["teams_ids"].append({"id": teams_id, "timestamp": timestamp})
            except json.JSONDecodeError:
                pass
        
        # Extract software versions
        versions = extract_versions(log.message)
        if versions:
            version_key = "\n".join(f"{k}: {v}" for k, v in sorted(versions.items()))
            if version_key in version_counts:
                version_counts[version_key].append(timestamp)
            else:
                version_counts[version_key] = [timestamp]
        
        # Extract other device info
        if "model" in log.message.lower():
            model_match = re.search(r"model='([^']*)'|\"model\":\"([^\"]*)\"", log.message)
            if model_match:
                summary["device_info"]["model"] = model_match.group(1) or model_match.group(2)
        
        if "manufacturer" in log.message.lower():
            manuf_match = re.search(r"manufacturer='([^']*)'|\"manufacturer\":\"([^\"]*)\"", log.message)
            if manuf_match:
                summary["device_info"]["manufacturer"] = manuf_match.group(1) or manuf_match.group(2)
        
        if "serial" in log.message.lower():
            serial_match = re.search(r"serial='([^']*)'|\"serial\":\"([^\"]*)\"", log.message)
            if serial_match:
                summary["device_info"]["serial"] = serial_match.group(1) or serial_match.group(2)
        
        if "flavor" in log.message.lower():
            flavor_match = re.search(r"flavor='([^']*)'|\"flavor\":\"([^\"]*)\"", log.message)
            if flavor_match:
                summary["device_info"]["flavor"] = flavor_match.group(1) or flavor_match.group(2)
        
        if "userType" in log.message.lower():
            user_type_match = re.search(r"userType='([^']*)'|\"userType\":\"([^\"]*)\"", log.message)
            if user_type_match:
                summary["device_info"]["user_type"] = user_type_match.group(1) or user_type_match.group(2)
        
        # Log level counts
        if log.level == "E":
            summary["errors"].append(log.message)
        elif log.level == "W":
            summary["warnings"].append(log.message)
        elif log.level == "I":
            summary["info_count"] += 1
        
        # Boot time (example logic, adjust as needed)
        if "boot" in log.message.lower():
            summary["boot_time"] = timestamp
        
        # Sign-in history (example logic, adjust as needed)
        sign_in_match = re.search(r'"signInState":"([^"]*)".*?"timestamp":(\d+)', log.message)
        if sign_in_match:
            state, unix_ts = sign_in_match.groups()
            user_id_match = re.search(r'"userId":"([^"]*)"', log.message)
            user_id = user_id_match.group(1) if user_id_match else "Unknown"
            summary["device_info"]["sign_in_history"].append({
                "timestamp": timestamp,
                "state": state,
                "user_id": user_id,
                "unix_timestamp": int(unix_ts)
            })
        
        # MAC addresses (example logic, adjust as needed)
        mac_match = re.search(r'"macAddresses":\s*\[(.*?)\]', log.message)
        if mac_match:
            mac_list = []
            for mac_entry in re.findall(r'{"interfaceType":"([^"]*)","macAddress":"([^"]*)"}', mac_match.group(1)):
                mac_list.append({"interface_type": mac_entry[0], "mac_address": mac_entry[1]})
            if mac_list:
                summary["device_info"]["mac_addresses"].append({"timestamp": timestamp, "mac_list": mac_list})
        
        # IP address (example logic, adjust as needed)
        ip_match = re.search(r'"ipAddress":"([^"]*)"', log.message)
        if ip_match:
            summary["device_info"]["ip_address"].append({"timestamp": timestamp, "ip": ip_match.group(1)})

    # Populate software versions
    for version_key, timestamps in version_counts.items():
        versions = dict(line.split(": ", 1) for line in version_key.split("\n"))
        firmware_type = "User used Company Portal Firmware"
        if versions.get("ngmsApp_name", "") or versions.get("ngmsApp_code", "-1") != "-1":
            firmware_type = "User used NGMS Firmware"
        summary["device_info"]["software_versions"].append({
            "versions": versions,
            "timestamps": timestamps,
            "firmware_type": firmware_type
        })

    print(f"Total unique software versions stored: {len(summary['device_info']['software_versions'])}")
    print(f"Software versions data: {summary['device_info']['software_versions']}")
    print(f"Device IDs: {summary['device_info']['device_ids']}")
    print(f"Teams IDs: {summary['device_info']['teams_ids']}")
    return summary

# Helper function for template (if not already defined)
def unix_to_readable(unix_timestamp):
    from datetime import datetime
    return datetime.fromtimestamp(unix_timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')

def analyze_log_entry(log):
    analysis = {"type": "", "description": "", "details": [], "insights": []}
    
    if "DeviceMetaData" in log.message:
        analysis["type"] = "Device Metadata"
        analysis["description"] = "Information about the device and its login status."
        flavor = re.search(r"flavor='([^']+)'", log.message)
        user_type = re.search(r"userType='([^']+)'", log.message)
        if flavor:
            analysis["details"].append(f"Device Type: {flavor.group(1)} (e.g., IP phone).")
        if user_type:
            analysis["details"].append(f"User Category: {user_type.group(1)} (personal or shared user).")
        analysis["insights"].append("The device is set up and connected to a service.")

    elif "EnrollRequest" in log.message:
        analysis["type"] = "Enrollment Request"
        analysis["description"] = "The device is registering with a service (e.g., Teams)."
        method = re.search(r"enrollmentMethod=([^,]+)", log.message)
        if method:
            analysis["details"].append(f"Method: {method.group(1)} (registration type).")
        analysis["insights"].append("This is the device joining a network or service.")

    elif "ScaleDensityUtils" in log.tag and "dpi" in log.message:
        analysis["type"] = "Display Settings"
        analysis["description"] = "Adjusting screen display for readability."
        dpi = re.search(r"dpi:(\d+)", log.message)
        if dpi:
            analysis["details"].append(f"DPI: {dpi.group(1)} (screen resolution setting).")
        analysis["insights"].append("Ensures the display looks clear and sharp.")

    elif "Booting" in log.message and log.pid == "0":
        analysis["type"] = "Device Startup"
        analysis["description"] = "The device’s core system is starting up."
        cpu = re.search(r"CPU (0x[0-9a-f]+)", log.message)
        if cpu:
            analysis["details"].append(f"Processor: {cpu.group(1)} (hardware starting).")
        analysis["insights"].append("The device is powering on.")

    elif "LogonUserWatcher" in log.tag:
        analysis["type"] = "User Login Update"
        analysis["description"] = "Update on user login status."
        sign_in_state = re.search(r"signInState\":\"([^\"]+)\"", log.message) or re.search(r"signInState='([^']+)'", log.message)
        if sign_in_state:
            analysis["details"].append(f"Status: {sign_in_state.group(1)} (logged in or out).")
        analysis["insights"].append("Tracks user activity on the device.")

    elif log.level == "E":
        analysis["type"] = "Error"
        analysis["description"] = "Something went wrong on the device."
        analysis["details"].append(f"Message: {log.message} (what failed).")
        if "timeout" in log.message.lower():
            analysis["insights"].append("A process took too long and stopped. Check connections or resources.")
        elif "null" in log.message.lower():
            analysis["insights"].append("Something expected was missing. Could be a setup issue.")
        else:
            analysis["insights"].append("An unexpected problem occurred. May need technical review.")

    elif log.level == "W":
        analysis["type"] = "Warning"
        analysis["description"] = "A potential issue that didn’t stop the device."
        analysis["details"].append(f"Message: {log.message} (what’s concerning).")
        if "deprecated" in log.message.lower():
            analysis["insights"].append("Using old software/method. Update recommended.")
        else:
            analysis["insights"].append("Not critical yet, but keep an eye on it.")

    if not analysis["type"]:
        analysis["type"] = "General Info"
        analysis["description"] = "Routine device status update."
        analysis["details"].append(f"Message: {log.message}.")
        analysis["insights"].append("Normal operation, no action needed.")

    return analysis

def unix_to_readable(unix_ts):
    if unix_ts:
        return datetime.fromtimestamp(unix_ts / 1000).strftime('%Y-%m-%d %H:%M:%S')
    return "Unknown"

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            file_path = os.path.join("uploads", file.filename)
            if not os.path.exists("uploads"):
                os.makedirs("uploads")
            file.save(file_path)
            logs = parse_logcat(file_path)
            if not logs:
                return "No valid log entries found in the file."
            summary = summarize_logs(logs)
            log_groups = defaultdict(list)
            for log in logs:
                log_groups[(log.level, log.tag, log.message)].append(log.timestamp)
            analyzed_logs = [(LogcatEntry("", ts, "0", "0", level, tag, msg), analyze_log_entry(LogcatEntry("", ts, "0", "0", level, tag, msg))) 
                            for (level, tag, msg), timestamps in log_groups.items() for ts in timestamps]
            return render_template('summary.html', summary=summary, analyzed_logs=analyzed_logs, unix_to_readable=unix_to_readable)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)