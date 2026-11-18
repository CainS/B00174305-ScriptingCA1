import os
import json
from collections import Counter

# Read Function
def read_log_file(filepath):
    lines = []
    try: 
        with open(filepath, "r", encoding="utf-8") as file:
            for line in file: 
                lines.append(line.strip())
        print(f"Success: Read {len(lines)} lines from {filepath}")
    except FileNotFoundError: 
        print(f"Error: The file '{filepath}' was not found.")
        print(f"Please check that the 'data' folder exists and contains the log files.")
    except Exception as e: 
        print(f"An unexpected error occurred: {e}")
    return lines

# Firewall Parser
def parse_firewall(line): 
    parts = line.split()
    if len(parts) < 8:
        return None
    try: 
        timestamp = parts[0] + " " + parts[1]
        action = parts[2]
        event = {
            "timestamp": timestamp,
            "action": action,
            "src_ip": None, 
            "dst_ip": None,
            "protocol": None,
            "port": None,
            "bytes": None
        }
        for part in parts[3:]:
            if part.startswith("src="):
                event["src_ip"] = part.replace("src=", "")
            elif part.startswith("dst="):
                event["dst_ip"] = part.replace("dst=", "")
            elif part.startswith("proto="):
                event["protocol"] = part.replace("proto=", "")
            elif part.startswith("port="):
                event["port"] = part.replace("port=", "")
            elif part.startswith("bytes="):
                event["bytes"] = part.replace("bytes=", "")
        if not event["src_ip"] or not event["port"]:
            return None
        return event
    except Exception as e: 
        return None

# Auth Parser
def parse_auth(line):
    parts = line.split()
    if len(parts) < 7:
        return None
    try:
        timestamp = parts[0] + " " + parts[1]
        event_type = parts[2]
        event = {
            "timestamp": timestamp,
            "event": event_type,
            "user": None,
            "src_ip": None,
            "host": None,
            "method": None
        }
        for part in parts[3:]:
            if part.startswith("user="):
                event["user"] = part.replace("user=", "")
            elif part.startswith("src="):
                event["src_ip"] = part.replace("src=", "")
            elif part.startswith("host="):
                event["host"] = part.replace("host=", "")
            elif part.startswith("method="):
                event["method"] = part.replace("method=", "")
        if not event["user"] or not event["src_ip"]:
            return None
        return event
    except Exception as e:
        return None

# Analyse Functions
def analyse_firewall(log_lines):
    valid_count = 0
    allowed_count = 0
    blocked_count = 0

    allowed_ips = []
    blocked_ips = []
    dst_ports = []

    for line in log_lines: 
        event = parse_firewall(line)
        if event: 
            valid_count += 1
            if event["action"] == "ALLOWED":
                allowed_count += 1
                allowed_ips.append(event["src_ip"])
            elif event["action"] == "BLOCKED":
                blocked_count += 1
                blocked_ips.append(event["src_ip"])
            
            dst_ports.append(event["port"])

    top_blocked = Counter(blocked_ips).most_common(3)
    top_ports = Counter(dst_ports).most_common(5)

    return {
        "valid_events": valid_count, 
        "allowed": allowed_count,
        "blocked": blocked_count,
        "unique_blocked_ips": len(set(blocked_ips)), 
        "top_blocked": top_blocked,
        "top_ports": top_ports
    }

def analyse_auth(log_lines):
    success_count = 0
    failed_count = 0
    locked_count = 0
    
    failed_ips = []
    targeted_users = []
    
    for line in log_lines:
        event = parse_auth(line)
        
        if event:
            if event["event"] == "LOGIN_SUCCESS":
                success_count += 1
            elif event["event"] == "LOGIN_FAILED":
                failed_count += 1
                failed_ips.append(event["src_ip"])
                targeted_users.append(event["user"])
            elif event["event"] == "ACCOUNT_LOCKED":
                locked_count += 1
                
    top_failed_ips = Counter(failed_ips).most_common(3)
    top_users = Counter(targeted_users).most_common(3)
    
    return {
        "success": success_count,
        "failed": failed_count,
        "locked": locked_count,
        "unique_failed_ips": len(set(failed_ips)),
        "top_failed_ips": top_failed_ips,
        "top_users": top_users
    }

# Threat Intelligence Functions
def load_suspicious_ips(filepath):
    suspicious_ips = set()
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            for line in file:
                ip = line.strip()
                if ip: 
                    suspicious_ips.add(ip)
        print(f"Success: Loaded {len(suspicious_ips)} suspicious IPs.")
    except Exception as e:
        print(f"Error loading suspicious IPs: {e}")
    return suspicious_ips

def correlate_threats(firewall_lines, auth_lines, suspicious_ips):
    firewall_hits = []
    auth_hits = []
    
    for line in firewall_lines:
        event = parse_firewall(line)
        if event and event["src_ip"] in suspicious_ips:
            firewall_hits.append(event)
            
    for line in auth_lines:
        event = parse_auth(line)
        if event and event["src_ip"] in suspicious_ips:
            auth_hits.append(event)
            
    return {
        "firewall_hits": firewall_hits,
        "auth_hits": auth_hits,
        "total_hits": len(firewall_hits) + len(auth_hits)
    }

# Findings & Risk
def calculate_risk(firewall_stats, auth_stats, correlation_results):
    findings = []
    
    HIGH_FAILED_LOGINS = 100
    HIGH_BLOCKED_EVENTS = 300
    HIGH_CORRELATION_HITS = 50
    
    if auth_stats['failed'] > HIGH_FAILED_LOGINS:
        findings.append({
            "risk": "HIGH",
            "finding": "Brute force attack detected",
            "explanation": f"Detected {auth_stats['failed']} failed login attempts."
        })
    elif auth_stats['failed'] > 50:
        findings.append({
            "risk": "MEDIUM",
            "finding": "Elevated failed logins",
            "explanation": f"Detected {auth_stats['failed']} failed login attempts. Monitor for escalation."
        })
        
    if auth_stats['locked'] > 0:
        findings.append({
            "risk": "HIGH",
            "finding": "Account lockouts occurred",
            "explanation": f"{auth_stats['locked']} accounts were locked out."
        })

    if firewall_stats['blocked'] > HIGH_BLOCKED_EVENTS:
        findings.append({
            "risk": "MEDIUM",
            "finding": "High volume of blocked traffic",
            "explanation": f"{firewall_stats['blocked']} events were blocked."
        })

    if correlation_results['total_hits'] > HIGH_CORRELATION_HITS:
        findings.append({
            "risk": "HIGH",
            "finding": "Known malicious IPs active",
            "explanation": f"Found {correlation_results['total_hits']} events from IPs on the suspicious list."
        })
    elif correlation_results['total_hits'] > 0:
        findings.append({
            "risk": "MEDIUM",
            "finding": "Known malicious IPs detected",
            "explanation": f"Found {correlation_results['total_hits']} events from suspicious IPs."
        })
        
    return findings

def save_json_report(filename, firewall_stats, auth_stats, correlation_results, findings):
    report = {
        "firewall_analysis": firewall_stats,
        "authentication_analysis": auth_stats,
        "threat_correlation": correlation_results,
        "findings": findings
    }
    
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)
        print(f"Report successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving report: {e}")

def save_txt_report(filename, firewall_stats, auth_stats, correlation_results, findings):
    try: 
        with open(filename, "w", encoding="utf-8") as file:
            file.write("--------------------------------\n")
            file.write("---Security Log Investigation---\n")
            file.write("--------------------------------\n\n")

            file.write("---Firewall Summary---\n")
            file.write(f"Total Valid Events: {firewall_stats['valid_events']}\n")
            file.write(f"Blocked: {firewall_stats['blocked']}\n")
            file.write(f"Allowed: {firewall_stats['allowed']}\n")
            file.write(f"Unique Blocked IPs: {firewall_stats['unique_blocked_ips']}\n\n")

            file.write("---Authentication Summary---\n")
            file.write(f"Success: {auth_stats['success']}\n")
            file.write(f"Failed: {auth_stats['failed']}\n")
            file.write(f"Locked: {auth_stats['locked']}\n\n")

            file.write("---Threat Intelligence---\n")
            file.write(f"Total Hits: {correlation_results['total_hits']}\n\n")

            file.write("---Findings---\n")
            if not findings: 
                file.write("No significant findings detected\n")
            else: 
                for item in findings:
                    file.write(f"[{item['risk']}] {item['finding']}\n")
                    file.write(f"  - {item['explanation']}\n\n")

        print(f"Success: TXT report saved to {filename}")
    except Exception as e:
        print(f"Error saving TXT report: {e}")
        

    # Main Block
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    firewall_path = os.path.join(script_dir, "data", "firewall.log")
    auth_path = os.path.join(script_dir, "data", "authentication.log")
    suspicious_ips_path = os.path.join(script_dir, "data", "suspicious_ips.txt")
    
    firewall_lines = None
    auth_lines = None
    suspicious_ips = None
    firewall_stats = None
    auth_stats = None
    correlation_results = None
    findings = None

    while True:
        print("\n" + "="*50)
        print("--- Security Log Investigation Tool ---")
        print("="*50)
        print("1. Read Logs")
        print("2. Analyse Firewall Log")
        print("3. Analyse Authentication Log")
        print("4. Load Suspicious IPs")
        print("5. Correlate Threats")
        print("6. Generate Findings & Risk Assessment")
        print("7. Save Report (TXT & JSON)")
        print("0. Exit")
        print("="*50)
        
        choice = input("Enter your choice: ").strip()
        
        if choice == "0":
            print("Exiting...")
            break
            
        elif choice == "1":
            print("\n--- Loading Data ---")
            firewall_lines = read_log_file(firewall_path)
            auth_lines = read_log_file(auth_path)
            print("Data loaded successfully.")
            
        elif choice == "2":
            if firewall_lines:
                print("\n---Firewall Analysis Results---")
                firewall_stats = analyse_firewall(firewall_lines)
                print(f"Total Valid Events: {firewall_stats['valid_events']}")
                print(f"Allowed: {firewall_stats['allowed']}")
                print(f"Blocked: {firewall_stats['blocked']}")
                print(f"Unique Blocked IPs: {firewall_stats['unique_blocked_ips']}")
                print("\nTop 3 Blocked Source IPs (IP, Count):")
                for ip, count in firewall_stats['top_blocked']:
                    print(f"  {ip}: {count}")
                print("\nTop 5 Targeted Destination Ports (Port, Count):")
                for port, count in firewall_stats['top_ports']:
                    print(f"  Port {port}: {count}")
            else:
                print("\nError: Please load data first (Option 1).")
                
        elif choice == "3":
            if auth_lines:
                print("\n--- Authentication Analysis Results ---")
                auth_stats = analyse_auth(auth_lines)
                print(f"LOGIN_SUCCESS: {auth_stats['success']}")
                print(f"LOGIN_FAILED: {auth_stats['failed']}")
                print(f"ACCOUNT_LOCKED: {auth_stats['locked']}")
                print(f"Unique Failed Login IPs: {auth_stats['unique_failed_ips']}")
                print("\nTop 3 Failed Login Source IPs (IP, Count):")
                for ip, count in auth_stats['top_failed_ips']:
                    print(f"  {ip}: {count}")
                print("\nTop 3 Targeted Usernames (User, Count):")
                for user, count in auth_stats['top_users']:
                    print(f"  {user}: {count}")
            else:
                print("\nError: Please load data first (Option 1).")
                
        elif choice == "4":
            print("\n--- Loading Threat Intelligence ---")
            suspicious_ips = load_suspicious_ips(suspicious_ips_path)
            
        elif choice == "5":
            if firewall_lines and auth_lines and suspicious_ips:
                print("\n--- Threat Intelligence Correlation ---")
                correlation_results = correlate_threats(firewall_lines, auth_lines, suspicious_ips)
                print(f"Total log events matching suspicious IP list: {correlation_results['total_hits']}")
                print(f"  - Firewall events: {len(correlation_results['firewall_hits'])}")
                print(f"  - Authentication events: {len(correlation_results['auth_hits'])}")
                
                found_ips = set([e["src_ip"] for e in correlation_results["firewall_hits"] + correlation_results["auth_hits"]])
                print("\nSuspicious IPs found in logs:")
                for ip in found_ips:
                    print(f"  - {ip}")
            else:
                print("\nError: Please complete steps 1 and 4 first.")
                
        elif choice == "6":
            if firewall_stats and auth_stats and correlation_results:
                print("\n--- Analyst Findings ---")
                findings = calculate_risk(firewall_stats, auth_stats, correlation_results)
                if not findings:
                    print("No significant findings detected based on current thresholds.")
                else:
                    for item in findings:
                        print(f"[{item['risk']}] {item['finding']}")
                        print(f"  -> {item['explanation']}")
                        print()
            else:
                print("\nError: Please complete steps 2, 3, and 5 first.")
                
        elif choice == "7":
            if not firewall_lines or not auth_lines:
                firewall_lines = read_log_file(firewall_path)
                auth_lines = read_log_file(auth_path)

            if not suspicious_ips:
                suspicious_ips = load_suspicious_ips(suspicious_ips_path)

            if not firewall_stats:
                firewall_stats = analyse_firewall(firewall_lines)

            if not auth_stats:
                auth_stats = analyse_auth(auth_lines)

            if not correlation_results:
                correlation_results = correlate_threats(firewall_lines, auth_lines, suspicious_ips)

            if findings is None:
                findings = calculate_risk(firewall_stats, auth_stats, correlation_results)

            if firewall_stats and auth_stats and correlation_results and findings is not None:

                output_dir = os.path.join(script_dir, "output")
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)

                json_report_path = os.path.join(output_dir, "report.json")
                txt_report_path = os.path.join(output_dir, "report.txt")

                print("\n--- Saving Reports ---")
                save_json_report(json_report_path, firewall_stats, auth_stats, correlation_results, findings)
                save_txt_report(txt_report_path, firewall_stats, auth_stats, correlation_results, findings)
            else:
                print("\nError: Couldnt generate report.")

        else: 
            print("\nInvalid choice. Please select a valid option.")

