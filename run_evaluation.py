import logging
from datetime import datetime, timedelta
from src.engine.evaluation_harness import EvaluationHarness, Scenario

def main():
    harness = EvaluationHarness()
    now = datetime.now()

    # --- MALICIOUS SCENARIOS (Target: detection) ---

    # 1. Brute Force
    harness.add_scenario(Scenario("Brute Force Attack", True, [
        {"timestamp": (now + timedelta(seconds=i)).isoformat(), "event_type": "login_failure", "severity": "high", "source": f"remote-ip-{i}"}
        for i in range(10)
    ]))

    # 2. USB Drop & File Steal
    harness.add_scenario(Scenario("USB Drop & File Steal", True, [
        {"timestamp": now.isoformat(), "event_type": "usb_inserted", "severity": "medium", "source": "USB-Mass-Storage"},
        {"timestamp": (now + timedelta(seconds=2)).isoformat(), "event_type": "file_created", "severity": "low", "source": "explorer.exe"},
        {"timestamp": (now + timedelta(seconds=5)).isoformat(), "event_type": "process_started", "severity": "medium", "source": "cmd.exe"}
    ]))

    # 3. Network Exfiltration (Suspicious Port)
    harness.add_scenario(Scenario("Data Exfiltration", True, [
        {"timestamp": now.isoformat(), "event_type": "process_started", "severity": "low", "source": "powershell.exe"},
        {"timestamp": (now + timedelta(seconds=1)).isoformat(), "event_type": "network_suspicious_port", "severity": "high", "source": "powershell.exe"}
    ]))

    # 4. Rapid File Deletion (Ransomware-like)
    harness.add_scenario(Scenario("Rapid File Deletion", True, [
        {"timestamp": (now + timedelta(milliseconds=i*100)).isoformat(), "event_type": "file_deleted", "severity": "medium", "source": "unknown.exe"}
        for i in range(20)
    ]))

    # --- BENIGN SCENARIOS (Target: no false flags) ---

    # 5. Normal Web Browsing
    harness.add_scenario(Scenario("Web Browsing", False, [
        {"timestamp": (now + timedelta(minutes=5, seconds=i*30)).isoformat(), "event_type": "process_started", "severity": "low", "source": "chrome.exe"}
        for i in range(5)
    ]))

    # 6. Software Update
    harness.add_scenario(Scenario("System Update", False, [
        {"timestamp": (now + timedelta(minutes=10)).isoformat(), "event_type": "process_started", "severity": "low", "source": "trustedinstaller.exe"},
        {"timestamp": (now + timedelta(minutes=10, seconds=5)).isoformat(), "event_type": "file_modified", "severity": "low", "source": "trustedinstaller.exe"}
    ]))

    # 7. Document Editing
    harness.add_scenario(Scenario("Document Editing", False, [
        {"timestamp": (now + timedelta(minutes=15)).isoformat(), "event_type": "file_modified", "severity": "low", "source": "winword.exe"}
        for i in range(3)
    ]))

    # 8. Background Services
    harness.add_scenario(Scenario("Background Noise", False, [
        {"timestamp": (now + timedelta(minutes=20)).isoformat(), "event_type": "network_connection_new", "severity": "low", "source": "svchost.exe"}
    ]))

    # Run evaluation
    print("Executing Sentinel-X Evaluation Harness...")
    print(f"Scenarios: 4 Malicious, 4 Benign\n")

    results = harness.run()
    print(results)

if __name__ == "__main__":
    main()
