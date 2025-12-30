import win32evtlog
import time
import requests
import json

# =====================================================
# CONFIGURATION
# =====================================================
SERVER = 'localhost'
LOG_TYPE = 'Security'
# NOTE: We target ScreenerAgent as the entry point. 
# In a full production mesh, this would hit an Orchestrator/Ingestor.
API_URL = "http://localhost:7071/api/ScreenerAgent"

# NOISE FILTER: Events we want to ignore because they happen too often
# 5379 = Credential Manager Read (Noise)
# 4624 = Successful Logon (Normal noise)
IGNORE_LIST = [5379, 4624] 

# DEFINITION: Known Malicious Intent Categories
FORBIDDEN = ["credential_access", "privilege_escalation", "data_exfiltration"]

def tail_windows_logs():
    print(f"🔌 Connecting to Windows {LOG_TYPE} Event Log...")
    print("   (Filtering out common noise like Event 5379...)")
    print("   (Forwarding telemetry to AI Defense Swarm...)")
    
    # NOTE: In a production forwarder (Splunk/Sentinel), we would persist 
    # the 'LastReadRecordID' to prevent duplicates on restart. 
    # For this real-time MVP, we start reading from the current stream.
    hand = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    try:
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if events:
                for event in events:
                    event_id = event.EventID
                    
                    # 1. SKIP NOISE
                    if event_id in IGNORE_LIST:
                        continue 
                        
                    msg = str(event.StringInserts)
                    print(f"\n⚡ Detected Real Event: {event_id}")
                    
                    # 2. SEND TO AGENT 1 (Ingestion Layer)
                    # Note: We function as a 'Forwarder' here, not the policy enforcer.
                    payload = {
                        "id": f"Win-{event_id}",
                        "message": f"EventID: {event_id}. Data: {msg}",
                        "user_role": "system" # Telemetry Source Context (Not an RBAC identity)
                    }
                    
                    try:
                        response = requests.post(API_URL, json=payload)
                        
                        # 3. DISPLAY SWARM VERDICT (Visualization Only)
                        # We print what the AI decided. We do not make the decision.
                        data = response.json()
                        risk_data = data.get("risk_analysis", {})
                        
                        intent = risk_data.get("intent", "unknown")
                        impact = risk_data.get("impact", "unknown")
                        try:
                            confidence = float(risk_data.get("confidence", 0.0))
                        except:
                            confidence = 0.0


                        print(f"   🔎 Brain Analysis: Intent='{intent}' | Impact='{impact}' | Conf={confidence:.2f}")

                        # Unified Visual Status
                        if impact == "credential_theft" or (intent in FORBIDDEN and confidence > 0.7):
                            print("   ❌ SWARM VERDICT: MALICIOUS (Escalation Signal Sent)")
                        elif impact in ["destructive", "sensitive_read"]:
                            print("   ⚠️ SWARM VERDICT: SUSPICIOUS (Verification Required)")
                        else:
                            print("   ✅ SWARM VERDICT: ALLOWED")
                            
                    except Exception as e:
                        print(f"   ⚠️ Connection Error: {e}")
                        
            # Simple polling delay
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("Stopping connector...")

if __name__ == "__main__":
    tail_windows_logs()