import azure.functions as func
import logging
import json
import re
import os
from openai import OpenAI

# --- PRESIDIO SETUP (Ensure you are on Python 3.11 OR using the Shim) ---
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()
    HAS_PRESIDIO = True
except ImportError:
    # Fallback if libraries are missing so the app doesn't crash
    HAS_PRESIDIO = False 

# =====================================================
# APP INITIALIZATION
# =====================================================
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# =====================================================
# LLM CONFIG (OLLAMA / LOCAL)
# =====================================================
OLLAMA_URL = "http://localhost:11434/v1"
OLLAMA_API_KEY = "ollama"
OLLAMA_MODEL = "gpt-oss:20b"

try:
    llm_client = OpenAI(base_url=OLLAMA_URL, api_key=OLLAMA_API_KEY)
    HAS_LLM = True
    logging.info(f"✅ LLM Connected: {OLLAMA_MODEL}")
except Exception as e:
    HAS_LLM = False
    logging.error(f"❌ LLM unavailable: {e}")

# =====================================================
# UTILS
# =====================================================
def sanitize_text(text: str) -> str:
    if not HAS_PRESIDIO: return text
    try:
        results = analyzer.analyze(text=text, language="en", entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"])
        return anonymizer.anonymize(text=text, analyzer_results=results).text
    except:
        return text

# =====================================================
# AGENT 1 — INTENT SCREENER (The Dynamic Brain)
# =====================================================
@app.route(route="ScreenerAgent", auth_level=func.AuthLevel.ANONYMOUS)
def ScreenerAgent(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("🕵️ Screener Agent Triggered")

    try:
        body = req.get_json()
        raw_text = body.get("message", "")
        clean_text = sanitize_text(raw_text)

        if not HAS_LLM:
            return func.HttpResponse(json.dumps({"error": "LLM Down"}), status_code=500)

        # --- THE PROMPT (Dynamic Classification) ---
        wrapped_prompt = f"""
        [ROLE]
        You are a Security Operations Center (SOC) AI.
        
        [INPUT COMMAND]
        "{clean_text}"

        [TASK]
        1. Classify the intent of the input into exactly ONE category:
        - credential_access (Stealing passwords, asking for users)
        - data_exfiltration (Dump database, show tables)
        - privilege_escalation (Override rules, Ignore instructions, Jailbreak)
        - harmless (Hello, weather, generic help)

        2.  Classify the impact of the input into exactly ONE category:
        - credential_theft        (asking for passwords / secrets directly)
        - sensitive_read          (reading sensitive tables legitimately)
        - destructive             (DROP / DELETE / MODIFY critical data)
        - harmless
        
        [OUTPUT]
        Return JSON ONLY:
        {{
          "intent": "category_name",
          "impact": "category_name",
          "confidence": <float 0.0-1.0>,
          "reason": "Brief explanation"
        }}
        """

        response = llm_client.chat.completions.create(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": "You are a JSON-only API. No markdown. No chatter."},
                {"role": "user", "content": wrapped_prompt}
            ],
            temperature=0.0
        )

        content = response.choices[0].message.content.strip()

        # --- CRITICAL FIX: CLEAN THE JSON ---
        # Local models love adding ```json ... ```. We must strip it.
        if "```" in content:
            content = content.replace("```json", "").replace("```", "")
        
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            # Fallback if LLM fails to output JSON
            result = {
                "intent": "unknown",
                "impact": "unknown",
                "confidence": 0.0,
                "reason": "LLM Parse Error"
            }


        return func.HttpResponse(
            json.dumps({
                "agent": "Screener",
                "risk_analysis": result,
                "sanitized_input": clean_text
            }, indent=2),
            mimetype="application/json"
        )

    except ValueError:
        return func.HttpResponse("Invalid Request", status_code=400)

# =====================================================
# AGENT 2 — INVESTIGATOR (Renamed for Dashboard Compatibility)
# =====================================================
@app.route(route="InvestigatorAgent", auth_level=func.AuthLevel.ANONYMOUS)
def InvestigatorAgent(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("🧠 Investigator Agent Triggered")
    
    try:
        body = req.get_json()
        velocity = body.get("velocity", 0)
        spread = body.get("spread", 0)

        norm_velocity = min(velocity / 100, 1.0)
        norm_spread = min(spread / 20, 1.0)
        
        # Weighted Risk
        behavior_risk = round((0.6 * norm_velocity) + (0.4 * norm_spread), 2)
        
        return func.HttpResponse(
            json.dumps({
                "agent": "Investigator",
                "behavior_analysis": {
                    "total_risk_score": behavior_risk,
                    "velocity": norm_velocity
                }
            }, indent=2),
            mimetype="application/json"
        )
    except:
         return func.HttpResponse("Error", status_code=400)

# =====================================================
# AGENT 3 — THE GOVERNOR (Policy Enforcer)
# =====================================================
@app.route(route="GovernorAgent", auth_level=func.AuthLevel.ANONYMOUS)
def GovernorAgent(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("⚖️ Governor Agent Triggered")
    
    try:
        body = req.get_json()
        intent_data = body.get("intent_data", {})
        behavior_score = body.get("behavior_score", 0.0)

        # Extract Intelligence
        intent = intent_data.get("intent", "unknown")
        impact = intent_data.get("impact", "unknown")
        intent_conf = float(intent_data.get("confidence", 0.0))

        # --- 1. THE FUSION MATH (Fixes the "High Velocity" Bug) ---
        # Old Math: max(intent, behavior) -> This ignored velocity if intent was high.
        # New Math: Weighted Sum. If velocity rises, risk RISES.
        # Formula: 40% Intent + 40% Behavior + 20% Base Risk
        
        base_risk = (0.4 * intent_conf) + (0.4 * behavior_score) + 0.1
        final_risk = min(base_risk, 1.0) # Cap at 1.0
        
        policy_violation = "None"
        decision = "ALLOW"

        # --- 2. THE HARD RULES (Overrides) ---

        # Rule A: Credential Theft (Identity Protection)
        # FIX: We now check Intent OR Impact. If either says "Credentials", we block.
        if impact == "credential_theft" or intent == "credential_access":
            final_risk = 1.0
            decision = "BLOCK"
            policy_violation = "Zero-Trust: Credential Access Attempt"

        # Rule B: Destructive Actions (Data Integrity)
        elif impact == "destructive" or intent == "data_exfiltration":
            # If they are moving fast (High Velocity) doing destructive things -> BLOCK
            if behavior_score > 0.5: 
                final_risk = 1.0
                decision = "BLOCK"
                policy_violation = "Critical: High-Velocity Data Destruction"
            else:
                final_risk = max(final_risk, 0.8)
                decision = "VERIFY_THEN_ALLOW"
                policy_violation = "Suspicious Destructive Command"

        # Rule C: Sensitive Reads (Privacy)
        # This was the specific bug case. Now, high velocity pushes this score up.
        elif impact == "sensitive_read":
            # If behavior is high (>0.6), a "read" becomes a "scrape" -> SUSPICIOUS
            if behavior_score > 0.6:
                final_risk = max(final_risk, 0.75)
                decision = "VERIFY_THEN_ALLOW" 
                policy_violation = "Abnormal Data Access Pattern (Scraping)"
            else:
                # Low velocity read is safer
                decision = "ALLOW"

        # Rule D: Jailbreaks
        elif intent == "privilege_escalation":
            final_risk = 1.0
            decision = "BLOCK"
            policy_violation = "AI Safety: Jailbreak Detected"

        return func.HttpResponse(
            json.dumps({
                "agent": "Governor",
                "decision": decision,
                "final_risk_score": round(final_risk, 2),
                "policy_violation": policy_violation,
                "impact": impact
            }, indent=2),
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(str(e))
        return func.HttpResponse("Error", status_code=400)