import json
import logging
from datetime import datetime

try:
    from waf_engine import (
        KillerAgent,
        BrainApproval,
        MaliciousSignature,
        AzureFrontDoorBackend,
    )
    HAS_REAL_ENGINE = True
except ImportError:
    HAS_REAL_ENGINE = False


class EnforcementService:
    def __init__(self, mode="AUDIT"):
        self.mode = mode
        self.audit_file = "defense_audit.json"

        if HAS_REAL_ENGINE:
            self.backend = AzureFrontDoorBackend(
                subscription_id="DEMO-SUB-123",
                resource_group="DefenseLab-RG",
                front_door_name="DefenseLab-FD",
                policy_name="Global-WAF-Policy",
            )
            self.real_agent = KillerAgent(self.backend)
        else:
            self.real_agent = None

    def execute_containment(self, incident_id, risk_score, context):
        timestamp = datetime.now().isoformat()

        action = "LOG_ONLY"
        if self.mode == "ACTIVE_AZURE" and risk_score >= 0.9:
            action = "ACTIVE_BLOCK"

        audit_entry = {
            "id": incident_id,
            "timestamp": timestamp,
            "risk_score": risk_score,
            "mode": self.mode,
            "decision": action,
            "context": context,
        }

        if action == "ACTIVE_BLOCK" and HAS_REAL_ENGINE:
            try:
                approval = BrainApproval(
                    confidence=risk_score * 100,
                    incident_id=incident_id,
                    level="L3",
                    action="containment",
                    metadata={"source": "AI_Swarm_Governor"},
                    timestamp=timestamp,
                )

                signature = MaliciousSignature(
                    incident_id=incident_id,
                    signature_type="AI_Heuristic_Block",
                    patterns=[str(context)],
                    behavior_fingerprint={"risk": risk_score},
                    confidence=risk_score * 100,
                    timestamp=timestamp,
                )

                result = self.real_agent.block(approval, signature)
                audit_entry["enforcement_details"] = result.to_dict()

            except Exception as e:
                logging.error(e)
                audit_entry["status"] = "ERROR"
                audit_entry["error"] = str(e)

        self._write_audit(audit_entry)
        return audit_entry

    def _write_audit(self, entry):
        with open(self.audit_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
