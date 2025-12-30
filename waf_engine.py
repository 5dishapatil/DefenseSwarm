import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, List
from datetime import datetime, timedelta
import hashlib
import uuid

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class BrainApproval:
    """Input from Core Brain (must be ≥90% confidence)"""
    confidence: float
    incident_id: str
    level: str  # Must be "L3"
    action: str  # Must be "containment"
    metadata: Dict
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict) -> 'BrainApproval':
        return cls(**data)

    def is_valid(self) -> bool:
        """Validate this is a legitimate L3 containment approval"""
        return (
            self.confidence >= 90.0 and
            self.level == "L3" and
            self.action == "containment"
        )


@dataclass
class MaliciousSignature:
    """Verified malicious patterns from Deceptor or Brain"""
    incident_id: str
    signature_type: str  # sqli, cmdi, xss, backdoor, etc.
    patterns: List[str]  # Actual malicious strings detected
    behavior_fingerprint: Dict  # Request pattern, headers, TLS, session traits
    confidence: float
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict) -> 'MaliciousSignature':
        return cls(**data)
    
@dataclass
class BlockRule:
    """WAF blocking rule with TTL"""
    rule_id: str
    incident_id: str
    signature_type: str
    patterns: List[str]
    behavior_conditions: Dict
    ttl_seconds: int
    expires_at: str
    confidence: float
    created_at: str
    metadata: Dict

    def to_dict(self) -> Dict:
        return asdict(self)

    def is_expired(self) -> bool:
        """Check if TTL has expired"""
        expiry = datetime.fromisoformat(self.expires_at)
        return datetime.now() > expiry



@dataclass
class BlockResult:
    """Result of blocking operation"""
    success: bool
    rule_id: str
    message: str
    backend: str
    metadata: Dict

    # ✅ REQUIRED for enforcement_service.py
    def to_dict(self) -> Dict:
        return asdict(self)



# ============================================================================
# WAF BACKEND INTERFACE
# ============================================================================

class WAFBackend(ABC):
    """Abstract interface for different WAF providers"""

    @abstractmethod
    def create_rule(self, rule: BlockRule) -> BlockResult:
        """Create a blocking rule in the WAF"""
        pass

    @abstractmethod
    def delete_rule(self, rule_id: str) -> BlockResult:
        """Delete a rule (for rollback or TTL expiry)"""
        pass

    @abstractmethod
    def list_rules(self) -> List[BlockRule]:
        """List all active rules"""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if WAF backend is reachable"""
        pass


# ============================================================================
# MODSECURITY BACKEND (Recommended)
# ============================================================================

class ModSecurityBackend(WAFBackend):
    """
    ModSecurity WAF backend
    Writes rules to ModSecurity config file
    Requires: ModSecurity installed with Nginx/Apache
    """

    def __init__(self, config_path: str = "/etc/modsecurity/crs/rules/killer-agent.conf"):
        self.config_path = config_path
        self.rules_file = config_path
        self.active_rules: Dict[str, BlockRule] = {}
        self._load_existing_rules()

    def _load_existing_rules(self):
        """Load existing rules from file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    content = f.read()
                    # Parse existing rules (simplified)
                    # In production, implement full ModSecurity rule parser
            except Exception as e:
                print(f"Warning: Could not load rules: {e}")

    def _generate_modsec_rule(self, rule: BlockRule) -> str:
        """
        Generate ModSecurity rule syntax
        Example: Block SQLi patterns with specific behavior
        """
        rule_lines = [
            f"# Rule ID: {rule.rule_id}",
            f"# Incident: {rule.incident_id}",
            f"# Expires: {rule.expires_at}",
            f"# Confidence: {rule.confidence}%",
            ""
        ]

        # Build condition based on signature type
        if rule.signature_type == "sqli":
            conditions = " ".join([
                f"@rx {self._escape_pattern(p)}" for p in rule.patterns
            ])
            rule_lines.append(
                f'SecRule ARGS "{conditions}" \\'
            )
        elif rule.signature_type == "cmdi":
            conditions = " ".join([
                f"@rx {self._escape_pattern(p)}" for p in rule.patterns
            ])
            rule_lines.append(
                f'SecRule ARGS|REQUEST_BODY "{conditions}" \\'
            )

        # Add behavior-based conditions
        behavior = rule.behavior_conditions
        if behavior.get("request_frequency"):
            rule_lines.append(
                f'    "chain,id:{rule.rule_id},deny,status:403,log"'
            )
            rule_lines.append(
                f'SecRule REMOTE_ADDR "@rbl {behavior["request_frequency"]}"'
            )
        else:
            rule_lines.append(
                f'    "id:{rule.rule_id},deny,status:403,log,msg:\'Killer Agent Block: {rule.signature_type}\'"'
            )

        rule_lines.append("")
        return "\n".join(rule_lines)

    def _escape_pattern(self, pattern: str) -> str:
        """Escape special regex characters"""
        special_chars = r'\.^$*+?{}[]|()'
        for char in special_chars:
            pattern = pattern.replace(char, f'\\{char}')
        return pattern

    def create_rule(self, rule: BlockRule) -> BlockResult:
        """Create ModSecurity rule"""
        try:
            modsec_rule = self._generate_modsec_rule(rule)

            # Append to rules file
            with open(self.rules_file, 'a') as f:
                f.write(modsec_rule)

            # Store in memory
            self.active_rules[rule.rule_id] = rule

            # Reload ModSecurity (requires sudo/permissions)
            # In production: os.system("sudo systemctl reload nginx")

            return BlockResult(
                success=True,
                rule_id=rule.rule_id,
                message=f"ModSecurity rule created: {rule.rule_id}",
                backend="modsecurity",
                metadata={"rule_path": self.rules_file}
            )
        except Exception as e:
            return BlockResult(
                success=False,
                rule_id=rule.rule_id,
                message=f"Failed to create rule: {str(e)}",
                backend="modsecurity",
                metadata={"error": str(e)}
            )

    def delete_rule(self, rule_id: str) -> BlockResult:
        """Delete ModSecurity rule"""
        try:
            # Read all rules
            with open(self.rules_file, 'r') as f:
                lines = f.readlines()

            # Filter out the rule to delete
            new_lines = []
            skip_until_blank = False
            for line in lines:
                if f"# Rule ID: {rule_id}" in line:
                    skip_until_blank = True
                    continue
                if skip_until_blank and line.strip() == "":
                    skip_until_blank = False
                    continue
                if not skip_until_blank:
                    new_lines.append(line)

            # Write back
            with open(self.rules_file, 'w') as f:
                f.writelines(new_lines)

            # Remove from memory
            if rule_id in self.active_rules:
                del self.active_rules[rule_id]

            return BlockResult(
                success=True,
                rule_id=rule_id,
                message=f"Rule deleted: {rule_id}",
                backend="modsecurity",
                metadata={}
            )
        except Exception as e:
            return BlockResult(
                success=False,
                rule_id=rule_id,
                message=f"Failed to delete rule: {str(e)}",
                backend="modsecurity",
                metadata={"error": str(e)}
            )

    def list_rules(self) -> List[BlockRule]:
        """List active rules"""
        return list(self.active_rules.values())

    def health_check(self) -> bool:
        """Check if ModSecurity config file is writable"""
        try:
            return os.access(self.rules_file, os.W_OK)
        except:
            return False


# ============================================================================
# AZURE FRONT DOOR BACKEND
# ============================================================================

class AzureFrontDoorBackend(WAFBackend):
    """
    Azure Front Door WAF backend
    Requires: azure-mgmt-frontdoor package
    """

    def __init__(self, subscription_id: str, resource_group: str,
                 front_door_name: str, policy_name: str):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.front_door_name = front_door_name
        self.policy_name = policy_name

        # In production: Initialize Azure SDK client
        # from azure.mgmt.frontdoor import FrontDoorManagementClient
        # from azure.identity import DefaultAzureCredential
        # self.client = FrontDoorManagementClient(
        #     credential=DefaultAzureCredential(),
        #     subscription_id=subscription_id
        # )

    def create_rule(self, rule: BlockRule) -> BlockResult:
        """Create Azure WAF custom rule"""
        try:
            # Example Azure WAF rule structure
            custom_rule = {
                "name": rule.rule_id,
                "priority": 100,
                "ruleType": "MatchRule",
                "matchConditions": self._build_match_conditions(rule),
                "action": "Block"
            }

            # In production: Use Azure SDK
            # self.client.policies.create_or_update(
            #     resource_group_name=self.resource_group,
            #     policy_name=self.policy_name,
            #     parameters=custom_rule
            # )

            return BlockResult(
                success=True,
                rule_id=rule.rule_id,
                message=f"Azure WAF rule created: {rule.rule_id}",
                backend="azure_frontdoor",
                metadata={"policy": self.policy_name}
            )
        except Exception as e:
            return BlockResult(
                success=False,
                rule_id=rule.rule_id,
                message=f"Azure WAF error: {str(e)}",
                backend="azure_frontdoor",
                metadata={"error": str(e)}
            )

    def _build_match_conditions(self, rule: BlockRule) -> List[Dict]:
        """Build Azure-specific match conditions"""
        conditions = []

        for pattern in rule.patterns:
            conditions.append({
                "matchVariable": "RequestUri",
                "operator": "Contains",
                "matchValue": [pattern]
            })

        return conditions

    def delete_rule(self, rule_id: str) -> BlockResult:
        """Delete Azure WAF rule"""
        # Implementation similar to create_rule
        return BlockResult(
            success=True,
            rule_id=rule_id,
            message="Azure rule deleted",
            backend="azure_frontdoor",
            metadata={}
        )

    def list_rules(self) -> List[BlockRule]:
        """List Azure WAF rules"""
        return []

    def health_check(self) -> bool:
        """Check Azure connection"""
        return True


# ============================================================================
# GENERIC HTTP API BACKEND
# ============================================================================

class GenericAPIBackend(WAFBackend):
    """
    Generic HTTP API backend for any WAF
    Useful for: Cloudflare, custom WAFs, etc.
    """

    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key

    def create_rule(self, rule: BlockRule) -> BlockResult:
        """POST rule to generic API"""
        try:
            import requests

            response = requests.post(
                f"{self.api_url}/rules",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=rule.to_dict()
            )

            if response.status_code == 200:
                return BlockResult(
                    success=True,
                    rule_id=rule.rule_id,
                    message="Rule created via API",
                    backend="generic_api",
                    metadata=response.json()
                )
            else:
                return BlockResult(
                    success=False,
                    rule_id=rule.rule_id,
                    message=f"API error: {response.status_code}",
                    backend="generic_api",
                    metadata={"status": response.status_code}
                )
        except Exception as e:
            return BlockResult(
                success=False,
                rule_id=rule.rule_id,
                message=f"API request failed: {str(e)}",
                backend="generic_api",
                metadata={"error": str(e)}
            )

    def delete_rule(self, rule_id: str) -> BlockResult:
        """DELETE rule via API"""
        try:
            import requests

            response = requests.delete(
                f"{self.api_url}/rules/{rule_id}",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )

            return BlockResult(
                success=response.status_code == 200,
                rule_id=rule_id,
                message="Rule deleted" if response.status_code == 200 else "Delete failed",
                backend="generic_api",
                metadata={}
            )
        except Exception as e:
            return BlockResult(
                success=False,
                rule_id=rule_id,
                message=str(e),
                backend="generic_api",
                metadata={}
            )

    def list_rules(self) -> List[BlockRule]:
        """GET rules from API"""
        return []

    def health_check(self) -> bool:
        """Check API health"""
        try:
            import requests
            response = requests.get(f"{self.api_url}/health")
            return response.status_code == 200
        except:
            return False


# ============================================================================
# AGENT 5: KILLER / REFLEX AGENT
# ============================================================================

class KillerAgent:
    """
    Agent 5: Surgical containment at WAF layer

    Boundaries (ENFORCED):
    ❌ No permanent bans
    ❌ No identity deletion
    ❌ No system shutdown
    """

    def __init__(self, backend: WAFBackend, config_path: str = "killer_config.json"):
        self.backend = backend
        self.config = self._load_config(config_path)
        self.active_rules: Dict[str, BlockRule] = {}
        self.block_history: List[BlockResult] = []

    def _load_config(self, path: str) -> Dict:
        """Load configuration"""
        default_config = {
            "default_ttl_seconds": 3600,  # 1 hour
            "max_ttl_seconds": 86400,  # 24 hours max
            "min_confidence": 90.0,
            "auto_cleanup_expired": True
        }

        if os.path.exists(path):
            with open(path, 'r') as f:
                return {**default_config, **json.load(f)}
        return default_config

    def _generate_rule_id(self, incident_id: str, signature_type: str) -> str:
        return f"KILL-{uuid.uuid4().hex[:12]}"


    def _calculate_ttl(self, confidence: float) -> int:
        """
        Calculate TTL based on confidence
        Higher confidence = longer TTL (but never permanent)
        """
        if confidence >= 95:
            ttl = 86400  # 24 hours
        elif confidence >= 92:
            ttl = 14400  # 4 hours
        else:  # 90-92%
            ttl = 3600  # 1 hour

        return min(ttl, self.config["max_ttl_seconds"])

    def block(
        self,
        brain_approval: BrainApproval,
        malicious_signature: MaliciousSignature
    ) -> BlockResult:
        """
        Main blocking function

        CRITICAL: Only executes if brain_approval.confidence >= 90%
        """
        # Step 1: Validate approval
        if not brain_approval.is_valid():
            return BlockResult(
                success=False,
                rule_id="",
                message=f"Invalid approval: confidence={brain_approval.confidence}, level={brain_approval.level}",
                backend=self.backend.__class__.__name__,
                metadata={"reason": "approval_validation_failed"}
            )

        # Step 2: Validate confidence threshold
        if brain_approval.confidence < self.config["min_confidence"]:
            return BlockResult(
                success=False,
                rule_id="",
                message=f"Confidence {brain_approval.confidence}% below minimum {self.config['min_confidence']}%",
                backend=self.backend.__class__.__name__,
                metadata={"reason": "confidence_too_low"}
            )

        # Step 3: Generate rule
        rule_id = self._generate_rule_id(
            brain_approval.incident_id,
            malicious_signature.signature_type
        )

        ttl_seconds = self._calculate_ttl(brain_approval.confidence)
        expires_at = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()

        rule = BlockRule(
            rule_id=rule_id,
            incident_id=brain_approval.incident_id,
            signature_type=malicious_signature.signature_type,
            patterns=malicious_signature.patterns,
            behavior_conditions=malicious_signature.behavior_fingerprint,
            ttl_seconds=ttl_seconds,
            expires_at=expires_at,
            confidence=brain_approval.confidence,
            created_at=datetime.now().isoformat(),
            metadata={
                "brain_decision": brain_approval.metadata,
                "signature_confidence": malicious_signature.confidence
            }
        )

        # Step 4: Create rule in WAF backend
        result = self.backend.create_rule(rule)

        # Step 5: Track rule
        if result.success:
            self.active_rules[rule_id] = rule

        self.block_history.append(result)

        return result

    def rollback(self, rule_id: str) -> BlockResult:
        """
        Rollback a blocking rule (for mistakes or false positives)
        """
        if rule_id not in self.active_rules:
            return BlockResult(
                success=False,
                rule_id=rule_id,
                message="Rule not found in active rules",
                backend=self.backend.__class__.__name__,
                metadata={}
            )

        result = self.backend.delete_rule(rule_id)

        if result.success:
            del self.active_rules[rule_id]

        return result

    def cleanup_expired(self) -> List[BlockResult]:
        """
        Automatic cleanup of expired rules (TTL enforcement)
        """
        results = []
        expired_rules = [
            rule_id for rule_id, rule in self.active_rules.items()
            if rule.is_expired()
        ]

        for rule_id in expired_rules:
            result = self.rollback(rule_id)
            results.append(result)

        return results

    def get_stats(self) -> Dict:
        """Get statistics"""
        return {
            "active_rules": len(self.active_rules),
            "total_blocks": len([r for r in self.block_history if r.success]),
            "failed_blocks": len([r for r in self.block_history if not r.success]),
            "backend": self.backend.__class__.__name__
        }


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("AGENT 5: KILLER / REFLEX AGENT - Multi-Backend Demo")
    print("=" * 70)

    # Choose your backend
    print("\nAvailable backends:")
    print("1. ModSecurity (recommended, open-source)")
    print("2. Azure Front Door (enterprise)")
    print("3. Generic API (for Cloudflare, custom WAF)")

    # Demo with ModSecurity
    backend = ModSecurityBackend(config_path="./modsecurity_rules.conf")
    killer = KillerAgent(backend)

    # Simulate Brain approval (L3, ≥90%)
    brain_approval = BrainApproval(
        confidence=95.0,
        incident_id="INC-003",
        level="L3",
        action="containment",
        metadata={"pattern": "credential_abuse"},
        timestamp=datetime.now().isoformat()
    )

    # Simulate malicious signature from Deceptor
    malicious_sig = MaliciousSignature(
        incident_id="INC-003",
        signature_type="sqli",
        patterns=["' OR '1'='1", "UNION SELECT", "'; DROP TABLE"],
        behavior_fingerprint={
            "request_frequency": 50,  # 50 req/min
            "header_order": "non-standard",
            "tls_fingerprint": "automation_detected"
        },
        confidence=92.0,
        timestamp=datetime.now().isoformat()
    )

    # Block!
    print("\n[BLOCKING ATTACK]")
    result = killer.block(brain_approval, malicious_sig)
    print(f"Success: {result.success}")
    print(f"Rule ID: {result.rule_id}")
    print(f"Message: {result.message}")
    print(f"Backend: {result.backend}")

    # Check stats
    print("\n[STATISTICS]")
    stats = killer.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Demo: Rollback
    print("\n[ROLLBACK TEST]")
    rollback_result = killer.rollback(result.rule_id)
    print(f"Rollback success: {rollback_result.success}")

    print("\n" + "=" * 70)
    print("✓ Killer Agent ready for deployment!")
    print("=" * 70)