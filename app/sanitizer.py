import re
import hashlib
from datetime import datetime

# --- SECURITY CONCEPT ---
# Sanitization is your second line of defense after detection
# Detection says "this is malicious"
# Sanitization decides what to do about it
# 
# In EDR terms:
# Detection = alert fires on suspicious process
# Sanitization = block / quarantine / allow with monitoring
#
# In AI security terms:
# Detection = prompt injection pattern found
# Sanitization = block / clean / quarantine the input

# Phrases we strip out if found — we don't block the whole input
# we surgically remove the malicious instruction parts
# This is like removing a malicious macro from a Word document
# rather than blocking Word entirely
STRIP_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|system)\s+instructions?",
    r"forget\s+(everything|all|your\s+instructions?)",
    r"disregard\s+(all\s+)?(previous|prior|above)?\s*instructions?",
    r"override\s+(your\s+)?(instructions?|rules?|guidelines?)",
    r"your\s+(new|real|actual)\s+instructions?\s+(are|is)[^.]*\.",
    r"you\s+are\s+now\s+(a|an)\s+\w+[^.]*\.",
    r"act\s+as\s+(a|an|if)\s+[^.]*\.",
    r"pretend\s+(you\s+are|to\s+be)\s+[^.]*\.",
    r"from\s+now\s+on\s+you\s+(are|will\s+be)[^.]*\.",
    r"without\s+(any\s+)?(restrictions?|limitations?|filters?)",
    r"bypass\s+(your\s+)?(safety|security|content)?\s*(filter|restriction|rule)",
    r"\[system\]|\[admin\]|\[override\]|\[instruction\]",
    r"(admin|administrator|system)\s+(override|access|mode|command)[^.]*\.",
]

def block_input(user_input, risk_level, findings):
    """
    Completely blocks the input — used for CRITICAL and HIGH risk
    Returns a safe error message instead
    Like isolating an endpoint during a ransomware incident
    """
    log_attempt(user_input, "BLOCKED", risk_level)
    return {
        "action": "BLOCKED",
        "safe_response": "Your input contains patterns that violate our security policy and has been blocked. This attempt has been logged.",
        "original_input": None,  # Never pass original to LLM
        "sanitized_input": None,
        "risk_level": risk_level
    }

def sanitize_input(user_input, risk_level, findings):
    """
    Surgically removes malicious parts and allows the rest through
    Used for MEDIUM and LOW risk — attacker may have mixed
    legitimate question with injection attempt
    Like removing a malicious macro but keeping the document
    """
    cleaned = user_input
    cleaned_lower = cleaned.lower()

    for pattern in STRIP_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE)

    # Clean up extra whitespace left after removal
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()

    log_attempt(user_input, "SANITIZED", risk_level)

    return {
        "action": "SANITIZED",
        "safe_response": None,
        "original_input": user_input,
        "sanitized_input": cleaned if cleaned else None,
        "risk_level": risk_level
    }

def quarantine_input(user_input, risk_level, findings):
    """
    Flags for human review — used when we're not sure
    Like sending a suspicious file to sandbox analysis
    Human analyst reviews before deciding block or allow
    """
    log_attempt(user_input, "QUARANTINED", risk_level)
    return {
        "action": "QUARANTINED",
        "safe_response": "Your input has been flagged for security review. A security analyst will review this shortly.",
        "original_input": user_input,
        "sanitized_input": None,
        "risk_level": risk_level
    }

def log_attempt(user_input, action, risk_level):
    """
    Logs every detection — critical for forensics and audit
    In your Ahold work you maintained logs for compliance
    Same principle here — every blocked attempt is evidence
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Hash the input for privacy — we log THAT it happened, not the full content
    input_hash = hashlib.sha256(user_input.encode()).hexdigest()[:16]

    log_entry = f"[{timestamp}] ACTION={action} | RISK={risk_level} | INPUT_HASH={input_hash}"
    print(f"\n  📋 LOGGED: {log_entry}")

    # In production this would write to a SIEM or security log file
    with open("../data/injection_attempts.log", "a") as f:
        f.write(log_entry + "\n")

def respond_to_injection(user_input, detection_result):
    """
    Main function — decides which response to use based on risk level
    This is your decision engine — like your SOC triage logic
    
    CRITICAL / HIGH  → Block completely
    MEDIUM           → Sanitize and allow cleaned version through
    LOW              → Quarantine for human review
    SAFE             → Allow through normally
    """
    risk = detection_result["risk_level"]
    findings = detection_result["findings"]

    if risk == "SAFE":
        return {
            "action": "ALLOWED",
            "safe_response": None,
            "original_input": user_input,
            "sanitized_input": user_input,
            "risk_level": "SAFE"
        }
    elif risk in ["CRITICAL", "HIGH"]:
        return block_input(user_input, risk, findings)
    elif risk == "MEDIUM":
        return sanitize_input(user_input, risk, findings)
    else:  # LOW
        return quarantine_input(user_input, risk, findings)

def print_sanitization_report(result):
    action_icons = {
        "BLOCKED": "🚫",
        "SANITIZED": "🔧",
        "QUARANTINED": "🔒",
        "ALLOWED": "✅"
    }
    icon = action_icons.get(result["action"], "❓")

    print(f"\n  {icon} Action taken : {result['action']}")
    print(f"  Risk level    : {result['risk_level']}")

    if result["action"] == "SANITIZED":
        print(f"  Cleaned input : {result['sanitized_input']}")
    elif result["action"] == "BLOCKED":
        print(f"  Response sent : {result['safe_response']}")
    elif result["action"] == "QUARANTINED":
        print(f"  Response sent : {result['safe_response']}")
    elif result["action"] == "ALLOWED":
        print(f"  Passed to LLM : {result['sanitized_input']}")