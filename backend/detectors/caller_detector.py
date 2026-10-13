import re


def analyze_caller(number: str):
    """
    Check basic phone-number formatting for ScamShield.

    A phone number alone cannot prove that a caller is a scammer.
    Use this result as a limited signal, not as proof of fraud.
    """

    if not isinstance(number, str) or not number.strip():
        return {
            "caller_risk": 0,
            "risk_level": "SAFE",
            "is_suspicious": False,
            "reasons": ["No phone number provided"]
        }

    original = number.strip()
    cleaned = re.sub(r"[\s()-]", "", original)

    if not re.fullmatch(r"\+?\d+", cleaned):
        return {
            "caller_risk": 0,
            "risk_level": "SAFE",
            "is_suspicious": False,
            "reasons": ["Invalid phone number formatting; risk cannot be determined"]
        }

    digits = cleaned.lstrip("+")

    # Reject impossible international lengths as a format warning.
    if cleaned.startswith("+"):
        valid_length = 8 <= len(digits) <= 15
    else:
        # Accept a 10-digit number without a country code.
        valid_length = len(digits) == 10

    risk = 0
    reasons = []

    if not valid_length:
        risk += 15
        reasons.append("Phone number has an unusual length")

    # A repeated-digit pattern is only a weak signal.
    if len(digits) >= 8 and len(set(digits)) <= 2:
        risk += 10
        reasons.append("Phone number contains highly repetitive digits")

    risk = min(risk, 30)
    level = "CAUTION" if risk >= 20 else "SAFE"

    if not reasons:
        reasons.append("No major number-format risk detected")

    return {
        "caller_risk": risk,
        "risk_level": level,
        "is_suspicious": risk >= 20,
        "reasons": reasons
    }
