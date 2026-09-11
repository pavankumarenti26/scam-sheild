import re


def analyze_caller(phone_number: str):

    score = 0
    reasons = []

    # Remove spaces, brackets and hyphens
    cleaned = re.sub(r"[\s\-\(\)]", "", phone_number)

    # 1. Check whether the number contains valid characters
    if not re.match(r"^\+?\d+$", cleaned):

        return {
            "caller_risk": 80,
            "risk_level": "HIGH",
            "is_suspicious": True,
            "reasons": [
                "Invalid phone number format"
            ]
        }

    # 2. Check number length
    digits_only = cleaned.lstrip("+")

    if len(digits_only) < 10:

        score += 30

        reasons.append(
            "Phone number appears unusually short"
        )

    elif len(digits_only) > 15:

        score += 30

        reasons.append(
            "Phone number appears unusually long"
        )

    # 3. Repeated digits
    if len(set(digits_only)) <= 2:

        score += 25

        reasons.append(
            "Phone number contains highly repetitive digits"
        )

    # 4. Suspicious prefixes
    suspicious_prefixes = [
        "+44",
        "+92",
        "+234",
        "+63",
        "+880"
    ]

    for prefix in suspicious_prefixes:

        if cleaned.startswith(prefix):

            score += 15

            reasons.append(
                f"Unusual international calling prefix detected: {prefix}"
            )

            break

    # 5. International number
    if cleaned.startswith("+"):

        score += 5

        reasons.append(
            "International phone number"
        )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Risk level
    if score >= 80:

        risk_level = "CRITICAL"

    elif score >= 60:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "CAUTION"

    else:

        risk_level = "SAFE"

    is_suspicious = score >= 60

    if not reasons:

        reasons.append(
            "No major caller-risk indicators detected"
        )

    return {

        "caller_risk": score,

        "risk_level": risk_level,

        "is_suspicious": is_suspicious,

        "reasons": reasons
    }