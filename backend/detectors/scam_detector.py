def analyze_text(text: str):
    text_lower = text.lower()

    score = 0
    reasons = []

    # Money-related words
    money_words = [
        "send money",
        "transfer money",
        "pay",
        "payment",
        "₹",
        "rupees",
        "upi",
        "bank transfer"
    ]

    if any(word in text_lower for word in money_words):
        score += 25
        reasons.append("Money transfer request")

    # Urgency
    urgency_words = [
        "immediately",
        "urgent",
        "right now",
        "quickly",
        "as soon as possible",
        "hurry",
        "emergency"
    ]

    if any(word in text_lower for word in urgency_words):
        score += 20
        reasons.append("Urgency or emergency pressure")

    # Impersonation
    impersonation_phrases = [
        "i'm your son",
        "i am your son",
        "i'm your brother",
        "i am your brother",
        "i'm your daughter",
        "i am your daughter",
        "this is your friend",
        "i'm your dad",
        "i am your dad",
        "this is me"
    ]

    if any(phrase in text_lower for phrase in impersonation_phrases):
        score += 20
        reasons.append("Possible impersonation")

    # Secrecy
    secrecy_words = [
        "don't tell anyone",
        "do not tell anyone",
        "keep this secret",
        "don't tell mom",
        "don't tell dad",
        "keep it secret"
    ]

    if any(phrase in text_lower for phrase in secrecy_words):
        score += 15
        reasons.append("Request for secrecy")

    # OTP
    otp_words = [
        "otp",
        "one time password",
        "verification code"
    ]

    if any(word in text_lower for word in otp_words):
        score += 25
        reasons.append("OTP or verification code request")

    # Account threats
    threat_words = [
        "account will be blocked",
        "account will be closed",
        "account suspended",
        "account blocked",
        "police case",
        "legal action"
    ]

    if any(phrase in text_lower for phrase in threat_words):
        score += 20
        reasons.append("Threat or account pressure")

    # Limit score to 100
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

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "is_scam": score >= 60,
        "reasons": reasons
    }