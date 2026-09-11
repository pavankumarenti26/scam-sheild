from urllib.parse import urlparse
import ipaddress


def analyze_url(url: str):
    reasons = []
    score = 0

    # 1. Check HTTPS
    if not url.lower().startswith("https://"):
        score += 10
        reasons.append("Non-HTTPS URL")

    # 2. Parse the URL
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {
                "risk_score": 100,
                "risk_level": "CRITICAL",
                "is_phishing": True,
                "reasons": ["Invalid URL"]
            }

    except Exception:
        return {
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "is_phishing": True,
            "reasons": ["Invalid URL"]
        }

    # 3. Check whether the URL uses an IP address
    try:
        ipaddress.ip_address(hostname)
        score += 20
        reasons.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    # 4. Check suspicious words
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "bank",
        "payment",
        "upi",
        "password",
        "otp"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            found_keywords.append(keyword)

    if found_keywords:
        score += min(20, len(found_keywords) * 5)
        reasons.append(
            "Suspicious keywords: " + ", ".join(found_keywords)
        )

    # 4. Check for possible brand impersonation
    trusted_brands = [
        "sbi",
        "hdfc",
        "icici",
        "axisbank",
        "paytm",
        "phonepe",
        "paypal",
        "google",
        "microsoft",
        "amazon"
    ]

    hostname_lower = hostname.lower()

    for brand in trusted_brands:
        if brand in hostname_lower:
            score += 15
            reasons.append(f"Possible {brand.upper()} brand impersonation")
            break
    # 5. Check for too many subdomains
    if hostname.count(".") >= 3:
        score += 15
        reasons.append("Unusually complex domain structure")

    # 6. Check suspicious domain extensions
    suspicious_extensions = [
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf"
    ]

    if any(hostname.lower().endswith(ext) for ext in suspicious_extensions):
        score += 15
        reasons.append("Suspicious domain extension")

    # 7. Keep score between 0 and 100
    score = min(score, 100)

    # 8. Decide risk level
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
        "is_phishing": score >= 60,
        "reasons": reasons
    }