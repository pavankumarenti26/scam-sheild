def calculate_risk(
    url_risk=0,
    scam_language_risk=0,
    voice_risk=0,
    caller_risk=0,
    ai_voice_risk=0
):
    """
    ScamShield Explainable Risk Engine.

    Combines multiple risk signals into
    one final score from 0 to 100.
    """

    # --------------------------------------------------
    # Store available signals
    # --------------------------------------------------

    signals = []

    if url_risk > 0:
        signals.append(("url", url_risk))

    if scam_language_risk > 0:
        signals.append(
            ("scam_language", scam_language_risk)
        )

    if voice_risk > 0:
        signals.append(
            ("voice", voice_risk)
        )

    if caller_risk > 0:
        signals.append(
            ("caller", caller_risk)
        )

    if ai_voice_risk > 0:
        signals.append(
            ("ai_voice", ai_voice_risk)
        )

    # --------------------------------------------------
    # No risk signals
    # --------------------------------------------------

    if not signals:

        return {
            "risk_score": 0,
            "risk_level": "SAFE",
            "recommendation": "No major risk detected"
        }

    # --------------------------------------------------
    # Weights
    # --------------------------------------------------

    weights = {
        "url": 0.35,
        "scam_language": 0.35,
        "voice": 0.20,
        "caller": 0.10,
        "ai_voice": 0.10
    }

    # --------------------------------------------------
    # Calculate weighted score
    # --------------------------------------------------

    weighted_total = 0
    total_weight = 0

    for name, value in signals:

        weight = weights[name]

        weighted_total += value * weight

        total_weight += weight

    base_score = (
        weighted_total / total_weight
    )

    # --------------------------------------------------
    # Critical scam-language boost
    # --------------------------------------------------

    if scam_language_risk >= 80:

        base_score += 15

    # --------------------------------------------------
    # Count high-risk signals
    # --------------------------------------------------

    high_risk_count = 0

    for name, value in signals:

        if value >= 60:

            high_risk_count += 1

    if high_risk_count >= 3:

        base_score += 15

    elif high_risk_count >= 2:

        base_score += 10

    # --------------------------------------------------
    # Count suspicious signals
    # --------------------------------------------------

    suspicious_count = 0

    for name, value in signals:

        if value >= 30:

            suspicious_count += 1

    if suspicious_count >= 3:

        base_score += 5

    # --------------------------------------------------
    # Critical protection
    # --------------------------------------------------

    if (
        scam_language_risk >= 80
        and (
            url_risk >= 30
            or caller_risk >= 30
            or ai_voice_risk >= 30
        )
    ):

        base_score = max(
            base_score,
            80
        )

    # --------------------------------------------------
    # Limit score
    # --------------------------------------------------

    score = round(base_score)

    score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------
    # Risk level
    # --------------------------------------------------

    if score >= 80:

        level = "CRITICAL"

        recommendation = (
            "DO NOT SEND MONEY"
        )

    elif score >= 60:

        level = "HIGH"

        recommendation = (
            "VERIFY BEFORE PAYING"
        )

    elif score >= 30:

        level = "CAUTION"

        recommendation = (
            "BE CAREFUL"
        )

    else:

        level = "SAFE"

        recommendation = (
            "No major risk detected"
        )

    # --------------------------------------------------
    # Final result
    # --------------------------------------------------

    return {
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation
    }