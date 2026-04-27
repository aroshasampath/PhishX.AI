def calculate_risk(score):
    score = min(score, 100)

    if score >= 71:
        risk = "High"
    elif score >= 31:
        risk = "Medium"
    else:
        risk = "Low"

    return risk, score
