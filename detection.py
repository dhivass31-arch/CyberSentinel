# ==========================================
# CYBERSENTINEL
# SECURITY THREAT DETECTION ENGINE
# ==========================================


def detect_threat(
    event_name,
    source_ip,
    recent_failed_attempts=0
):
    event = event_name.lower().strip()
    ip = source_ip.strip()

    # ==========================================
    # RULE 1 — BRUTE FORCE DETECTION
    # ==========================================

    if (
        recent_failed_attempts >= 5
        and (
            "failed login" in event
            or "login attempt" in event
            or "authentication failure" in event
            or "authentication failed" in event
        )
    ):
        return {
            "severity": "High",
            "reason": (
                f"Possible brute-force attack detected: "
                f"{recent_failed_attempts} failed login attempts "
                f"from {source_ip}"
            ),
            "rule": "BRUTE_FORCE_DETECTION"
        }

    # ==========================================
    # RULE 2 — SUSPICIOUS IP DETECTION
    # ==========================================

    suspicious_test_ips = [
        "203.0.113.10",
        "203.0.113.50",
        "198.51.100.20",
        "198.51.100.50",
        "192.0.2.100"
    ]

    if ip in suspicious_test_ips:
        return {
            "severity": "High",
            "reason": (
                f"Security event received from "
                f"suspicious source IP {source_ip}"
            ),
            "rule": "SUSPICIOUS_IP_DETECTION"
        }

    # ==========================================
    # RULE 3 — PORT SCAN DETECTION
    # ==========================================

    port_scan_keywords = [
        "port scan",
        "port scanning",
        "port scan detected",
        "multiple ports",
        "multiple port connections",
        "network scan",
        "tcp scan",
        "udp scan"
    ]

    for keyword in port_scan_keywords:
        if keyword in event:
            return {
                "severity": "High",
                "reason": (
                    f"Potential port scanning activity detected "
                    f"from {source_ip}"
                ),
                "rule": "PORT_SCAN_DETECTION"
            }

    # ==========================================
    # RULE 4 — AUTHENTICATION FAILURE
    # ==========================================

    authentication_keywords = [
        "authentication failure",
        "authentication failed",
        "authentication error",
        "invalid credentials",
        "invalid password",
        "wrong password",
        "login failed",
        "login failure"
    ]

    for keyword in authentication_keywords:
        if keyword in event:

            return {
                "severity": "Medium",
                "reason": (
                    f"Authentication failure detected "
                    f"from {source_ip}"
                ),
                "rule": "AUTHENTICATION_FAILURE_DETECTION"
            }

    # ==========================================
    # RULE 5 — SUSPICIOUS LOGIN
    # ==========================================

    suspicious_login_keywords = [
        "suspicious login",
        "unusual login",
        "unknown login",
        "login from unknown device",
        "login from unusual location",
        "unauthorized login"
    ]

    for keyword in suspicious_login_keywords:
        if keyword in event:

            return {
                "severity": "Medium",
                "reason": (
                    f"Suspicious login activity detected "
                    f"from {source_ip}"
                ),
                "rule": "SUSPICIOUS_LOGIN_DETECTION"
            }

    # ==========================================
    # RULE 6 — OTHER HIGH-RISK EVENTS
    # ==========================================

    high_keywords = [
        "multiple failed login",
        "brute force",
        "brute-force",
        "unauthorized access",
        "malware detected",
        "ransomware",
        "privilege escalation",
        "reverse shell",
        "suspicious network activity",
        "credential attack",
        "account takeover",
        "suspicious ip",
        "malicious ip"
    ]

    for keyword in high_keywords:
        if keyword in event:

            return {
                "severity": "High",
                "reason": (
                    f"High-risk activity detected: "
                    f"{keyword}"
                ),
                "rule": "HIGH_THREAT_RULE"
            }

    # ==========================================
    # RULE 7 — MEDIUM-RISK EVENTS
    # ==========================================

    medium_keywords = [
        "ssh login attempt",
        "failed login",
        "login attempt",
        "suspicious connection",
        "network connection",
        "unknown connection",
        "unknown ip"
    ]

    for keyword in medium_keywords:
        if keyword in event:

            return {
                "severity": "Medium",
                "reason": (
                    f"Suspicious activity detected: "
                    f"{keyword}"
                ),
                "rule": "MEDIUM_THREAT_RULE"
            }

    # ==========================================
    # RULE 8 — LOW-RISK ACTIVITY
    # ==========================================

    return {
        "severity": "Low",
        "reason": "No high-risk pattern detected",
        "rule": "LOW_ACTIVITY_RULE"
    }