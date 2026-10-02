from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from urllib.parse import urlparse
import re
from database import init_database, save_analysis, get_analyses


app = FastAPI(
    title="Phishing Email Detection & Awareness Dashboard",
    description="Defensive educational phishing email analysis API",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
init_database()


# -----------------------------
# Request format
# -----------------------------

class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    urls: List[str] = []
    attachments: List[str] = []


# -----------------------------
# Helper functions
# -----------------------------

def analyze_sender(sender: str):
    findings = []
    score = 0

    sender_lower = sender.lower()

    suspicious_domains = [
        ".invalid",
        ".test",
        "secure-login",
        "account-alert",
        "verify-account"
    ]

    if any(domain in sender_lower for domain in suspicious_domains):
        score += 20
        findings.append({
            "type": "Sender",
            "severity": "High",
            "message": "Sender address contains a suspicious or demonstration domain pattern."
        })

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender):
        score += 15
        findings.append({
            "type": "Sender",
            "severity": "Medium",
            "message": "Sender address format appears unusual."
        })

    return score, findings


def analyze_content(subject: str, body: str):
    findings = []
    score = 0

    text = f"{subject} {body}".lower()

    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "verify",
        "suspended",
        "expire",
        "security alert",
        "confirm your account"
    ]

    credential_words = [
        "password",
        "login",
        "username",
        "credential",
        "account information",
        "verify your account"
    ]

    found_urgent = [word for word in urgent_words if word in text]
    found_credentials = [
        word for word in credential_words if word in text
    ]

    if found_urgent:
        score += min(25, len(found_urgent) * 5)
        findings.append({
            "type": "Content",
            "severity": "High",
            "message": "Urgency or pressure language detected: "
                       + ", ".join(found_urgent)
        })

    if found_credentials:
        score += min(25, len(found_credentials) * 5)
        findings.append({
            "type": "Content",
            "severity": "High",
            "message": "Possible credential or account-information request detected."
        })

    return score, findings


def analyze_url(url: str):
    findings = []
    score = 0

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if parsed.scheme.lower() != "https":
            score += 15
            findings.append({
                "type": "URL",
                "severity": "Medium",
                "message": "URL does not use HTTPS."
            })

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            score += 20
            findings.append({
                "type": "URL",
                "severity": "High",
                "message": "URL uses a raw IP address instead of a normal domain."
            })

        suspicious_terms = [
            "verify",
            "login",
            "account",
            "secure",
            "update",
            "password"
        ]

        found_terms = [
            term for term in suspicious_terms
            if term in url.lower()
        ]

        if found_terms:
            score += min(20, len(found_terms) * 5)
            findings.append({
                "type": "URL",
                "severity": "Medium",
                "message": "URL contains account or verification-related terms."
            })

    except Exception:
        score += 10
        findings.append({
            "type": "URL",
            "severity": "Medium",
            "message": "URL could not be parsed normally."
        })

    return score, findings


def analyze_attachment(filename: str):
    findings = []
    score = 0

    dangerous_extensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".ps1"
    ]

    filename_lower = filename.lower()

    if any(filename_lower.endswith(ext) for ext in dangerous_extensions):
        score += 25
        findings.append({
            "type": "Attachment",
            "severity": "High",
            "message": "Attachment uses a potentially risky executable/script extension."
        })

    return score, findings


# -----------------------------
# Risk engine
# -----------------------------

def classify_risk(score: int):
    score = min(100, max(0, score))

    if score >= 70:
        return "Likely Phishing", "High"
    elif score >= 40:
        return "Suspicious", "Medium"
    else:
        return "Likely Legitimate", "Low"


# -----------------------------
# Main analysis endpoint
# -----------------------------

@app.post("/analyze")
def analyze_email(email: EmailRequest):

    total_score = 0
    findings = []

    sender_score, sender_findings = analyze_sender(email.sender)
    total_score += sender_score
    findings.extend(sender_findings)

    content_score, content_findings = analyze_content(
        email.subject,
        email.body
    )
    total_score += content_score
    findings.extend(content_findings)

    for url in email.urls:
        url_score, url_findings = analyze_url(url)
        total_score += url_score
        findings.extend(url_findings)

    for attachment in email.attachments:
        attachment_score, attachment_findings = analyze_attachment(
            attachment
        )
        total_score += attachment_score
        findings.extend(attachment_findings)

    total_score = min(total_score, 100)

    classification, risk_level = classify_risk(total_score)
    save_analysis(
    email.sender,
    email.subject,
    email.body,
    total_score,
    classification,
    risk_level
)

    recommendations = []

    if total_score >= 70:
        recommendations = [
            "Do not click links in the email.",
            "Do not open unexpected attachments.",
            "Do not provide passwords or sensitive information.",
            "Verify the sender through a trusted communication channel.",
            "Report the message as suspicious or phishing."
        ]
    elif total_score >= 40:
        recommendations = [
            "Verify the sender independently.",
            "Inspect links before clicking.",
            "Avoid providing credentials.",
            "Treat unexpected attachments with caution."
        ]
    else:
        recommendations = [
            "No major phishing indicators were detected.",
            "Continue following normal email security practices."
        ]

    return {
        "risk_score": total_score,
        "classification": classification,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations,
        "analysis_summary": {
            "sender_analyzed": True,
            "content_analyzed": True,
            "urls_analyzed": len(email.urls),
            "attachments_analyzed": len(email.attachments)
        }
    }


# -----------------------------
# Health check
# -----------------------------

@app.get("/")
def root():
    return {
        "message": "Phishing Email Detection API is running",
        "status": "healthy"
    }
@app.get("/history")
def history():
    return {
        "analyses": get_analyses()
    }

@app.get("/stats")
def stats():
    analyses = get_analyses()

    total = len(analyses)
    phishing = sum(
        1 for item in analyses
        if item["classification"] == "Likely Phishing"
    )
    suspicious = sum(
        1 for item in analyses
        if item["classification"] == "Suspicious"
    )
    legitimate = sum(
        1 for item in analyses
        if item["classification"] == "Likely Legitimate"
    )

    return {
        "total": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "legitimate": legitimate
    }