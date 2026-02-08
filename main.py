from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Threat Advisor & Risk Assessment API")

# ===============================
# Input Schemas
# ===============================

class ThreatAdvisorInput(BaseModel):
    sybil_detected: bool
    sensor_spoofing_detected: bool
    confidence: Optional[float] = None

class ThreatEducationInput(BaseModel):
    question: str


# ===============================
# Health Check
# ===============================

@app.get("/")
def health():
    return {"status": "Threat Advisor running"}


# ===============================
# Threat Advisor (Risk Assessment)
# ===============================

@app.post("/threat-advisor")
def threat_advisor(data: ThreatAdvisorInput):
    risk_level = "Low"
    detailed_explanation = []
    potential_impact = []
    recommended_actions = []

    if data.sybil_detected:
        risk_level = "High"
        detailed_explanation.append(
            "Multiple vehicle identities are exhibiting highly similar communication and "
            "movement patterns. This behavior is characteristic of a Sybil attack, where "
            "a single malicious entity controls multiple fake identities."
        )
        potential_impact.append(
            "Sybil attacks can manipulate traffic awareness, disrupt cooperative driving "
            "decisions, and reduce trust among autonomous vehicles."
        )
        recommended_actions.append(
            "Isolate suspicious identities, strengthen authentication mechanisms, and "
            "increase monitoring of vehicle-to-vehicle communication."
        )

    if data.sensor_spoofing_detected:
        risk_level = "High"
        detailed_explanation.append(
            "Sensor readings deviate from expected physical behavior, indicating possible "
            "sensor spoofing where false data is injected to mislead vehicle perception systems."
        )
        potential_impact.append(
            "Sensor spoofing can cause incorrect obstacle detection, unsafe navigation "
            "decisions, and increased collision risk."
        )
        recommended_actions.append(
            "Enable sensor fusion, rely on redundant sensors, and restrict autonomous control "
            "until sensor data integrity is verified."
        )

    if not detailed_explanation:
        detailed_explanation.append(
            "No abnormal communication patterns or sensor anomalies have been detected. "
            "The system is operating within normal safety thresholds."
        )
        potential_impact.append(
            "No immediate cybersecurity or safety threats are present."
        )
        recommended_actions.append(
            "Continue routine monitoring and maintain standard security policies."
        )

    return {
        "risk_level": risk_level,
        "detailed_explanation": detailed_explanation,
        "potential_impact": potential_impact,
        "recommended_actions": recommended_actions
    }


# ===============================
# Threat Advisor (Education / Q&A)
# ===============================

@app.post("/threat-advisor/education")
def threat_advisor_education(data: ThreatEducationInput):
    q = data.question.lower()

    if "sybil" in q and "type" in q:
        return {
            "answer": (
                "A Sybil attack occurs when a single malicious entity creates or controls "
                "multiple fake identities within a network. Common types of Sybil attacks include:\n\n"
                "1. Direct Sybil Attack – Fake identities communicate directly with honest nodes.\n"
                "2. Indirect Sybil Attack – Fake identities communicate via compromised nodes.\n"
                "3. Insider Sybil Attack – A legitimate node creates additional fake identities.\n"
                "4. Outsider Sybil Attack – All Sybil identities are created externally.\n"
                "5. Simultaneous Sybil Attack – Multiple Sybil identities attack the network together."
            )
        }

    if "what is sybil" in q or "sybil attack" in q:
        return {
            "answer": (
                "A Sybil attack is a cybersecurity threat in which one attacker creates "
                "multiple fake identities to gain disproportionate influence over a network. "
                "In autonomous vehicle systems, Sybil attacks can manipulate traffic data, "
                "disrupt coordination, and compromise safety."
            )
        }

    if "sensor spoofing" in q:
        return {
            "answer": (
                "Sensor spoofing is an attack where false or manipulated sensor data is injected "
                "to mislead vehicle perception systems, potentially causing unsafe driving decisions."
            )
        }

    return {
        "answer": (
            "This Threat Advisor provides educational explanations of cybersecurity threats "
            "and performs real-time risk assessment based on dashboard detection results."
        )
    }
