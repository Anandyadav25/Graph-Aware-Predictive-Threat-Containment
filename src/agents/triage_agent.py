class TriageAgent:
    """
    Classifies a detected network threat based on its risk score
    and blast radius.
    """

    def __init__(self):
        self.high_risk_threshold = 0.75
        self.medium_risk_threshold = 0.40

    def analyze(self, threat_data):
        risk_score = threat_data.get("risk_score", 0)
        blast_radius = threat_data.get("blast_radius", 0)
        attack_type = threat_data.get("attack_type", "Unknown")

        # Determine severity
        if risk_score >= self.high_risk_threshold or blast_radius >= 4:
            severity = "HIGH"
        elif risk_score >= self.medium_risk_threshold or blast_radius >= 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine priority
        if severity == "HIGH":
            priority = "IMMEDIATE"
        elif severity == "MEDIUM":
            priority = "HIGH"
        else:
            priority = "NORMAL"

        return {
            "attack_type": attack_type,
            "risk_score": risk_score,
            "blast_radius": blast_radius,
            "severity": severity,
            "priority": priority,
            "status": "THREAT IDENTIFIED"
        }


if __name__ == "__main__":

    # Temporary test data.
    # Later this will come from Member 2's GNN.
    test_threat = {
        "source_node": "Web_Server",
        "attack_type": "Web Attack",
        "risk_score": 0.91,
        "affected_nodes": [
            "App_Server",
            "Database",
            "Finance_PC"
        ],
        "blast_radius": 3
    }

    agent = TriageAgent()

    result = agent.analyze(test_threat)

    print("\n--- THREAT TRIAGE RESULT ---")
    for key, value in result.items():
        print(f"{key}: {value}")