class RecommendationAgent:
    """
    Converts a containment plan into a prioritized,
    explainable recommendation for the administrator.
    """

    def generate_recommendation(self, planning_result, threat_data):
        severity = planning_result.get("severity", "LOW")
        actions = planning_result.get("recommended_actions", [])
        source_node = threat_data.get("source_node", "Unknown")
        risk_score = threat_data.get("risk_score", 0)
        blast_radius = threat_data.get("blast_radius", 0)

        if severity == "HIGH":
            primary_action = actions[0] if actions else "Increase monitoring"
            confidence = "HIGH"

            reason = (
                f"{source_node} has a high risk score of "
                f"{risk_score:.2f} and a predicted blast radius "
                f"of {blast_radius} nodes."
            )

        elif severity == "MEDIUM":
            primary_action = (
                actions[0] if actions else "Increase monitoring"
            )
            confidence = "MEDIUM"

            reason = (
                f"{source_node} presents a moderate threat "
                f"with a predicted blast radius of "
                f"{blast_radius} nodes."
            )

        else:
            primary_action = "Continue monitoring"
            confidence = "LOW"

            reason = (
                f"The current risk level for {source_node} "
                f"does not justify immediate containment."
            )

        return {
            "source_node": source_node,
            "severity": severity,
            "risk_score": risk_score,
            "blast_radius": blast_radius,
            "recommended_action": primary_action,
            "reason": reason,
            "confidence": confidence,
            "requires_admin_approval": True
        }


if __name__ == "__main__":

    # Temporary test data.
    # Later this will come from the real GNN pipeline.
    threat_data = {
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

    planning_result = {
        "attack_type": "Web Attack",
        "severity": "HIGH",
        "blast_radius": 3,
        "recommended_actions": [
            "Isolate affected node",
            "Restrict suspicious network traffic",
            "Increase monitoring on affected nodes",
            "Alert security administrator"
        ],
        "requires_admin_approval": True
    }

    agent = RecommendationAgent()

    recommendation = agent.generate_recommendation(
        planning_result,
        threat_data
    )

    print("\n--- FINAL RECOMMENDATION ---")

    for key, value in recommendation.items():
        print(f"{key}: {value}")