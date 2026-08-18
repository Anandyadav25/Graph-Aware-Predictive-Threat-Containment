class PlanningAgent:
    """
    Creates a recommended containment plan based on
    threat severity and blast radius.
    """

    def create_plan(self, triage_result):
        severity = triage_result.get("severity", "LOW")
        blast_radius = triage_result.get("blast_radius", 0)
        attack_type = triage_result.get("attack_type", "Unknown")

        actions = []

        if severity == "HIGH":
            actions = [
                "Isolate affected node",
                "Restrict suspicious network traffic",
                "Increase monitoring on affected nodes",
                "Alert security administrator"
            ]

        elif severity == "MEDIUM":
            actions = [
                "Restrict suspicious network traffic",
                "Increase monitoring on affected nodes",
                "Alert security administrator"
            ]

        else:
            actions = [
                "Continue monitoring",
                "Log the event"
            ]

        return {
            "attack_type": attack_type,
            "severity": severity,
            "blast_radius": blast_radius,
            "recommended_actions": actions,
            "requires_admin_approval": True
        }


if __name__ == "__main__":

    # Temporary input from the Triage Agent.
    # Later this will be connected automatically.
    triage_result = {
        "attack_type": "Web Attack",
        "risk_score": 0.91,
        "blast_radius": 3,
        "severity": "HIGH",
        "priority": "IMMEDIATE",
        "status": "THREAT IDENTIFIED"
    }

    agent = PlanningAgent()

    plan = agent.create_plan(triage_result)

    print("\n--- CONTAINMENT PLAN ---")
    print(f"Attack Type: {plan['attack_type']}")
    print(f"Severity: {plan['severity']}")
    print(f"Blast Radius: {plan['blast_radius']}")

    print("\nRecommended Actions:")
    for i, action in enumerate(plan["recommended_actions"], start=1):
        print(f"{i}. {action}")

    print(
        f"\nAdmin Approval Required: "
        f"{plan['requires_admin_approval']}"
    )