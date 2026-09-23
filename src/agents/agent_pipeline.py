from triage_agent import TriageAgent
from planning_agent import PlanningAgent
from recommendation_agent import RecommendationAgent


def run_agent_pipeline(threat_data):
    """
    Run the complete agent pipeline:

    Threat Data
        ↓
    Triage Agent
        ↓
    Planning Agent
        ↓
    Recommendation Agent
    """

    triage_agent = TriageAgent()
    planning_agent = PlanningAgent()
    recommendation_agent = RecommendationAgent()

    # Step 1: Triage
    triage_result = triage_agent.analyze(threat_data)

    # Step 2: Planning
    planning_result = planning_agent.create_plan(triage_result)

    # Step 3: Recommendation
    recommendation_result = recommendation_agent.generate_recommendation(
        planning_result,
        threat_data
    )

    return {
        "triage": triage_result,
        "plan": planning_result,
        "recommendation": recommendation_result
    }


if __name__ == "__main__":

    # Temporary test data.
    # We will replace this with the REAL GNN output next.
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

    result = run_agent_pipeline(threat_data)

    print("\n========== AGENT PIPELINE ==========")

    print("\n--- TRIAGE ---")
    for key, value in result["triage"].items():
        print(f"{key}: {value}")

    print("\n--- PLANNING ---")
    for key, value in result["plan"].items():
        if key == "recommended_actions":
            print(f"{key}:")
            for action in value:
                print(f"  - {action}")
        else:
            print(f"{key}: {value}")

    print("\n--- RECOMMENDATION ---")
    for key, value in result["recommendation"].items():
        print(f"{key}: {value}")