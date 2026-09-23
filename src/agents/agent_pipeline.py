from .gnn_tool import get_gnn_threat
from .triage_agent import TriageAgent
from .planning_agent import PlanningAgent
from .recommendation_agent import RecommendationAgent

def run_agent_pipeline(source_node: str):
    """
    Complete Agentic AI pipeline.

    REAL GNN
        ↓
    GNN Tool
        ↓
    Triage Agent
        ↓
    Planning Agent
        ↓
    Recommendation Agent
    """

    print("\n========================================")
    print("      GRAPH-AWARE AGENTIC SOC")
    print("========================================")

    # --------------------------------------------------
    # STEP 1: Get REAL GNN threat intelligence
    # --------------------------------------------------

    print("\n[1/4] Running GNN threat prediction...")

    threat_data = get_gnn_threat(source_node)

    # The GNN does not currently provide attack type.
    # Therefore we use a descriptive label rather than
    # inventing an attack classification.

    threat_data["attack_type"] = "GNN Detected Threat"

    print("Source Node :", threat_data["source_node"])
    print("Risk Score  :", threat_data["risk_score"])
    print("Blast Radius:", threat_data["blast_radius"])
    print(
        "Affected Nodes:",
        len(threat_data["affected_nodes"])
    )

    # --------------------------------------------------
    # STEP 2: Triage Agent
    # --------------------------------------------------

    print("\n[2/4] Running Triage Agent...")

    triage_agent = TriageAgent()

    triage_result = triage_agent.analyze(
        threat_data
    )

    print("Severity :", triage_result["severity"])
    print("Priority :", triage_result["priority"])

    # --------------------------------------------------
    # STEP 3: Planning Agent
    # --------------------------------------------------

    print("\n[3/4] Running Planning Agent...")

    planning_agent = PlanningAgent()

    planning_result = planning_agent.create_plan(
        triage_result,
        threat_data
    )

    print(
        "Objective:",
        planning_result["objective"]
    )

    print("Recommended Actions:")

    for action in planning_result[
        "recommended_actions"
    ]:
        print("  -", action)

    # --------------------------------------------------
    # STEP 4: Recommendation Agent
    # --------------------------------------------------

    print("\n[4/4] Running Recommendation Agent...")

    recommendation_agent = RecommendationAgent()

    recommendation_result = (
        recommendation_agent.generate_recommendation(
            planning_result,
            threat_data
        )
    )

    print(
        "Recommended Action:",
        recommendation_result[
            "recommended_action"
        ]
    )

    print(
        "Confidence:",
        recommendation_result["confidence"]
    )

    print(
        "Admin Approval:",
        recommendation_result[
            "requires_admin_approval"
        ]
    )

    # --------------------------------------------------
    # Final structured result
    # --------------------------------------------------

    return {
        "incident": threat_data,
        "triage": triage_result,
        "plan": planning_result,
        "recommendation": recommendation_result
    }


if __name__ == "__main__":

    # REAL GNN source node
    source_node = "192.168.10.5"

    result = run_agent_pipeline(
        source_node
    )

    print("\n========================================")
    print("          FINAL SOC DECISION")
    print("========================================")

    recommendation = result[
        "recommendation"
    ]

    print(
        "\nAction:",
        recommendation["recommended_action"]
    )

    print(
        "Reason:",
        recommendation["reason"]
    )

    print(
        "Expected Effect:",
        recommendation["expected_effect"]
    )

    print(
        "Confidence:",
        recommendation["confidence"]
    )

    print(
        "Requires Admin Approval:",
        recommendation[
            "requires_admin_approval"
        ]
    )