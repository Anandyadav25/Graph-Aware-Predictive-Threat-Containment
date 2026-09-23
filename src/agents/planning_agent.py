import json
import re

from .ollama_client import OllamaClient


class PlanningAgent:
    """
    LLM-powered containment planning agent.

    Uses the triage result and GNN evidence to generate
    a proposed response plan.
    """

    def __init__(self):
        self.llm = OllamaClient()

    def _extract_json(self, response):
        """
        Extract JSON from the LLM response.
        """

        response = response.strip()

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```",
            response,
            re.DOTALL
        )

        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        match = re.search(
            r"\{.*\}",
            response,
            re.DOTALL
        )

        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    def _fallback_plan(self, triage_result):
        """
        Deterministic safety fallback.
        """

        severity = triage_result.get("severity", "LOW")
        blast_radius = triage_result.get("blast_radius", 0)

        if severity == "HIGH":
            actions = [
                "Isolate the affected source node",
                "Restrict suspicious network traffic",
                "Increase monitoring of affected nodes",
                "Alert the security administrator"
            ]

            objective = (
                "Limit threat propagation and prevent further "
                "lateral movement."
            )

        elif severity == "MEDIUM":
            actions = [
                "Restrict suspicious network traffic",
                "Increase monitoring of affected nodes",
                "Alert the security administrator"
            ]

            objective = (
                "Reduce the opportunity for further propagation "
                "while monitoring the incident."
            )

        else:
            actions = [
                "Continue monitoring the source node",
                "Record the event in the security audit log"
            ]

            objective = (
                "Monitor the event and collect additional evidence."
            )

        return {
            "objective": objective,
            "recommended_actions": actions,
            "reasoning": (
                f"Fallback containment plan generated for "
                f"{severity} severity with blast radius "
                f"{blast_radius}."
            )
        }

    def create_plan(self, triage_result, threat_data=None):
        """
        Generate a containment plan using Qwen3.
        """

        if threat_data is None:
            threat_data = {}

        severity = triage_result.get(
            "severity",
            "LOW"
        )

        priority = triage_result.get(
            "priority",
            "NORMAL"
        )

        blast_radius = triage_result.get(
            "blast_radius",
            0
        )

        source_node = threat_data.get(
            "source_node",
            triage_result.get("source_node", "Unknown")
        )

        affected_nodes = threat_data.get(
            "affected_nodes",
            triage_result.get("affected_nodes", [])
        )

        risk_score = threat_data.get(
            "risk_score",
            triage_result.get("risk_score", 0)
        )

        system_prompt = """
You are the Planning Agent in an AI-powered
Security Operations Center.

Your responsibility is to create a safe and practical
containment plan based on threat evidence and triage.

You do NOT execute containment actions.

You only propose actions for administrator approval.

Possible actions include:

- isolate the affected source node
- restrict suspicious traffic
- increase monitoring
- monitor affected nodes
- collect additional evidence
- alert the security administrator

Do not invent technical evidence.

Return ONLY valid JSON.

Required format:

{
  "objective": "short containment objective",
  "recommended_actions": [
    "action 1",
    "action 2"
  ],
  "reasoning": "short technical explanation"
}

Do not use markdown.
Do not add text outside the JSON.
"""

        user_prompt = f"""
Create a containment plan for this incident.

Source node: {source_node}
Risk score: {risk_score}
Blast radius: {blast_radius}
Affected nodes: {affected_nodes}

Triage severity: {severity}
Triage priority: {priority}
Triage reasoning: {triage_result.get("reasoning", "")}

The plan must prioritize limiting propagation,
protecting affected assets, and maintaining
administrator control over containment.

Return only JSON.
"""

        try:
            llm_response = self.llm.generate(
                system_prompt,
                user_prompt
            )

            llm_result = self._extract_json(llm_response)

        except Exception:
            llm_result = None

        if (
            llm_result
            and isinstance(
                llm_result.get("recommended_actions"),
                list
            )
            and len(llm_result["recommended_actions"]) > 0
        ):
            objective = llm_result.get(
                "objective",
                "Limit threat propagation."
            )

            actions = llm_result["recommended_actions"]

            reasoning = llm_result.get(
                "reasoning",
                "Containment plan generated by the LLM."
            )

        else:
            fallback = self._fallback_plan(
                triage_result
            )

            objective = fallback["objective"]
            actions = fallback["recommended_actions"]
            reasoning = fallback["reasoning"]

        return {
            "attack_type": triage_result.get(
                "attack_type",
                "GNN Detected Threat"
            ),
            "severity": severity,
            "priority": priority,
            "blast_radius": blast_radius,
            "objective": objective,
            "recommended_actions": actions,
            "reasoning": reasoning,
            "requires_admin_approval": True
        }


if __name__ == "__main__":

    # Example triage result.
    # Later this will come directly from TriageAgent.

    test_triage = {
        "attack_type": "GNN Detected Threat",
        "risk_score": 0.9981,
        "blast_radius": 15,
        "severity": "HIGH",
        "priority": "IMMEDIATE",
        "reasoning": (
            "The GNN reports an extremely high threat "
            "probability and significant propagation risk."
        ),
        "affected_nodes": [
            "205.174.165.73",
            "192.168.10.50",
            "172.16.0.1"
        ],
        "source_node": "192.168.10.5"
    }

    test_threat = {
        "source_node": "192.168.10.5",
        "risk_score": 0.9981,
        "affected_nodes": [
            "205.174.165.73",
            "192.168.10.50",
            "172.16.0.1"
        ]
    }

    agent = PlanningAgent()

    result = agent.create_plan(
        test_triage,
        test_threat
    )

    print("\n--- LLM CONTAINMENT PLAN ---")

    for key, value in result.items():

        if key == "recommended_actions":

            print(f"{key}:")

            for action in value:
                print(f"  - {action}")

        else:
            print(f"{key}: {value}")