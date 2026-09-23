import json
import re

from .ollama_client import OllamaClient


class RecommendationAgent:
    """
    LLM-powered recommendation agent.

    Converts the triage result and containment plan into
    a prioritized, explainable recommendation for the
    administrator.
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

    def _fallback_recommendation(
        self,
        planning_result,
        threat_data
    ):
        """
        Deterministic safety fallback.
        """

        severity = planning_result.get(
            "severity",
            "LOW"
        )

        actions = planning_result.get(
            "recommended_actions",
            []
        )

        source_node = threat_data.get(
            "source_node",
            "Unknown"
        )

        risk_score = threat_data.get(
            "risk_score",
            0
        )

        blast_radius = threat_data.get(
            "blast_radius",
            0
        )

        if severity == "HIGH":

            primary_action = (
                actions[0]
                if actions
                else "Increase monitoring"
            )

            confidence = "HIGH"

            reason = (
                f"{source_node} has a high risk score of "
                f"{risk_score:.2f} and a predicted blast "
                f"radius of {blast_radius} nodes."
            )

        elif severity == "MEDIUM":

            primary_action = (
                actions[0]
                if actions
                else "Increase monitoring"
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
            "recommended_action": primary_action,
            "reason": reason,
            "expected_effect": (
                "Reduce the probability of further "
                "threat propagation."
            ),
            "confidence": confidence
        }

    def generate_recommendation(
        self,
        planning_result,
        threat_data
    ):
        """
        Generate the final administrator recommendation
        using Qwen3.
        """

        severity = planning_result.get(
            "severity",
            "LOW"
        )

        priority = planning_result.get(
            "priority",
            "NORMAL"
        )

        actions = planning_result.get(
            "recommended_actions",
            []
        )

        planning_reasoning = planning_result.get(
            "reasoning",
            ""
        )

        source_node = threat_data.get(
            "source_node",
            "Unknown"
        )

        risk_score = threat_data.get(
            "risk_score",
            0
        )

        blast_radius = threat_data.get(
            "blast_radius",
            0
        )

        affected_nodes = threat_data.get(
            "affected_nodes",
            []
        )

        system_prompt = """
You are the Recommendation Agent in an
AI-powered Security Operations Center.

Your job is to convert the existing triage decision
and containment plan into ONE clear recommendation
for a security administrator.

You must NOT execute any action.

The administrator must approve the recommendation
before containment can be performed.

Use only the supplied evidence.

Return ONLY valid JSON.

Required format:

{
  "recommended_action": "one primary action",
  "reason": "short technical explanation",
  "expected_effect": "expected security effect",
  "confidence": "HIGH/MEDIUM/LOW"
}

Rules:

- HIGH severity normally requires immediate containment.
- MEDIUM severity normally requires controlled mitigation
  and monitoring.
- LOW severity normally requires monitoring.
- Do not invent network evidence.
- Do not claim that an action has already been executed.
- Do not add markdown.
- Do not add text outside the JSON.
"""

        user_prompt = f"""
Generate the final administrator recommendation.

Source node: {source_node}

GNN risk score: {risk_score}

Blast radius: {blast_radius}

Affected nodes: {affected_nodes}

Triage severity: {severity}

Triage priority: {priority}

Proposed containment actions:
{actions}

Planning reasoning:
{planning_reasoning}

Select the single most appropriate primary action
from the proposed containment actions.

Return only JSON.
"""

        try:

            llm_response = self.llm.generate(
                system_prompt,
                user_prompt
            )

            llm_result = self._extract_json(
                llm_response
            )

        except Exception:

            llm_result = None

        valid_confidence = {
            "HIGH",
            "MEDIUM",
            "LOW"
        }

        if (
            llm_result
            and llm_result.get("recommended_action")
            and llm_result.get("reason")
            and llm_result.get("confidence")
            in valid_confidence
        ):

            recommended_action = (
                llm_result["recommended_action"]
            )

            reason = llm_result["reason"]

            expected_effect = llm_result.get(
                "expected_effect",
                "Reduce further threat propagation."
            )

            confidence = llm_result["confidence"]

        else:

            fallback = self._fallback_recommendation(
                planning_result,
                threat_data
            )

            recommended_action = fallback[
                "recommended_action"
            ]

            reason = fallback["reason"]

            expected_effect = fallback[
                "expected_effect"
            ]

            confidence = fallback["confidence"]

        return {
            "source_node": source_node,
            "severity": severity,
            "risk_score": risk_score,
            "blast_radius": blast_radius,
            "recommended_action": recommended_action,
            "reason": reason,
            "expected_effect": expected_effect,
            "confidence": confidence,
            "requires_admin_approval": True
        }


if __name__ == "__main__":

    # Temporary test data.
    # Later this will come from the real GNN pipeline.

    threat_data = {
        "source_node": "192.168.10.5",
        "attack_type": "GNN Detected Threat",
        "risk_score": 0.9981,
        "affected_nodes": [
            "205.174.165.73",
            "192.168.10.50",
            "172.16.0.1"
        ],
        "blast_radius": 15
    }

    planning_result = {
        "attack_type": "GNN Detected Threat",
        "severity": "HIGH",
        "priority": "IMMEDIATE",
        "blast_radius": 15,
        "recommended_actions": [
            "Isolate the affected source node",
            "Restrict suspicious network traffic",
            "Increase monitoring of affected nodes",
            "Alert the security administrator"
        ],
        "reasoning": (
            "The source node presents a high propagation "
            "risk and requires immediate containment."
        ),
        "requires_admin_approval": True
    }

    agent = RecommendationAgent()

    recommendation = agent.generate_recommendation(
        planning_result,
        threat_data
    )

    print("\n--- LLM FINAL RECOMMENDATION ---")

    for key, value in recommendation.items():
        print(f"{key}: {value}")