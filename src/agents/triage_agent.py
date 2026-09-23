import json
import re

from .ollama_client import OllamaClient


class TriageAgent:
    """
    LLM-powered threat triage agent.

    Uses Qwen3 through Ollama to analyze GNN threat evidence
    and classify the incident.

    The existing threshold logic is retained as a safety
    fallback and validation layer.
    """

    def __init__(self):
        self.high_risk_threshold = 0.75
        self.medium_risk_threshold = 0.40

        self.llm = OllamaClient()

    def _fallback_classification(self, risk_score, blast_radius):
        """
        Deterministic fallback if the LLM response cannot
        be parsed or produces an invalid classification.
        """

        if (
            risk_score >= self.high_risk_threshold
            or blast_radius >= 4
        ):
            severity = "HIGH"
        elif (
            risk_score >= self.medium_risk_threshold
            or blast_radius >= 2
        ):
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if severity == "HIGH":
            priority = "IMMEDIATE"
        elif severity == "MEDIUM":
            priority = "HIGH"
        else:
            priority = "NORMAL"

        return severity, priority

    def _extract_json(self, response):
        """
        Extract JSON from the LLM response.

        Handles cases where the model accidentally places
        text or markdown around the JSON.
        """

        response = response.strip()

        # Direct JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # JSON inside ```json ... ```
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

        # Find first JSON object
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

    def analyze(self, threat_data):
        """
        Analyze a network threat using GNN evidence
        and the local Qwen3 LLM.
        """

        risk_score = threat_data.get("risk_score", 0)
        blast_radius = threat_data.get("blast_radius", 0)

        attack_type = threat_data.get(
            "attack_type",
            "GNN Detected Threat"
        )

        source_node = threat_data.get(
            "source_node",
            "Unknown"
        )

        affected_nodes = threat_data.get(
            "affected_nodes",
            []
        )

        # Safety classification used as fallback
        fallback_severity, fallback_priority = (
            self._fallback_classification(
                risk_score,
                blast_radius
            )
        )

        system_prompt = """
You are the Triage Agent in an AI-powered Security
Operations Center.

Your job is to analyze network threat evidence produced
by a Graph Neural Network.

Use ONLY the supplied evidence.

Classify the threat into:

severity:
- HIGH
- MEDIUM
- LOW

priority:
- IMMEDIATE
- HIGH
- NORMAL

Return ONLY valid JSON.

Required format:

{
  "severity": "HIGH",
  "priority": "IMMEDIATE",
  "reasoning": "Short technical explanation"
}

Do not use markdown.
Do not add any text outside the JSON.
"""

        user_prompt = f"""
Analyze this network security incident.

Source node: {source_node}
Attack type: {attack_type}
GNN risk score: {risk_score}
Blast radius: {blast_radius}
Affected nodes: {affected_nodes}

Determine the severity and response priority.

Pay particular attention to:
1. The GNN risk score
2. The number of affected nodes
3. The blast radius
4. Potential propagation across the network

Return only JSON.
"""

        try:
            llm_response = self.llm.generate(
                system_prompt,
                user_prompt
            )

            llm_result = self._extract_json(llm_response)

        except Exception as exc:
            llm_result = None
            llm_response = f"LLM error: {exc}"

        # Validate LLM response
        valid_severities = {
            "HIGH",
            "MEDIUM",
            "LOW"
        }

        valid_priorities = {
            "IMMEDIATE",
            "HIGH",
            "NORMAL"
        }

        if (
            llm_result
            and llm_result.get("severity") in valid_severities
            and llm_result.get("priority") in valid_priorities
        ):
            severity = llm_result["severity"]
            priority = llm_result["priority"]
            reasoning = llm_result.get(
                "reasoning",
                "Threat classified by the LLM triage agent."
            )

        else:
            severity = fallback_severity
            priority = fallback_priority
            reasoning = (
                "LLM classification was unavailable or invalid. "
                "Deterministic safety rules were used."
            )

        return {
            "attack_type": attack_type,
            "risk_score": risk_score,
            "blast_radius": blast_radius,
            "severity": severity,
            "priority": priority,
            "status": "THREAT IDENTIFIED",
            "reasoning": reasoning,
            "affected_nodes": affected_nodes,
            "source_node": source_node
        }


if __name__ == "__main__":

    # Test data.
    # Later this will come directly from the GNN tool.

    test_threat = {
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

    agent = TriageAgent()

    result = agent.analyze(test_threat)

    print("\n--- LLM THREAT TRIAGE RESULT ---")

    for key, value in result.items():
        print(f"{key}: {value}")