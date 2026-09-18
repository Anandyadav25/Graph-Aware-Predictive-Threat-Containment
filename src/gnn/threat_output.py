"""
Create a clean threat-response payload from blast-radius results.
"""

from pathlib import Path
import json


INPUT_PATH = Path(
    "data/processed/blast_radius_results.json"
)

OUTPUT_PATH = Path(
    "data/processed/threat_response.json"
)


def main():

    print("\n========================================")
    print(" THREAT RESPONSE OUTPUT")
    print("========================================")

    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Input not found: {INPUT_PATH}\n"
            "Run blast_radius.py first."
        )

    with open(
        INPUT_PATH,
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    threats = []

    for threat in data.get("threats", []):

        affected = threat.get(
            "affected_nodes",
            [],
        )

        response = {
            "source_node": threat["source_node"],
            "risk_score": threat["risk_score"],
            "confidence": threat["confidence"],
            "blast_radius": threat["blast_radius"],
            "affected_node_count": threat[
                "affected_node_count"
            ],
            "direct_affected_nodes": [
                item["node"]
                for item in threat.get(
                    "direct_affected_nodes",
                    [],
                )
            ],
            "secondary_affected_nodes": [
                item["node"]
                for item in threat.get(
                    "secondary_affected_nodes",
                    [],
                )
            ],
            "affected_nodes": [
                item["node"]
                for item in affected
            ],
            "recommended_action": (
                "ISOLATE_AND_INVESTIGATE"
                if threat["risk_score"] >= 0.99
                else "INVESTIGATE"
            ),
        }

        threats.append(response)

    output = {
        "module": "Member 2 - GNN Threat Prediction",
        "model": data.get(
            "model",
            "GraphSAGE",
        ),
        "threshold": data.get(
            "threshold"
        ),
        "threat_count": len(threats),
        "threats": threats,
    }

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=4,
        )

    print(
        f"\nThreats exported: "
        f"{len(threats)}"
    )

    print(
        f"Output saved to: "
        f"{OUTPUT_PATH}"
    )

    print("\n--- SAMPLE THREAT ---")

    if threats:

        sample = threats[0]

        print(
            json.dumps(
                sample,
                indent=4,
            )
        )

    print("\n========================================")
    print(" THREAT OUTPUT COMPLETE")
    print("========================================")


if __name__ == "__main__":
    main()