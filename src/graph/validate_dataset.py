import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CSV_PATH = PROJECT_ROOT / "dataset" / "network_attack_dataset.csv"
GRAPH_PATH = PROJECT_ROOT / "dataset" / "network_graph.json"


def validate_attack_dataset():
    """Validate the generated attack propagation dataset."""

    required_columns = {
        "scenario",
        "source_node",
        "target_node",
        "hops",
        "criticality",
        "compromised",
    }

    with open(CSV_PATH, newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    if not rows:
        raise ValueError("Attack dataset is empty.")

    actual_columns = set(rows[0].keys())

    if actual_columns != required_columns:
        raise ValueError(
            f"Unexpected CSV columns: {actual_columns}"
        )

    if len(rows) != 147:
        raise ValueError(
            f"Expected 147 records, found {len(rows)}."
        )

    scenarios = {row["scenario"] for row in rows}
    sources = {row["source_node"] for row in rows}
    hops = {int(row["hops"]) for row in rows}
    labels = {int(row["compromised"]) for row in rows}

    if len(scenarios) != 21:
        raise ValueError(
            f"Expected 21 scenarios, found {len(scenarios)}."
        )

    if len(sources) != 7:
        raise ValueError(
            f"Expected 7 source nodes, found {len(sources)}."
        )

    if hops != {1, 2, 3}:
        raise ValueError(
            f"Unexpected hop values: {hops}"
        )

    if not labels.issubset({0, 1}):
        raise ValueError(
            f"Invalid compromised labels: {labels}"
        )

    print("Attack dataset validation passed.")
    print(f"Records: {len(rows)}")
    print(f"Scenarios: {len(scenarios)}")
    print(f"Sources: {len(sources)}")
    print(f"Hop values: {sorted(hops)}")


def validate_network_graph():
    """Validate the exported network graph."""

    with open(GRAPH_PATH) as json_file:
        graph_data = json.load(json_file)

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if len(nodes) != 7:
        raise ValueError(
            f"Expected 7 graph nodes, found {len(nodes)}."
        )

    if len(edges) != 6:
        raise ValueError(
            f"Expected 6 graph edges, found {len(edges)}."
        )

    required_node_fields = {
        "index",
        "id",
        "type",
        "criticality",
        "degree",
        "betweenness",
    }

    for node in nodes:
        if set(node.keys()) != required_node_fields:
            raise ValueError(
                f"Unexpected node fields for {node['id']}: "
                f"{set(node.keys())}"
            )

    print("Network graph validation passed.")
    print(f"Nodes: {len(nodes)}")
    print(f"Edges: {len(edges)}")


if __name__ == "__main__":
    validate_attack_dataset()
    validate_network_graph()
    print("All dataset validations passed.")