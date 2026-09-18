"""
Risk-aware blast-radius analysis for GNN-detected threats.
"""

from pathlib import Path
from collections import deque
import json

import torch

from src.gnn.model import ThreatGNN


GRAPH_PATH = Path("data/processed/cic_ids2017_full_graph.pt")
MODEL_PATH = Path("data/processed/threat_gnn_cic_ids2017.pt")
OUTPUT_PATH = Path("data/processed/blast_radius_results.json")

MAX_HOPS = 2


def build_adjacency(edge_index, num_nodes):
    """Build an undirected adjacency list."""

    adjacency = [[] for _ in range(num_nodes)]

    for source, target in edge_index.t().tolist():
        adjacency[source].append(target)
        adjacency[target].append(source)

    return adjacency


def find_reachable_nodes(
    source_node,
    adjacency,
    max_hops,
):
    """Find nodes reachable within the requested hop distance."""

    visited = {source_node}
    queue = deque([(source_node, 0)])
    nodes_by_hop = {1: [], 2: []}

    while queue:
        current, distance = queue.popleft()

        if distance >= max_hops:
            continue

        for neighbor in adjacency[current]:

            if neighbor in visited:
                continue

            visited.add(neighbor)

            next_distance = distance + 1

            if next_distance <= max_hops:
                nodes_by_hop[next_distance].append(
                    neighbor
                )

            queue.append(
                (neighbor, next_distance)
            )

    return nodes_by_hop


def main():

    print("\n========================================")
    print(" RISK-AWARE BLAST RADIUS ANALYSIS")
    print("========================================")

    data = torch.load(
        GRAPH_PATH,
        weights_only=False,
    )

    checkpoint = torch.load(
        MODEL_PATH,
        weights_only=False,
    )

    model = ThreatGNN(
        input_features=checkpoint["input_features"],
        hidden_features=checkpoint["hidden_features"],
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.eval()

    # Same feature normalization as inference
    mean = checkpoint["feature_mean"]
    std = checkpoint["feature_std"]

    std[std < 1e-8] = 1.0

    data.x = (data.x - mean) / std

    data.x = torch.nan_to_num(
        data.x,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )

    # GNN prediction
    with torch.no_grad():

        logits = model(
            data.x,
            data.edge_index,
        )

        probabilities = torch.sigmoid(logits)

    threshold = float(
        checkpoint["threshold"]
    )

    predictions = (
        probabilities >= threshold
    ).long()

    adjacency = build_adjacency(
        data.edge_index,
        data.num_nodes,
    )

    threat_indices = torch.where(
        predictions == 1
    )[0]

    print(
        f"\nDetected threat nodes: "
        f"{len(threat_indices)}"
    )

    print(
        f"Risk threshold: "
        f"{threshold:.4f}"
    )

    print(
        f"Maximum topology distance: "
        f"{MAX_HOPS} hops"
    )

    results = []

    print("\n--- THREAT ANALYSIS ---")

    for node_id in threat_indices.tolist():

        source_ip = data.node_ips[node_id]

        source_risk = float(
            probabilities[node_id].item()
        )

        nodes_by_hop = find_reachable_nodes(
            node_id,
            adjacency,
            MAX_HOPS,
        )

        direct_nodes = []
        secondary_nodes = []

        # Only classify another node as affected
        # when its GNN risk is also above threshold.
        for neighbor_id in nodes_by_hop[1]:

            risk = float(
                probabilities[neighbor_id].item()
            )

            if risk >= threshold:
                direct_nodes.append(
                    {
                        "node": data.node_ips[neighbor_id],
                        "risk_score": round(risk, 4),
                        "hops": 1,
                    }
                )

        for neighbor_id in nodes_by_hop[2]:

            risk = float(
                probabilities[neighbor_id].item()
            )

            if risk >= threshold:
                secondary_nodes.append(
                    {
                        "node": data.node_ips[neighbor_id],
                        "risk_score": round(risk, 4),
                        "hops": 2,
                    }
                )

        affected_nodes = (
            direct_nodes
            + secondary_nodes
        )

        result = {
            "source_node": source_ip,
            "risk_score": round(
                source_risk,
                4,
            ),
            "confidence": round(
                source_risk,
                4,
            ),
            "blast_radius": MAX_HOPS,
            "direct_affected_nodes": direct_nodes,
            "secondary_affected_nodes": secondary_nodes,
            "affected_nodes": affected_nodes,
            "affected_node_count": len(
                affected_nodes
            ),
        }

        results.append(result)

        print(
            f"\nThreat: {source_ip}"
        )

        print(
            f"Risk: {source_risk:.4f}"
        )

        print(
            f"1-hop high-risk nodes: "
            f"{len(direct_nodes)}"
        )

        print(
            f"2-hop high-risk nodes: "
            f"{len(secondary_nodes)}"
        )

        print(
            f"Total affected high-risk nodes: "
            f"{len(affected_nodes)}"
        )

        if direct_nodes:

            print(
                "Direct:",
                ", ".join(
                    item["node"]
                    for item in direct_nodes[:10]
                ),
            )

        if secondary_nodes:

            print(
                "Secondary:",
                ", ".join(
                    item["node"]
                    for item in secondary_nodes[:10]
                ),
            )

    # Save structured handoff
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "model": "GraphSAGE",
        "threshold": threshold,
        "max_hops": MAX_HOPS,
        "threat_count": len(results),
        "threats": results,
    }

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

    print("\n========================================")
    print(" BLAST RADIUS ANALYSIS COMPLETE")
    print("========================================")

    print(
        f"\nStructured output: "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()