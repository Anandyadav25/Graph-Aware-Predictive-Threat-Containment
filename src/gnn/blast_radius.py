"""
Risk-aware blast-radius analysis for GNN-detected threats.
"""

from collections import deque
from pathlib import Path
import json

import torch

from src.gnn.predict import run_prediction


OUTPUT_PATH = Path(
    "data/processed/blast_radius_results.json"
)

MAX_HOPS = 2


def build_adjacency(edge_index, num_nodes):
    """Build an undirected adjacency list."""

    adjacency = [
        []
        for _ in range(num_nodes)
    ]

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

    queue = deque(
        [(source_node, 0)]
    )

    nodes_by_hop = {
        hop: []
        for hop in range(1, max_hops + 1)
    }

    while queue:

        current, distance = queue.popleft()

        if distance >= max_hops:
            continue

        for neighbor in adjacency[current]:

            if neighbor in visited:
                continue

            visited.add(neighbor)

            next_distance = distance + 1

            nodes_by_hop[
                next_distance
            ].append(neighbor)

            queue.append(
                (
                    neighbor,
                    next_distance,
                )
            )

    return nodes_by_hop


def calculate_blast_radius(
    source_node,
    data,
    probabilities,
    threshold,
    adjacency,
    max_hops=MAX_HOPS,
):
    """
    Calculate the risk-aware blast radius for one GNN-detected threat.

    Args:
        source_node: IP address of the threat node.
        data: Loaded PyTorch Geometric graph.
        probabilities: GNN threat probabilities for all nodes.
        threshold: GNN detection threshold.
        adjacency: Network adjacency list.
        max_hops: Maximum topology distance to inspect.

    Returns:
        Dictionary containing the threat and blast-radius information.
    """

    try:
        node_id = data.node_ips.index(source_node)
    except ValueError as exc:
        raise ValueError(
            f"Source node '{source_node}' was not found "
            "in the CIC-IDS2017 graph."
        ) from exc

    source_risk = float(
        probabilities[node_id].item()
    )

    nodes_by_hop = find_reachable_nodes(
        node_id,
        adjacency,
        max_hops,
    )

    direct_nodes = []
    secondary_nodes = []

    # 1-hop affected nodes.
    for neighbor_id in nodes_by_hop.get(1, []):

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

    # 2-hop affected nodes.
    for neighbor_id in nodes_by_hop.get(2, []):

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

    detailed_affected_nodes = (
        direct_nodes
        + secondary_nodes
    )

    affected_nodes = [
        item["node"]
        for item in detailed_affected_nodes
    ]

    affected_node_count = len(
        affected_nodes
    )

    return {
        "source_node": source_node,

        "risk_score": round(
            source_risk,
            4,
        ),

        "confidence": round(
            source_risk,
            4,
        ),

        "blast_radius": affected_node_count,

        "max_hops": max_hops,

        "direct_affected_nodes": direct_nodes,

        "secondary_affected_nodes": secondary_nodes,

        "affected_nodes": affected_nodes,

        "affected_node_count": affected_node_count,
    }
    
def predict_threat_with_blast_radius(source_node):
    """
    Return the GNN prediction and blast-radius result
    for one source node.

    This is the integration function for Member 3.
    """
    data, probabilities, predictions, threshold = run_prediction()

    adjacency = build_adjacency(
        data.edge_index,
        data.num_nodes,
    )

    node_id = data.node_ips.index(source_node)

    if int(predictions[node_id].item()) != 1:
        risk_score = float(
            probabilities[node_id].item()
        )

        return {
            "source_node": source_node,
            "risk_score": round(risk_score, 4),
            "confidence": round(risk_score, 4),
            "blast_radius": 0,
            "affected_nodes": [],
        }

    result = calculate_blast_radius(
        source_node=source_node,
        data=data,
        probabilities=probabilities,
        threshold=threshold,
        adjacency=adjacency,
        max_hops=MAX_HOPS,
    )

    return {
        "source_node": result["source_node"],
        "risk_score": result["risk_score"],
        "confidence": result["confidence"],
        "blast_radius": result["blast_radius"],
        "affected_nodes": result["affected_nodes"],
    }


def analyze_all_threats():
    """
    Run GNN prediction once and calculate blast radius
    for every detected threat.

    Returns:
        Structured blast-radius result dictionary.
    """

    data, probabilities, predictions, threshold = (
        run_prediction()
    )

    adjacency = build_adjacency(
        data.edge_index,
        data.num_nodes,
    )

    threat_indices = torch.where(
        predictions == 1
    )[0]

    results = []

    for node_id in threat_indices.tolist():

        source_ip = data.node_ips[node_id]

        result = calculate_blast_radius(
            source_node=source_ip,
            data=data,
            probabilities=probabilities,
            threshold=threshold,
            adjacency=adjacency,
            max_hops=MAX_HOPS,
        )

        results.append(result)

    return {
        "model": "GraphSAGE",
        "threshold": threshold,
        "max_hops": MAX_HOPS,
        "threat_count": len(results),
        "threats": results,
    }


def main():

    print("\n========================================")
    print(" RISK-AWARE BLAST RADIUS ANALYSIS")
    print("========================================")

    output = analyze_all_threats()

    print(
        f"\nThreats analyzed: "
        f"{output['threat_count']}"
    )

    print(
        f"Risk threshold: "
        f"{output['threshold']:.4f}"
    )

    print(
        f"Maximum topology distance: "
        f"{output['max_hops']} hops"
    )

    print("\n--- THREAT ANALYSIS ---")

    for result in output["threats"]:

        print(
            f"\nThreat: "
            f"{result['source_node']}"
        )

        print(
            f"Risk: "
            f"{result['risk_score']:.4f}"
        )

        print(
            f"1-hop high-risk nodes: "
            f"{len(result['direct_affected_nodes'])}"
        )

        print(
            f"2-hop high-risk nodes: "
            f"{len(result['secondary_affected_nodes'])}"
        )

        print(
            f"Blast radius: "
            f"{result['blast_radius']} nodes"
        )

        print(
            f"Maximum topology distance: "
            f"{result['max_hops']} hops"
        )

        if result["direct_affected_nodes"]:

            print(
                "Direct:",
                ", ".join(
                    item["node"]
                    for item in result[
                        "direct_affected_nodes"
                    ][:10]
                ),
            )

        if result["secondary_affected_nodes"]:

            print(
                "Secondary:",
                ", ".join(
                    item["node"]
                    for item in result[
                        "secondary_affected_nodes"
                    ][:10]
                ),
            )

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
        "\n========================================"
    )

    print(
        " BLAST RADIUS ANALYSIS COMPLETE"
    )

    print(
        "========================================"
    )

    print(
        f"\nStructured output: "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()