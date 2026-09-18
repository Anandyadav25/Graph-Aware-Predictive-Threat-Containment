"""
Risk-aware blast-radius analysis for GNN-detected threats.
"""

from pathlib import Path
from collections import deque
import json

import torch

from src.gnn.model import ThreatGNN


GRAPH_PATH = Path(
    "data/processed/cic_ids2017_full_graph.pt"
)

MODEL_PATH = Path(
    "data/processed/threat_gnn_cic_ids2017.pt"
)

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


def main():

    print("\n========================================")
    print(" RISK-AWARE BLAST RADIUS ANALYSIS")
    print("========================================")

    # ---------------------------------------------------------
    # Load graph
    # ---------------------------------------------------------

    if not GRAPH_PATH.exists():
        raise FileNotFoundError(
            f"Graph not found: {GRAPH_PATH}"
        )

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    data = torch.load(
        GRAPH_PATH,
        weights_only=False,
    )

    checkpoint = torch.load(
        MODEL_PATH,
        weights_only=False,
    )

    print(
        f"\nGraph nodes: "
        f"{data.num_nodes:,}"
    )

    print(
        f"Graph edges: "
        f"{data.num_edges:,}"
    )

    # ---------------------------------------------------------
    # Load trained GraphSAGE model
    # ---------------------------------------------------------

    model = ThreatGNN(
        input_features=checkpoint[
            "input_features"
        ],
        hidden_features=checkpoint[
            "hidden_features"
        ],
    )

    model.load_state_dict(
        checkpoint[
            "model_state_dict"
        ]
    )

    model.eval()

    # ---------------------------------------------------------
    # Feature normalization
    # ---------------------------------------------------------

    mean = checkpoint[
        "feature_mean"
    ]

    std = checkpoint[
        "feature_std"
    ].clone()

    std[std < 1e-8] = 1.0

    data.x = (
        data.x - mean
    ) / std

    data.x = torch.nan_to_num(
        data.x,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )

    # ---------------------------------------------------------
    # GNN prediction
    # ---------------------------------------------------------

    with torch.no_grad():

        logits = model(
            data.x,
            data.edge_index,
        )

        probabilities = torch.sigmoid(
            logits
        ).view(-1)

    threshold = float(
        checkpoint["threshold"]
    )

    predictions = (
        probabilities >= threshold
    ).long()

    # ---------------------------------------------------------
    # Build network topology
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Analyze every detected threat
    # ---------------------------------------------------------

    results = []

    print("\n--- THREAT ANALYSIS ---")

    for node_id in threat_indices.tolist():

        source_ip = data.node_ips[
            node_id
        ]

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

        # -----------------------------------------------------
        # 1-hop affected nodes
        # -----------------------------------------------------

        for neighbor_id in nodes_by_hop.get(
            1,
            [],
        ):

            risk = float(
                probabilities[
                    neighbor_id
                ].item()
            )

            if risk >= threshold:

                direct_nodes.append(
                    {
                        "node": data.node_ips[
                            neighbor_id
                        ],
                        "risk_score": round(
                            risk,
                            4,
                        ),
                        "hops": 1,
                    }
                )

        # -----------------------------------------------------
        # 2-hop affected nodes
        # -----------------------------------------------------

        for neighbor_id in nodes_by_hop.get(
            2,
            [],
        ):

            risk = float(
                probabilities[
                    neighbor_id
                ].item()
            )

            if risk >= threshold:

                secondary_nodes.append(
                    {
                        "node": data.node_ips[
                            neighbor_id
                        ],
                        "risk_score": round(
                            risk,
                            4,
                        ),
                        "hops": 2,
                    }
                )

        # -----------------------------------------------------
        # Combine affected nodes
        # -----------------------------------------------------

        affected_nodes = (
            direct_nodes
            + secondary_nodes
        )

        affected_node_count = len(
            affected_nodes
        )

        # -----------------------------------------------------
        # Threat result
        # -----------------------------------------------------

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

            # Blast radius = number of affected
            # high-risk nodes.
            "blast_radius": (
                affected_node_count
            ),

            # Maximum topology distance
            # examined separately.
            "max_hops": MAX_HOPS,

            "direct_affected_nodes": (
                direct_nodes
            ),

            "secondary_affected_nodes": (
                secondary_nodes
            ),

            "affected_nodes": (
                affected_nodes
            ),

            "affected_node_count": (
                affected_node_count
            ),
        }

        results.append(result)

        # -----------------------------------------------------
        # Console output
        # -----------------------------------------------------

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
            f"Blast radius: "
            f"{affected_node_count} nodes"
        )

        print(
            f"Maximum topology distance: "
            f"{MAX_HOPS} hops"
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

    # ---------------------------------------------------------
    # Save structured blast-radius output
    # ---------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {

        "model": "GraphSAGE",

        "threshold": threshold,

        "max_hops": MAX_HOPS,

        "threat_count": len(
            results
        ),

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

    # ---------------------------------------------------------
    # Final message
    # ---------------------------------------------------------

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
        f"\nThreats analyzed: "
        f"{len(results)}"
    )

    print(
        f"Maximum topology distance: "
        f"{MAX_HOPS} hops"
    )

    print(
        f"Structured output: "
        f"{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()