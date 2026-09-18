"""
Run trained GraphSAGE threat prediction on the CIC-IDS2017 graph.
"""

from pathlib import Path

import torch

from src.gnn.model import ThreatGNN


GRAPH_PATH = Path("data/processed/cic_ids2017_full_graph.pt")
MODEL_PATH = Path("data/processed/threat_gnn_cic_ids2017.pt")


def main():
    print("\n========================================")
    print(" GNN THREAT PREDICTION")
    print("========================================")

    # Load graph
    data = torch.load(
        GRAPH_PATH,
        weights_only=False,
    )

    # Load trained model
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

    # Apply the same normalization used during training
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

    # Generate predictions
    with torch.no_grad():
        logits = model(
            data.x,
            data.edge_index,
        )

        probabilities = torch.sigmoid(logits)

    threshold = checkpoint["threshold"]

    predictions = (
        probabilities >= threshold
    ).long()

    print(f"\nGraph nodes: {data.num_nodes:,}")
    print(f"Graph edges: {data.num_edges:,}")
    print(f"Detection threshold: {threshold:.4f}")

    print("\n--- TOP RISK NODES ---")

    top_count = min(
        10,
        data.num_nodes,
    )

    top_indices = torch.argsort(
        probabilities,
        descending=True,
    )[:top_count]

    for rank, node_id in enumerate(
        top_indices.tolist(),
        start=1,
    ):
        ip = data.node_ips[node_id]
        score = probabilities[node_id].item()
        prediction = int(predictions[node_id])

        status = (
            "THREAT"
            if prediction == 1
            else "BENIGN"
        )

        print(
            f"{rank:2d}. "
            f"{ip:<16} "
            f"Risk={score:.4f} "
            f"Status={status}"
        )

    threat_count = int(
        predictions.sum()
    )

    print("\n--- SUMMARY ---")
    print(
        f"Predicted threats: "
        f"{threat_count:,}"
    )

    print(
        f"Predicted benign: "
        f"{data.num_nodes - threat_count:,}"
    )

    print("\n========================================")
    print(" PREDICTION COMPLETE")
    print("========================================")


if __name__ == "__main__":
    main()