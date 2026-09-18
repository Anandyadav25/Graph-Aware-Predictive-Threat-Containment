"""
Train GraphSAGE on the real CIC-IDS2017 network graph.
"""

from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
)

from src.gnn.model import ThreatGNN


GRAPH_PATH = Path("data/processed/cic_ids2017_full_graph.pt")
MODEL_PATH = Path("data/processed/threat_gnn_cic_ids2017.pt")

EPOCHS = 200
LEARNING_RATE = 0.01
HIDDEN_FEATURES = 16
THRESHOLD = 0.5
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15

SEED = 42


def create_masks(labels):
    """Create deterministic stratified train/validation/test masks."""

    generator = torch.Generator()
    generator.manual_seed(SEED)

    positive_indices = torch.where(labels == 1)[0]
    negative_indices = torch.where(labels == 0)[0]

    # Shuffle both classes independently
    positive_indices = positive_indices[
        torch.randperm(
            len(positive_indices),
            generator=generator,
        )
    ]

    negative_indices = negative_indices[
        torch.randperm(
            len(negative_indices),
            generator=generator,
        )
    ]

    # ---------------------------------------------------------
    # Stratified split
    # ---------------------------------------------------------
    # We explicitly guarantee that the minority class is
    # distributed across train / validation / test.
    #
    # For 13 malicious nodes this gives:
    # Train = 9
    # Validation = 2
    # Test = 2
    # ---------------------------------------------------------

    pos_total = len(positive_indices)

    if pos_total >= 3:
        pos_train = max(
            1,
            int(round(pos_total * TRAIN_RATIO)),
        )

        pos_val = max(
            1,
            int(round(pos_total * VAL_RATIO)),
        )

        # Ensure at least one positive remains for test
        if pos_train + pos_val >= pos_total:
            pos_val = 1

        pos_test = (
            pos_total
            - pos_train
            - pos_val
        )

        # If rounding produced an undesirable split,
        # force at least one positive in every split.
        if pos_test < 1:
            pos_test = 1
            pos_val = max(
                1,
                pos_total - pos_train - pos_test,
            )
    else:
        raise ValueError(
            "At least 3 malicious nodes are required "
            "for stratified train/validation/test splitting."
        )

    # Negative class follows the requested ratios.
    neg_total = len(negative_indices)

    neg_train = int(
        neg_total * TRAIN_RATIO
    )

    neg_val = int(
        neg_total * VAL_RATIO
    )

    neg_test = (
        neg_total
        - neg_train
        - neg_val
    )

    # ---------------------------------------------------------
    # Build indices
    # ---------------------------------------------------------

    train_indices = torch.cat(
        [
            positive_indices[:pos_train],
            negative_indices[:neg_train],
        ]
    )

    val_indices = torch.cat(
        [
            positive_indices[
                pos_train:
                pos_train + pos_val
            ],
            negative_indices[
                neg_train:
                neg_train + neg_val
            ],
        ]
    )

    test_indices = torch.cat(
        [
            positive_indices[
                pos_train + pos_val:
            ],
            negative_indices[
                neg_train + neg_val:
            ],
        ]
    )

    # Shuffle final splits
    train_indices = train_indices[
        torch.randperm(
            len(train_indices),
            generator=generator,
        )
    ]

    val_indices = val_indices[
        torch.randperm(
            len(val_indices),
            generator=generator,
        )
    ]

    test_indices = test_indices[
        torch.randperm(
            len(test_indices),
            generator=generator,
        )
    ]

    # ---------------------------------------------------------
    # Create boolean masks
    # ---------------------------------------------------------

    num_nodes = len(labels)

    train_mask = torch.zeros(
        num_nodes,
        dtype=torch.bool,
    )

    val_mask = torch.zeros(
        num_nodes,
        dtype=torch.bool,
    )

    test_mask = torch.zeros(
        num_nodes,
        dtype=torch.bool,
    )

    train_mask[train_indices] = True
    val_mask[val_indices] = True
    test_mask[test_indices] = True

    return (
        train_mask,
        val_mask,
        test_mask,
    )


def calculate_metrics(y_true, y_pred):
    """Calculate binary classification metrics."""

    return {
        "accuracy": accuracy_score(
            y_true,
            y_pred,
        ),
        "precision": precision_score(
            y_true,
            y_pred,
            zero_division=0,
        ),
        "recall": recall_score(
            y_true,
            y_pred,
            zero_division=0,
        ),
        "f1": f1_score(
            y_true,
            y_pred,
            zero_division=0,
        ),
    }


def main():

    torch.manual_seed(SEED)
    np.random.seed(SEED)

    print("\n========================================")
    print(" CIC-IDS2017 GNN THREAT TRAINING")
    print("========================================")

    # ---------------------------------------------------------
    # Load graph
    # ---------------------------------------------------------

    if not GRAPH_PATH.exists():
        raise FileNotFoundError(
            f"Graph not found: {GRAPH_PATH}\n"
            "Run network_graph.py first."
        )

    print(f"\nLoading graph: {GRAPH_PATH}")

    data = torch.load(
        GRAPH_PATH,
        weights_only=False,
    )

    print(f"Nodes: {data.num_nodes:,}")
    print(f"Edges: {data.num_edges:,}")
    print(
        f"Node features: "
        f"{data.num_node_features}"
    )

    positive_count = int(data.y.sum())

    negative_count = int(
        (data.y == 0).sum()
    )

    print(
        f"Malicious nodes: "
        f"{positive_count:,}"
    )

    print(
        f"Benign nodes: "
        f"{negative_count:,}"
    )

    # ---------------------------------------------------------
    # Normalize features
    # ---------------------------------------------------------

    mean = data.x.mean(dim=0)
    std = data.x.std(dim=0)

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
    # Train / validation / test split
    # ---------------------------------------------------------

    (
        train_mask,
        val_mask,
        test_mask,
    ) = create_masks(data.y)

    data.train_mask = train_mask
    data.val_mask = val_mask
    data.test_mask = test_mask

    print("\n--- DATA SPLIT ---")

    print(
        f"Training nodes: "
        f"{int(train_mask.sum()):,}"
    )

    print(
        f"Validation nodes: "
        f"{int(val_mask.sum()):,}"
    )

    print(
        f"Test nodes: "
        f"{int(test_mask.sum()):,}"
    )

    print(
        f"Training malicious: "
        f"{int(data.y[train_mask].sum())}"
    )

    print(
        f"Validation malicious: "
        f"{int(data.y[val_mask].sum())}"
    )

    print(
        f"Test malicious: "
        f"{int(data.y[test_mask].sum())}"
    )

    # ---------------------------------------------------------
    # Model
    # ---------------------------------------------------------

    model = ThreatGNN(
        input_features=data.num_node_features,
        hidden_features=HIDDEN_FEATURES,
    )

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE,
        weight_decay=1e-4,
    )

    # ---------------------------------------------------------
    # Class-weighted loss
    # ---------------------------------------------------------

    train_labels = data.y[train_mask]

    train_positive = int(
        (train_labels == 1).sum()
    )

    train_negative = int(
        (train_labels == 0).sum()
    )

    if train_positive > 0:
        positive_weight = (
            train_negative
            / train_positive
        )
    else:
        positive_weight = 1.0

    positive_weight = min(
        positive_weight,
        1000.0,
    )

    pos_weight = torch.tensor(
        positive_weight,
        dtype=torch.float32,
    )

    criterion = torch.nn.BCEWithLogitsLoss(
        pos_weight=pos_weight
    )

    print("\n--- MODEL ---")
    print(model)

    print(
        f"\nPositive class weight: "
        f"{positive_weight:.2f}"
    )

    # ---------------------------------------------------------
    # Training
    # ---------------------------------------------------------

    print("\n--- TRAINING ---")

    best_val_f1 = -1.0
    best_state = None

    for epoch in range(
        1,
        EPOCHS + 1,
    ):

        model.train()

        optimizer.zero_grad()

        logits = model(
            data.x,
            data.edge_index,
        )

        loss = criterion(
            logits[train_mask],
            data.y[
                train_mask
            ].float(),
        )

        loss.backward()

        torch.nn.utils.clip_grad_norm_(
            model.parameters(),
            max_norm=1.0,
        )

        optimizer.step()

        # -----------------------------------------------------
        # Validation
        # -----------------------------------------------------

        model.eval()

        with torch.no_grad():

            val_logits = model(
                data.x,
                data.edge_index,
            )

            val_probabilities = torch.sigmoid(
                val_logits[val_mask]
            )

            val_predictions = (
                val_probabilities >= THRESHOLD
            ).long()

            val_true = data.y[val_mask]

            val_metrics = calculate_metrics(
                val_true.cpu().numpy(),
                val_predictions.cpu().numpy(),
            )

        if (
            val_metrics["f1"]
            > best_val_f1
        ):

            best_val_f1 = (
                val_metrics["f1"]
            )

            best_state = {
                key: value.detach()
                .cpu()
                .clone()
                for key, value
                in model.state_dict().items()
            }

        if (
            epoch == 1
            or epoch % 20 == 0
            or epoch == EPOCHS
        ):

            print(
                f"Epoch {epoch:3d}/{EPOCHS} | "
                f"Loss: {loss.item():.4f} | "
                f"Val F1: "
                f"{val_metrics['f1']:.4f} | "
                f"Val Recall: "
                f"{val_metrics['recall']:.4f}"
            )

    # ---------------------------------------------------------
    # Restore best model
    # ---------------------------------------------------------

    if best_state is not None:
        model.load_state_dict(
            best_state
        )

    print("\nTraining complete.")

    # ---------------------------------------------------------
    # Validation-based threshold selection
    # ---------------------------------------------------------

    model.eval()

    with torch.no_grad():

        validation_logits = model(
            data.x,
            data.edge_index,
        )

        validation_probabilities = torch.sigmoid(
            validation_logits[val_mask]
        )

    validation_true = data.y[val_mask]

    precision_values, recall_values, thresholds = (
        precision_recall_curve(
            validation_true.cpu().numpy(),
            validation_probabilities.cpu().numpy(),
        )
    )

    if len(thresholds) > 0:

        f1_values = (
            2
            * precision_values[:-1]
            * recall_values[:-1]
            / (
                precision_values[:-1]
                + recall_values[:-1]
                + 1e-8
            )
        )

        best_threshold_index = int(
            np.argmax(f1_values)
        )

        selected_threshold = float(
            thresholds[
                best_threshold_index
            ]
        )

        validation_pr_auc = (
            average_precision_score(
                validation_true.cpu().numpy(),
                validation_probabilities.cpu().numpy(),
            )
        )

    else:

        selected_threshold = THRESHOLD
        validation_pr_auc = 0.0

    print("\n--- THRESHOLD SELECTION ---")

    print(
        f"Selected threshold: "
        f"{selected_threshold:.4f}"
    )

    print(
        f"Validation PR-AUC: "
        f"{validation_pr_auc:.4f}"
    )

    # ---------------------------------------------------------
    # Final test evaluation
    # ---------------------------------------------------------

    model.eval()

    with torch.no_grad():

        logits = model(
            data.x,
            data.edge_index,
        )

        probabilities = torch.sigmoid(
            logits
        )

    test_probabilities = probabilities[
        test_mask
    ]

    test_predictions = (
        test_probabilities
        >= selected_threshold
    ).long()

    test_true = data.y[test_mask]

    metrics = calculate_metrics(
        test_true.cpu().numpy(),
        test_predictions.cpu().numpy(),
    )

    cm = confusion_matrix(
        test_true.cpu().numpy(),
        test_predictions.cpu().numpy(),
        labels=[0, 1],
    )

    # ---------------------------------------------------------
    # Results
    # ---------------------------------------------------------

    print("\n========================================")
    print(" FINAL TEST RESULTS")
    print("========================================")

    print(
        f"Accuracy : "
        f"{metrics['accuracy']:.2%}"
    )

    print(
        f"Precision: "
        f"{metrics['precision']:.2%}"
    )

    print(
        f"Recall   : "
        f"{metrics['recall']:.2%}"
    )

    print(
        f"F1 Score : "
        f"{metrics['f1']:.2%}"
    )

    print("\nConfusion Matrix:")
    print(cm)

    # ---------------------------------------------------------
    # Highest-risk nodes
    # ---------------------------------------------------------

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

        score = probabilities[
            node_id
        ].item()

        label = int(
            data.y[node_id]
        )

        print(
            f"{rank:2d}. "
            f"{ip:<16} "
            f"Risk={score:.4f} "
            f"Label={label}"
        )

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    torch.save(
        {
            "model_state_dict":
                model.state_dict(),

            "input_features":
                data.num_node_features,

            "hidden_features":
                HIDDEN_FEATURES,

            "threshold":
                selected_threshold,

            "feature_mean":
                mean,

            "feature_std":
                std,

            "metrics":
                metrics,
        },
        MODEL_PATH,
    )

    print(
        f"\nModel saved to: "
        f"{MODEL_PATH}"
    )

    print(
        "\n========================================"
    )

    print(
        " GNN TRAINING FINISHED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()