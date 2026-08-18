import torch
import torch.nn.functional as F

from src.gnn.model import ThreatGNN
from src.gnn.sample_data import create_sample_graph


# =========================================================
# SETTINGS
# =========================================================

# Scenarios used for training
training_sources = [0, 1, 2]

# Scenario NOT used during training
test_source = 3

node_names = [
    "WEB01",
    "APP01",
    "DB01",
    "FIN01"
]

threshold = 0.5


# =========================================================
# CREATE MODEL
# =========================================================

# All scenarios have the same number of features
sample_data = create_sample_graph(source_node=0)

model = ThreatGNN(
    input_features=sample_data.x.shape[1]
)

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=0.01
)


# =========================================================
# TRAIN ON MULTIPLE SCENARIOS
# =========================================================

print("\n--- TRAINING ---")
print("Training scenarios:", [
    node_names[i] for i in training_sources
])

for epoch in range(300):

    model.train()

    total_loss = 0.0

    for source in training_sources:

        data = create_sample_graph(
            source_node=source
        )

        optimizer.zero_grad()

        output = model(
            data.x,
            data.edge_index
        ).squeeze()

        loss = F.binary_cross_entropy_with_logits(
            output,
            data.y
        )

        loss.backward()

        optimizer.step()

        total_loss += loss.item()

    if (epoch + 1) % 50 == 0:

        average_loss = (
            total_loss / len(training_sources)
        )

        print(
            f"Epoch {epoch + 1}/300 | "
            f"Average Loss: {average_loss:.4f}"
        )


print("Training complete!")


# =========================================================
# TEST ON UNSEEN SCENARIO
# =========================================================

test_data = create_sample_graph(
    source_node=test_source
)

model.eval()

with torch.no_grad():

    logits = model(
        test_data.x,
        test_data.edge_index
    ).squeeze()

    probabilities = torch.sigmoid(logits)


source_name = node_names[test_source]


print("\n--- UNSEEN TEST SCENARIO ---")

print(
    "Attack source:",
    source_name
)


print("\n--- NODE RISK PREDICTIONS ---")

for name, probability in zip(
    node_names,
    probabilities
):

    print(
        f"{name}: {probability.item():.4f}"
    )


# =========================================================
# CONVERT PREDICTIONS TO LABELS
# =========================================================

predicted_labels = (
    probabilities >= threshold
).float()


# =========================================================
# COMPARE WITH GROUND TRUTH
# =========================================================

correct_predictions = (
    predicted_labels == test_data.y
).sum().item()

total_nodes = len(test_data.y)

accuracy = (
    correct_predictions / total_nodes
)


print("\n--- TEST EVALUATION ---")

print(
    f"Correct predictions: "
    f"{int(correct_predictions)}/{total_nodes}"
)

print(
    f"Test accuracy: {accuracy:.2%}"
)


# =========================================================
# BLAST RADIUS
# =========================================================

affected_nodes = []

for name, probability in zip(
    node_names,
    probabilities
):

    # Don't count the initial compromised node
    if (
        name != source_name
        and probability.item() >= threshold
    ):
        affected_nodes.append(name)


blast_radius = len(affected_nodes)


print("\n--- PREDICTED BLAST RADIUS ---")

print(
    "Affected nodes:",
    affected_nodes
)

print(
    "Blast radius:",
    blast_radius
)


# =========================================================
# FINAL RESULT
# =========================================================

source_risk = probabilities[
    test_source
].item()


result = {
    "source_node": source_name,
    "risk_score": round(source_risk, 4),
    "affected_nodes": affected_nodes,
    "blast_radius": blast_radius,
    "test_accuracy": round(accuracy, 4)
}


print("\n--- FINAL TEST RESULT ---")

for key, value in result.items():

    print(
        f"{key}: {value}"
    )