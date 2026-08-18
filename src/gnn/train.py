import torch
import torch.nn.functional as F

from src.gnn.model import ThreatGNN
from src.gnn.sample_data import create_sample_graph


# Load our sample network
# Choose the initially compromised node
# 0 = WEB01
# 1 = APP01
# 2 = DB01
# 3 = FIN01
source_node_index = 0

data = create_sample_graph(
    source_node=source_node_index
)


# Create the GNN
model = ThreatGNN(
    input_features=data.x.shape[1]
)


# Optimizer
optimizer = torch.optim.Adam(
    model.parameters(),
    lr=0.01
)


# Train the model
for epoch in range(200):

    model.train()

    optimizer.zero_grad()

    # Ask the GNN for predictions
    output = model(
        data.x,
        data.edge_index
    ).squeeze()

    # Calculate how wrong the predictions are
    loss = F.binary_cross_entropy_with_logits(
        output,
        data.y
    )

    # Learn from the mistake
    loss.backward()

    optimizer.step()

    if (epoch + 1) % 20 == 0:
        print(
            f"Epoch {epoch + 1}/200 | Loss: {loss.item():.4f}"
        )


print("Training complete!")


# =========================================================
# MAKE RISK PREDICTIONS
# =========================================================

model.eval()

with torch.no_grad():

    logits = model(
        data.x,
        data.edge_index
    ).squeeze()

    probabilities = torch.sigmoid(logits)


# Names of the nodes in our sample network
node_names = [
    "WEB01",
    "APP01",
    "DB01",
    "FIN01"
]


print("\n--- NODE RISK PREDICTIONS ---")

for name, probability in zip(node_names, probabilities):

    print(
        f"{name}: {probability.item():.4f}"
    )


# =========================================================
# CALCULATE BLAST RADIUS
# =========================================================

threshold = 0.5

# Initial compromised machine
node_names = [
    "WEB01",
    "APP01",
    "DB01",
    "FIN01"
]

source_node = node_names[source_node_index]

affected_nodes = []

for name, probability in zip(
    node_names,
    probabilities
):

    # Do not count the original compromised machine
    if (
        name != source_node
        and probability.item() >= threshold
    ):
        affected_nodes.append(name)


# Number of additional affected machines
blast_radius = len(affected_nodes)


print("\n--- BLAST RADIUS ---")

print(
    "Affected nodes:",
    affected_nodes
)

print(
    "Blast radius:",
    blast_radius
)


# =========================================================
# FINAL THREAT PREDICTION
# =========================================================

source_index = node_names.index(source_node)

source_risk = probabilities[
    source_index
].item()


result = {
    "source_node": source_node,
    "risk_score": round(source_risk, 4),
    "affected_nodes": affected_nodes,
    "blast_radius": blast_radius
}


print("\n--- THREAT PREDICTION ---")

for key, value in result.items():

    print(
        f"{key}: {value}"
    )
    
# =========================================================
# EVALUATE THE PREDICTION
# =========================================================

predicted_labels = (
    probabilities >= threshold
).float()

correct_predictions = (
    predicted_labels == data.y
).sum().item()

total_nodes = len(data.y)

accuracy = correct_predictions / total_nodes

print("\n--- MODEL EVALUATION ---")
print(f"Correct predictions: {int(correct_predictions)}/{total_nodes}")
print(f"Accuracy: {accuracy:.2%}")