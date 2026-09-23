import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv


class ThreatGNN(nn.Module):
    def __init__(self, input_features, hidden_features=16):
        super().__init__()

        self.conv1 = SAGEConv(input_features, hidden_features)
        self.conv2 = SAGEConv(hidden_features, 1)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = torch.relu(x)

        x = self.conv2(x, edge_index)
        return x.squeeze(-1)

        return x