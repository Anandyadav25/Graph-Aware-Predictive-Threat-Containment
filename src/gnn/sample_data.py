import torch
from torch_geometric.data import Data


def create_sample_graph(source_node=0):
    # Node mapping:
    # 0 = WEB01
    # 1 = APP01
    # 2 = DB01
    # 3 = FIN01

    criticality = [0.6, 0.8, 1.0, 0.7]

    # Mark the initially compromised machine
    compromised = [0.0, 0.0, 0.0, 0.0]
    compromised[source_node] = 1.0

    # Node features:
    # [criticality, compromised]
    x = torch.tensor(
        [
            [criticality[i], compromised[i]]
            for i in range(4)
        ],
        dtype=torch.float
    )

    # Network:
    # WEB01 <-> APP01 <-> DB01 <-> FIN01
    edge_index = torch.tensor(
        [
            [0, 1, 1, 2, 2, 3],
            [1, 0, 2, 1, 3, 2],
        ],
        dtype=torch.long
    )

    # Synthetic affected-node labels.
    # These represent our expected attack spread
    # for the current prototype.
    y = torch.zeros(4, dtype=torch.float)

    if source_node == 0:
        # WEB01 attack -> WEB01, APP01, DB01
        y[0] = 1
        y[1] = 1
        y[2] = 1

    elif source_node == 1:
        # APP01 attack -> APP01, DB01
        y[1] = 1
        y[2] = 1

    elif source_node == 2:
        # DB01 attack -> DB01, FIN01
        y[2] = 1
        y[3] = 1

    elif source_node == 3:
        # FIN01 attack -> FIN01
        y[3] = 1

    else:
        raise ValueError("source_node must be between 0 and 3")

    return Data(
        x=x,
        edge_index=edge_index,
        y=y
    )