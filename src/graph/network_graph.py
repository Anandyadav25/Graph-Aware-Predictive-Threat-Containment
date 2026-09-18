"""
CIC-IDS2017 network graph construction.

Graph definition:
    Node  = unique IP address
    Edge  = communication from Source IP -> Destination IP

Node features are aggregated from network-flow statistics.
Node labels indicate whether the node participated in at least
one non-benign flow.

Important:
    IP addresses are used only as graph identities.
    Raw IP addresses are NOT used as ML features.
"""

from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data


# Numerical flow features used to build node representations.
# Labels are intentionally NOT included in the feature set.
FLOW_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Min Packet Length",
    "Max Packet Length",
]


def is_benign(label):
    """Return True when a CIC-IDS2017 label represents benign traffic."""
    if pd.isna(label):
        return True

    text = str(label).strip().upper()

    return text in {
        "BENIGN",
        "NORMAL",
        "NORMAL TRAFFIC",
    }


def find_csv_files(data_path):
    """Find one CSV file or all CSV files inside a directory."""
    path = Path(data_path)

    if path.is_file():
        return [path]

    if path.is_dir():
        files = sorted(path.rglob("*.csv"))

        if not files:
            raise FileNotFoundError(
                f"No CSV files found inside: {path}"
            )

        return files

    raise FileNotFoundError(
        f"Dataset path does not exist: {path}"
    )


def build_network_graph(
    data_path,
    chunksize=100_000,
    min_flows_per_node=1,
):
    """
    Build a PyTorch Geometric graph from CIC-IDS2017 flow CSV files.

    Parameters
    ----------
    data_path : str or Path
        CSV file or directory containing CIC-IDS2017 CSV files.

    chunksize : int
        Number of CSV rows processed at a time.

    min_flows_per_node : int
        Minimum number of flows involving a node.

    Returns
    -------
    data : torch_geometric.data.Data
        Graph containing:
            x          -> node feature matrix
            edge_index -> communication edges
            edge_attr  -> edge flow counts
            y          -> node labels
            node_ips   -> original IP address for each node
    """

    csv_files = find_csv_files(data_path)

    print("\n--- GRAPH CONSTRUCTION ---")
    print(f"CSV files: {len(csv_files)}")
    for file in csv_files:
        print(f"  {file}")

    # IP -> integer node ID
    node_to_id = {}

    # Per-node feature sums.
    feature_sums = defaultdict(
        lambda: np.zeros(len(FLOW_FEATURES), dtype=np.float64)
    )

    # Number of flows involving each node.
    flow_counts = defaultdict(int)

    # Whether node has participated in a non-benign flow.
    malicious_nodes = set()

    # Directed edge -> number of flows.
    edge_counts = defaultdict(int)

    total_rows = 0

    for csv_file in csv_files:
        print(f"\nProcessing: {csv_file.name}")

        for chunk in pd.read_csv(
         csv_file,
         chunksize=chunksize,
         low_memory=False,
         encoding="latin1",
         ):
            # CIC-IDS2017 contains inconsistent leading spaces
            # in column names.
            chunk.columns = chunk.columns.str.strip()

            required = {
                "Source IP",
                "Destination IP",
                "Label",
                *FLOW_FEATURES,
            }

            missing = required - set(chunk.columns)

            if missing:
                raise ValueError(
                    f"Missing required columns in {csv_file.name}: "
                    f"{sorted(missing)}"
                )

            # Remove rows without endpoint information.
            chunk = chunk.dropna(
                subset=["Source IP", "Destination IP"]
            )

            if chunk.empty:
                continue

            # Convert numerical features safely.
            for column in FLOW_FEATURES:
                chunk[column] = pd.to_numeric(
                    chunk[column],
                    errors="coerce",
                )

            chunk[FLOW_FEATURES] = (
                chunk[FLOW_FEATURES]
                .replace([np.inf, -np.inf], np.nan)
                .fillna(0.0)
            )

                       # Select columns explicitly instead of using itertuples()
            # with column names containing spaces.
            selected_columns = [
                "Source IP",
                "Destination IP",
                "Label",
                *FLOW_FEATURES,
            ]

            for row in chunk[selected_columns].itertuples(
                index=False,
                name=None,
            ):
                source = str(row[0]).strip()
                destination = str(row[1]).strip()
                label = row[2]

                if not source or not destination:
                    continue

                # Create node IDs.
                if source not in node_to_id:
                    node_to_id[source] = len(node_to_id)

                if destination not in node_to_id:
                    node_to_id[destination] = len(node_to_id)

                source_id = node_to_id[source]
                destination_id = node_to_id[destination]

                # Feature values begin at position 3.
                values = np.array(
                    [
                        float(value)
                        for value in row[3:]
                    ],
                    dtype=np.float64,
                )

                # Add the flow representation to BOTH endpoints.
                feature_sums[source] += values
                feature_sums[destination] += values

                flow_counts[source] += 1
                flow_counts[destination] += 1

                # Directed communication edge.
                edge_counts[
                    (source_id, destination_id)
                ] += 1

                # Node label = involved in at least one
                # non-benign flow.
                if not is_benign(label):
                    malicious_nodes.add(source)
                    malicious_nodes.add(destination)

            total_rows += len(chunk)
        print(f"  Rows processed so far: {total_rows:,}")

    if not node_to_id:
        raise RuntimeError("No valid network nodes were found.")

    # ---------------------------------------------------------
    # Construct node features
    # ---------------------------------------------------------

    num_nodes = len(node_to_id)
    num_features = len(FLOW_FEATURES)

    x = np.zeros(
        (num_nodes, num_features),
        dtype=np.float32,
    )

    node_ips = [""] * num_nodes

    for ip, node_id in node_to_id.items():
        node_ips[node_id] = ip

        count = max(flow_counts[ip], 1)

        # Mean flow statistics for the node.
        x[node_id] = (
            feature_sums[ip] / count
        ).astype(np.float32)

    # Remove nodes below the minimum flow threshold.
    valid_nodes = {
        node_id
        for ip, node_id in node_to_id.items()
        if flow_counts[ip] >= min_flows_per_node
    }

    if len(valid_nodes) < num_nodes:
        print(
            f"Removing {num_nodes - len(valid_nodes)} "
            "low-flow nodes."
        )

    # ---------------------------------------------------------
    # Build edges
    # ---------------------------------------------------------

    edges = []
    edge_weights = []

    for (source_id, destination_id), count in edge_counts.items():
        if (
            source_id in valid_nodes
            and destination_id in valid_nodes
        ):
            edges.append([source_id, destination_id])
            edge_weights.append(float(count))

    if edges:
        edge_index = torch.tensor(
            np.array(edges).T,
            dtype=torch.long,
        )

        edge_attr = torch.tensor(
            np.array(edge_weights).reshape(-1, 1),
            dtype=torch.float32,
        )
    else:
        edge_index = torch.empty(
            (2, 0),
            dtype=torch.long,
        )

        edge_attr = torch.empty(
            (0, 1),
            dtype=torch.float32,
        )

    # ---------------------------------------------------------
    # Node labels
    # ---------------------------------------------------------

    y = torch.zeros(
        num_nodes,
        dtype=torch.long,
    )

    for ip in malicious_nodes:
        node_id = node_to_id[ip]

        if node_id in valid_nodes:
            y[node_id] = 1

    # ---------------------------------------------------------
    # Convert to PyTorch tensors
    # ---------------------------------------------------------

    x_tensor = torch.tensor(
        x,
        dtype=torch.float32,
    )

    # Remove extreme numerical values.
    x_tensor = torch.nan_to_num(
        x_tensor,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )

    data = Data(
        x=x_tensor,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=y,
    )

    # Store useful metadata.
    data.node_ips = node_ips
    data.node_flow_counts = torch.tensor(
        [
            flow_counts[ip]
            for ip in node_ips
        ],
        dtype=torch.long,
    )

    print("\n--- GRAPH SUMMARY ---")
    print(f"Nodes: {data.num_nodes:,}")
    print(f"Edges: {data.num_edges:,}")
    print(f"Node features: {data.num_node_features}")
    print(f"Malicious/involved nodes: {int(data.y.sum()):,}")
    print(f"Benign nodes: {int((data.y == 0).sum()):,}")

    return data


def save_graph(data, output_path):
    """Save a PyTorch Geometric graph to disk."""
    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    torch.save(data, output_path)

    print(f"\nGraph saved to: {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Build a network graph from CIC-IDS2017."
    )

    parser.add_argument(
        "--data",
        required=True,
        help="CSV file or directory containing CIC-IDS2017 CSV files.",
    )

    parser.add_argument(
        "--output",
        default="data/processed/cic_ids2017_graph.pt",
        help="Output PyTorch graph path.",
    )

    parser.add_argument(
        "--chunksize",
        type=int,
        default=100_000,
        help="CSV rows processed per chunk.",
    )

    args = parser.parse_args()

    graph = build_network_graph(
        data_path=args.data,
        chunksize=args.chunksize,
    )

    save_graph(
        graph,
        args.output,
    )