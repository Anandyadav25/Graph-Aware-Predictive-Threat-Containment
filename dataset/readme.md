# Network Attack Dataset

This directory contains the network topology and simulated attack propagation data used by the Graph-Aware Predictive Threat Containment project.

## Files

### network_graph.json

Represents the enterprise network as a graph.

#### Nodes

Each node contains:

- `id` - Unique device or server identifier
- `type` - Device category
- `criticality` - Importance of the device, from 1 to 5
- `degree` - Number of direct network connections
- `betweenness` - Betweenness centrality of the node

#### Edges

Each edge represents a network connection between two nodes.

- `source` - Starting node
- `target` - Connected node

## network_attack_dataset.csv

Contains simulated attack propagation scenarios.

### attack_scenario_summary.csv

Contains one summary record for each simulated attack scenario.

### Columns

- `scenario` - Name of the attack scenario
- `source_node` - Initial compromised node
- `hops` - Maximum attack propagation distance
- `compromised_nodes` - Nodes reached by the simulated attack
- `blast_radius` - Number of nodes reached by the attack

The summary contains 21 attack scenarios and provides a compact view of the simulated blast radius for each scenario.

### Columns

- `scenario` - Name of the attack scenario
- `source_node` - Initial compromised node
- `target_node` - Node being evaluated
- `hops` - Maximum attack propagation distance
- `criticality` - Criticality of the target node
- `compromised` - Target label: 1 if the node is within the simulated attack propagation range, otherwise 0

## Dataset Structure

The dataset contains:

- 7 network nodes
- 7 possible attack source nodes
- 3 propagation distances: 1, 2, and 3 hops
- 21 attack scenarios
- 147 total records

Each scenario evaluates all 7 network nodes.

## Purpose

The dataset provides the input and target labels for the GNN component.

The network graph provides the topology and node-level graph features.

The attack dataset provides simulated attack scenarios and the `compromised` target label that can be used for predictive modeling.

## Data Generation

The dataset is generated using:

`src/graph/generate_dataset.py`

The enterprise network and attack propagation logic are implemented in:

`src/graph/network_graph.py`