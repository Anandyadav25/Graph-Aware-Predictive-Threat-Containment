import networkx as nx


def create_enterprise_network():
    """
    Create a small enterprise network represented as a graph.

    Nodes represent devices/servers.
    Edges represent network connections.
    """

    graph = nx.Graph()

    # Add enterprise devices
    devices = {
    "firewall": {
        "type": "firewall",
        "criticality": 5,
        "compromised": 0
    },
    "web_server": {
        "type": "server",
        "criticality": 4,
        "compromised": 0
    },
    "app_server": {
        "type": "server",
        "criticality": 4,
        "compromised": 0
    },
    "database": {
        "type": "database",
        "criticality": 5,
        "compromised": 0
    },
    "auth_server": {
        "type": "authentication",
        "criticality": 5,
        "compromised": 0
    },
    "employee_pc_1": {
        "type": "endpoint",
        "criticality": 2,
        "compromised": 0
    },
    "employee_pc_2": {
        "type": "endpoint",
        "criticality": 2,
        "compromised": 0
    },
}

    for device, attributes in devices.items():
        graph.add_node(device, **attributes)

    # Add network connections
    connections = [
        ("firewall", "web_server"),
        ("web_server", "app_server"),
        ("app_server", "database"),
        ("app_server", "auth_server"),
        ("auth_server", "employee_pc_1"),
        ("auth_server", "employee_pc_2"),
    ]

    graph.add_edges_from(connections)

    return graph
def simulate_attack(graph, compromised_node):
    """
    Mark a node as compromised.

    Parameters:
        graph: NetworkX graph
        compromised_node: The node targeted by the attacker.

    Returns:
        Updated graph.
    """

    if compromised_node not in graph:
        raise ValueError(f"Node '{compromised_node}' does not exist in the network.")

    # Reset all nodes
    for node in graph.nodes:
        graph.nodes[node]["compromised"] = 0

    # Mark the attack source
    graph.nodes[compromised_node]["compromised"] = 1

    return graph

def propagate_attack(graph, compromised_node, max_hops=2):
    """
    Simulate possible attack propagation through the network.

    Parameters:
        graph: NetworkX graph
        compromised_node: Initial compromised node
        max_hops: Maximum number of network hops the attack can spread

    Returns:
        Updated graph with propagated compromised nodes.
    """

    if compromised_node not in graph:
        raise ValueError(f"Node '{compromised_node}' does not exist in the network.")

    # Reset all nodes
    for node in graph.nodes:
        graph.nodes[node]["compromised"] = 0

    # Find nodes reachable within the allowed number of hops
    reachable_nodes = nx.single_source_shortest_path_length(
        graph,
        compromised_node,
        cutoff=max_hops
    )

    # Mark reachable nodes as potentially compromised
    for node, distance in reachable_nodes.items():
        if distance <= max_hops:
            graph.nodes[node]["compromised"] = 1

    return graph

def run_attack_scenario(graph, source_node, max_hops=2):
    """
    Run an attack propagation scenario from a specified source node.

    Parameters:
        graph: NetworkX graph
        source_node: Initial compromised node
        max_hops: Maximum number of hops the attack can propagate

    Returns:
        List of compromised nodes.
    """

    graph = propagate_attack(graph, source_node, max_hops)

    compromised_nodes = [
        node
        for node, attributes in graph.nodes(data=True)
        if attributes["compromised"] == 1
    ]

    return compromised_nodes
  
if __name__ == "__main__":
    graph = create_enterprise_network()

    # Simulate an attacker compromising the web server
    scenarios = [
    {"name": "web_attack", "source": "web_server", "max_hops": 2},
    {"name": "endpoint_attack", "source": "employee_pc_1", "max_hops": 2},
    {"name": "application_attack", "source": "app_server", "max_hops": 2},
    {"name": "authentication_attack", "source": "auth_server", "max_hops": 2},
]

for scenario in scenarios:
    compromised = run_attack_scenario(
        graph,
        scenario["source"],
        scenario["max_hops"]
    )

    print(f"\nScenario: {scenario['name']}")
    print(f"Source node: {scenario['source']}")
    print(f"Compromised nodes: {compromised}")

    print("Number of nodes:", graph.number_of_nodes())
    print("Number of edges:", graph.number_of_edges())

    print("\nCompromised nodes:")

    for node, attributes in graph.nodes(data=True):
        if attributes["compromised"] == 1:
            print(node, attributes)