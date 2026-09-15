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
  
if __name__ == "__main__":
    graph = create_enterprise_network()

    # Simulate an attacker compromising the web server
    graph = simulate_attack(graph, "web_server")

    print("Number of nodes:", graph.number_of_nodes())
    print("Number of edges:", graph.number_of_edges())

    print("\nCompromised nodes:")

    for node, attributes in graph.nodes(data=True):
        if attributes["compromised"] == 1:
            print(node, attributes)