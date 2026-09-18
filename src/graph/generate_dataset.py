import csv
import json
from pathlib import Path

from network_graph import create_enterprise_network, run_attack_scenario


def generate_attack_dataset():
    """
    Generate attack propagation data for different attack scenarios.
    """

    graph = create_enterprise_network()

    sources = [
        "firewall",
        "web_server",
        "app_server",
        "database",
        "auth_server",
        "employee_pc_1",
        "employee_pc_2",
    ]

    scenarios = []

    for source in sources:
         for max_hops in [1, 2, 3]:
              scenarios.append({
                "name": f"{source}_attack_{max_hops}hop",
                "source": source,
                "max_hops": max_hops
            })

    rows = []

    for scenario in scenarios:
        compromised_nodes = run_attack_scenario(
            graph,
            scenario["source"],
            scenario["max_hops"]
        )

        for node in graph.nodes:
            rows.append({
                "scenario": scenario["name"],
                "source_node": scenario["source"],
                "target_node": node,
                "hops": scenario["max_hops"],
                "criticality": graph.nodes[node]["criticality"],
                "compromised": 1 if node in compromised_nodes else 0
            })

    output_path = Path(__file__).resolve().parents[2] / "dataset" / "network_attack_dataset.csv"

    with open(output_path, "w", newline="") as csv_file:
        fieldnames = [
            "scenario",
            "source_node",
            "target_node",
            "hops",
            "criticality",
            "compromised"
        ]

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Dataset generated: {output_path}")
    print(f"Total records: {len(rows)}")


def export_network_graph(graph):
    """
    Export the enterprise network structure for GNN processing.
    """

    graph_data = {
        "nodes": [],
        "edges": []
    }

    for index, (node, attributes) in enumerate(graph.nodes(data=True)):
        graph_data["nodes"].append({
            "index": index,
            "id": node,
            "type": attributes["type"],
            "criticality": attributes["criticality"],
            "degree": attributes["degree"],
            "betweenness": attributes["betweenness"]
        })

    for source, target in graph.edges():
        graph_data["edges"].append({
            "source": source,
            "target": target
        })

    output_path = (
        Path(__file__).resolve().parents[2]
        / "dataset"
        / "network_graph.json"
    )

    with open(output_path, "w") as json_file:
        json.dump(graph_data, json_file, indent=4)

    print(f"Graph exported: {output_path}")

if __name__ == "__main__":
    graph = create_enterprise_network()

    generate_attack_dataset()
    export_network_graph(graph)