from src.gnn.blast_radius import predict_threat_with_blast_radius


def get_gnn_threat(source_node: str) -> dict:
    """
    Run the trained GraphSAGE model and return
    threat + blast-radius information for one node.
    """

    result = predict_threat_with_blast_radius(source_node)

    return {
        "source_node": result["source_node"],
        "risk_score": result["risk_score"],
        "confidence": result["confidence"],
        "blast_radius": result["blast_radius"],
        "affected_nodes": result["affected_nodes"],
    }