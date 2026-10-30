"""Unit tests for the live interactive Flask web frontend."""

from tgap.webapp import app


def test_webapp_interactive_routes():
    client = app.test_client()

    # Default view
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Dataset Source" in html
    assert "Run Analysis" in html

    # Custom parameters view with PyTorch GNN and CADETS E3
    resp2 = client.get("/?dataset=cadets_e3&mechanism=uniform&rate=0.2&detector=deep_gnn&weight=0.8&seed=7")
    assert resp2.status_code == 200
    html2 = resp2.get_data(as_text=True)
    assert "20% Uniform" in html2
