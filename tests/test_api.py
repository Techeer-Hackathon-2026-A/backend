def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_not_found(client):
    assert client.get("/api/v1/scans/999").status_code == 404


def test_openapi_has_routes(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in [
        "/api/v1/scans",
        "/api/v1/scans/{scan_id}/report",
        "/api/v1/findings/{finding_id}",
        "/api/v1/findings/{finding_id}/fixes",
        "/api/v1/scans/{scan_id}/pull-requests",
    ]:
        assert p in paths
