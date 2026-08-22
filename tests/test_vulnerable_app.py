import requests


def test_index_reachable(live_target_url):
    resp = requests.get(live_target_url, timeout=5)
    assert resp.status_code == 200


def test_user_endpoint_returns_valid_row_for_normal_input(live_target_url):
    resp = requests.get(f"{live_target_url}/user", params={"id": "1"}, timeout=5)
    assert resp.status_code == 200
    assert resp.json()["rows"][0][1] == "alice"
