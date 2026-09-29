"""Server HTTP reale dell'agent + HttpGuestClient dell'host, su loopback."""

import threading

import pytest

from tests.agent_fakes import CAP, TOKEN, make_session, settings
from webcquisition.guest_client import AgentError, HttpGuestClient
from webcquisition_agent.server import build_server


@pytest.fixture
def server(tmp_path):
    session = make_session(tmp_path)
    srv = build_server(settings(), session, host="127.0.0.1", port=0)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield url, session
    srv.shutdown()
    srv.server_close()


def test_auth_required(server):
    url, _ = server
    with pytest.raises(AgentError) as e:
        HttpGuestClient(url, "sbagliato" * 5).health()
    assert e.value.status == 401


def test_end_to_end_download(server, tmp_path):
    url, _ = server
    c = HttpGuestClient(url, TOKEN)
    assert c.health()["agent_id"] == "agent-test"
    c.prepare({"case_id": "CASE-9"})
    c.capture_start({"interface": CAP})
    c.firefox_start({})
    assert c.status()["capture"]["running"]
    c.stop({"order": "capture_first"})
    seal = c.seal()
    files = c.list_files()["files"]
    entry = next(f for f in files if f["path"] == "tls/sslkeylog.log")
    dest = tmp_path / "dl.bin"
    digest, size = c.download("tls/sslkeylog.log", dest)
    assert (digest, size) == (entry["sha256"], entry["size"])
    assert seal["file_count"] == len(files)


def test_path_traversal_over_http(server, tmp_path):
    url, _ = server
    c = HttpGuestClient(url, TOKEN)
    c.prepare({"case_id": "CASE-8"})
    c.stop({})
    c.seal()
    for bad in ("../../../etc/passwd", "..%2F..%2Fx", "C:\\Windows\\win.ini"):
        with pytest.raises(AgentError) as e:
            c.download(bad, tmp_path / f"x{abs(hash(bad))}")
        assert e.value.status in (400, 404)


def test_errors_have_codes(server):
    url, _ = server
    c = HttpGuestClient(url, TOKEN)
    with pytest.raises(AgentError) as e:
        c.firefox_start({})
    assert e.value.code == "NO_SESSION" and e.value.status == 409


def test_unknown_route(server):
    url, _ = server
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url + "/v1/nope", headers={"Authorization": f"Bearer {TOKEN}"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 404
