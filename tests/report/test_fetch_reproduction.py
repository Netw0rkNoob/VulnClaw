"""Compare actual fetch requests with the requests exported in Solve reports."""

import shlex
import shutil
import socket
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager
from vulnclaw.report.solve_report import (
    extract_reproduction_requests,
    generate_solve_report,
    render_solve_report,
)


def _curl_config(arguments):
    """Transport parsed bash arguments without Windows' native argv code page."""
    escapes = str.maketrans({"\\": "\\\\", '"': '\\"', "\t": "\\t", "\r": "\\r", "\n": "\\n", "\v": "\\v"})
    lines = []
    options = iter(arguments[:-1])
    for option in options:
        if option in {"-k", "-i"}:
            lines.append(option)
        else:
            assert option in {"-X", "-H", "--data-raw"}
            lines.append(f'{option} "{next(options).translate(escapes)}"')
    lines.append(f'url = "{arguments[-1].translate(escapes)}"')
    return ("\n".join(lines) + "\n").encode("utf-8")


@pytest.fixture
def receiver():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.do_POST()

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.append((self.command, self.path, dict(self.headers.items()), body))
            self.send_response(200)
            self.send_header("Content-Length", "13")
            self.end_headers()
            self.wfile.write(b"response-only")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("arguments", [
    {},
    {"headers": {"X-Repro": "O'Reilly"}},
    {"params": {"term": "你好 world", "tag": ["one", "two"]}},
    {"method": "POST", "json": {"message": "你好 'quoted'", "count": 2}},
    {"method": "POST", "form": {"name": "你好", "tag": ["one", "two"]}},
    {"method": "POST", "data": {"name": "a b", "enabled": True}},
    {"method": "POST", "body": "name=demo&count=2",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    {"method": "POST", "data": "@literal\\path\r\n你好\t' $(not-a-command)",
     "headers": {"Content-Type": "text/plain", "X-Repro": "synthetic"}},
    {"method": "POST", "body": ""},
    {"method": "GET", "body": "get-with-body"},
    {"method": "POST", "json": {"chosen": True}, "form": {"ignored": "yes"}},
])
async def test_fetch_report_replays_recorded_request(receiver, arguments, tmp_path):
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if curl is None:
        pytest.skip("curl is required for the report replay integration check")
    address, received = receiver
    url = f"http://{address[0]}:{address[1]}/echo?original=kept"
    args = {"url": url, "timeout": 5, **arguments}
    manager = MCPLifecycleManager(VulnClawConfig())
    output = await manager._call_fetch(args)
    assert "Status: 200" in output
    original = received[-1]
    state = AgentState(origin=url, goal="Check local report export")
    state.remember_tool_result(tool="fetch", arguments=args, output=output)
    request, = extract_reproduction_requests(state)
    report = generate_solve_report(state, tmp_path / "report.md").read_bytes().decode("utf-8")
    assert "\r\r\n" not in report
    assert request.curl_command() in report
    assert request.request_packet() in report
    assert "response-only" in request.body

    arguments = shlex.split(request.curl_command())[1:]
    config = None
    if sys.platform == "win32":
        # Git's curl can replace Unicode argv with '?'. Keep the rendered values
        # unchanged and supply them as UTF-8 bytes through curl's config reader.
        config = _curl_config(arguments)
        arguments = ["--config", "-"]
    completed = subprocess.run(
        [curl, "--disable", *arguments, "--noproxy", "*", "--max-time", "5"],
        input=config, capture_output=True, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    from_curl = received[-1]
    # Check the raw HTTP example independently of curl's defaults and encoding.
    packet = request.request_packet()
    if "\r\n\r\n" not in packet and "\n\n" not in packet:
        packet += "\r\n\r\n"  # Historical header-only examples omit the terminator.
    with socket.create_connection(address, timeout=5) as client:
        client.sendall(packet.encode("utf-8"))
        while client.recv(4096):
            pass
    from_packet = received[-1]
    for replayed in (from_curl, from_packet):
        assert replayed[:2] == original[:2]
        assert replayed[3] == original[3]
        actual_headers = {k.lower(): v for k, v in replayed[2].items()}
        original_headers = {k.lower(): v for k, v in original[2].items()}
        for name in ("content-type", "x-repro"):
            assert actual_headers.get(name) == original_headers.get(name)


def test_old_or_invalid_fetch_arguments_keep_response_excerpt():
    for arguments in (
        {}, {"headers": ["invalid"]}, {"body": "contains\x00nul"},
        {"headers": {"Transfer-Encoding": "chunked"}, "body": "text"},
    ):
        state = AgentState(origin="https://example.test/", goal="Old evidence")
        state.remember_tool_result(
            tool="fetch", arguments=arguments,
            output="Request: GET https://example.test/?q=one\nStatus: 200\nBody (13):\nresponse-only",
        )
        request, = extract_reproduction_requests(state)
        assert request.url == "https://example.test/?q=one"
        assert request.body == "response-only"
        assert "response-only" not in request.curl_command()
        assert "response-only" not in request.request_packet()
        assert "incomplete" in request.replay_note


def test_reconstructed_request_uses_original_url_not_redirect_destination():
    state = AgentState(origin="https://example.test/", goal="Redirected fetch")
    state.remember_tool_result(
        tool="fetch", arguments={"url": "https://example.test/start", "params": {"q": "a b"}},
        output="Request: GET https://example.test/start\nFinal URL: https://example.test/end\n"
               "Status: 200\nBody (2):\nok",
    )
    request, = extract_reproduction_requests(state)
    parsed = urlsplit(request.url)
    assert parsed.path == "/start"
    assert parse_qs(parsed.query) == {"q": ["a b"]}


def test_report_marks_explicit_authentication_values_for_local_replacement():
    state = AgentState(origin="https://example.test/", goal="Recorded authentication")
    state.remember_tool_result(
        tool="fetch",
        arguments={"url": "https://example.test/", "headers": {
            "Authorization": "Bearer synthetic-secret", "X-Api-Key": "synthetic-key",
        }, "cookies": {"session": "synthetic-cookie"}},
        output="Request: GET https://example.test/\nStatus: 200\nBody (2):\nok",
    )
    request, = extract_reproduction_requests(state)
    report = render_solve_report(state)
    for secret in ("synthetic-secret", "synthetic-key", "synthetic-cookie"):
        assert secret not in report
    assert "<REDACTED>" in request.curl_command()
    assert "<REDACTED>" in request.request_packet()
    assert "Authentication headers" in report


@pytest.mark.parametrize("replacement", ["a longer body", "x", "", "你好", "O'Reilly\r\nnext"])
def test_edited_curl_body_uses_its_actual_length(receiver, replacement):
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if curl is None:
        pytest.skip("curl is required for the report replay integration check")
    address, received = receiver
    url = f"http://{address[0]}:{address[1]}/echo"
    state = AgentState(origin=url, goal="Edit an exported request")
    state.remember_tool_result(
        tool="fetch",
        arguments={"url": url, "method": "POST", "body": "original"},
        output=f"Request: POST {url}\nStatus: 200\nBody (2):\nok",
    )
    request, = extract_reproduction_requests(state)
    packet_before = request.request_packet()
    arguments = shlex.split(request.curl_command())[1:]
    arguments[arguments.index("--data-raw") + 1] = replacement
    config = None
    if sys.platform == "win32":
        config = _curl_config(arguments)
        arguments = ["--config", "-"]
    result = subprocess.run(
        [curl, "--disable", *arguments, "--noproxy", "*", "--max-time", "2"],
        input=config, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    _, _, headers, body = received[-1]
    assert body == replacement.encode("utf-8")
    assert int({k.lower(): v for k, v in headers.items()}["content-length"]) == len(body)
    # Generating an editable command must not mutate the raw recorded example.
    assert request.request_packet() == packet_before
    assert "content-length: 8\r\n" in packet_before
    assert packet_before.endswith("\r\n\r\noriginal")


@pytest.mark.parametrize("control", ["\r", "\n", "\r\n", "\x00"])
@pytest.mark.parametrize("location", ["name", "value", "cookie"])
def test_invalid_fetch_headers_are_not_exported(control, location):
    bad = f"before{control}X-Injected: yes"
    arguments = {"url": "https://example.test/", "method": "POST", "body": "original"}
    if location == "name":
        arguments["headers"] = {bad: "value"}
    elif location == "value":
        arguments["headers"] = {"X-Bad": bad}
    else:
        arguments["cookies"] = {"session": bad}
    state = AgentState(origin=arguments["url"], goal="Read malformed saved evidence")
    state.remember_tool_result(
        tool="fetch", arguments=arguments,
        output="Request: POST https://example.test/\nStatus: 200\nBody (13):\nresponse-only",
    )
    request, = extract_reproduction_requests(state)
    assert "incomplete" in request.replay_note
    assert request.body == "response-only"
    assert request.request_headers == {}
    assert request.request_body is None
    report = render_solve_report(state)
    assert "response-only" in report
    assert "X-Injected" not in report


def test_report_identifies_the_curl_shell():
    state = AgentState(origin="https://example.test/", goal="Export a request")
    state.remember_tool_result(
        tool="fetch", arguments={"url": state.origin},
        output="Request: GET https://example.test/\nStatus: 200\nBody (2):\nok",
    )
    assert "curl (Bash / POSIX shell):" in render_solve_report(state)
