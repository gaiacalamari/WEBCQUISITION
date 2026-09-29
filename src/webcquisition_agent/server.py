"""Server HTTP dell'agent (API v1).

* ascolta SOLO sull'IP della scheda host-only di controllo (vedi settings);
* ogni richiesta richiede ``Authorization: Bearer <token>`` (confronto a tempo costante);
* le risposte di errore hanno forma ``{"error": {"code": ..., "message": ...}}``;
* il download (``/v1/files/content``) è ammesso solo dopo il sigillo e solo per i
  file elencati nel manifest guest; il contenuto è inviato in streaming.
"""

from __future__ import annotations

import hmac
import json
import logging
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from webcquisition_common import PROTOCOL_VERSION
from webcquisition_common import protocol as P
from webcquisition_common.hashing import CHUNK_SIZE

from .session import AgentAPIError, Session

log = logging.getLogger("webcquisition.agent.http")


def make_handler(session: Session, token: str):
    expected = f"Bearer {token}".encode("utf-8")

    get_routes = {
        P.HEALTH: lambda q: session.health(),
        P.INTERFACES: lambda q: session.interfaces(),
        P.CAPTURE_STATUS: lambda q: session.capture_status(),
        P.STATUS: lambda q: session.status(),
        P.FILES: lambda q: session.list_files(),
    }
    post_routes = {
        P.SESSION_PREPARE: session.prepare,
        P.CAPTURE_START: session.capture_start,
        P.FIREFOX_START: session.firefox_start,
        P.UI_START: session.ui_start,
        P.SESSION_STOP: session.stop,
        P.SESSION_SEAL: lambda body: session.seal(),
        P.SESSION_RELEASE: lambda body: session.release(),
        P.SESSION_RECOVER: session.recover,
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "WEBCQUISITION-agent"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # noqa: A003 - API di BaseHTTPRequestHandler
            log.info("%s %s", self.client_address[0], fmt % args)

        def _send_json(self, status: int, payload: dict):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _error(self, status: int, code: str, message: str):
            self._send_json(status, {"error": {"code": code, "message": message}})

        def _authorized(self) -> bool:
            got = (self.headers.get(P.AUTH_HEADER) or "").encode("utf-8")
            if not hmac.compare_digest(got, expected):
                log.warning("richiesta non autenticata da %s: %s", self.client_address[0], self.path)
                self._error(401, "UNAUTHORIZED", "token mancante o non valido")
                return False
            proto = self.headers.get(P.PROTOCOL_HEADER)
            if proto is not None and proto != str(PROTOCOL_VERSION):
                self._error(400, "PROTOCOL_MISMATCH", f"protocollo {proto} non supportato (atteso {PROTOCOL_VERSION})")
                return False
            session.touch_host()
            return True

        def _dispatch(self, fn, *args):
            try:
                self._send_json(200, fn(*args))
            except AgentAPIError as exc:
                self._error(exc.status, exc.code, exc.message)
            except Exception as exc:  # noqa: BLE001 - mai far cadere il server
                log.exception("errore interno")
                self._error(500, "INTERNAL_ERROR", str(exc))

        def do_GET(self):  # noqa: N802
            if not self._authorized():
                return
            url = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(url.query)
            if url.path == P.FILES_CONTENT:
                return self._download(query)
            fn = get_routes.get(url.path)
            if fn is None:
                return self._error(404, "NOT_FOUND", url.path)
            self._dispatch(fn, query)

        def do_POST(self):  # noqa: N802
            if not self._authorized():
                return
            fn = post_routes.get(urllib.parse.urlsplit(self.path).path)
            if fn is None:
                return self._error(404, "NOT_FOUND", self.path)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._error(400, "BAD_REQUEST", "Content-Length non valido")
            if length > P.MAX_REQUEST_BODY:
                return self._error(413, "BODY_TOO_LARGE", "richiesta troppo grande")
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}") if length else {}
            except (ValueError, UnicodeDecodeError):
                return self._error(400, "BAD_JSON", "corpo JSON non valido")
            if not isinstance(body, dict):
                return self._error(400, "BAD_JSON", "atteso un oggetto JSON")
            self._dispatch(fn, body)

        def _download(self, query):
            rel = (query.get("path") or [""])[0]
            try:
                path, size = session.open_file(rel)
            except AgentAPIError as exc:
                return self._error(exc.status, exc.code, exc.message)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(path, "rb") as fh:
                while chunk := fh.read(CHUNK_SIZE):
                    self.wfile.write(chunk)

    return Handler


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def build_server(settings, session: Session, host: str | None = None, port: int | None = None) -> AgentServer:
    host = host if host is not None else settings.listen_host
    port = settings.listen_port if port is None else port
    return AgentServer((host, port), make_handler(session, settings.token))
