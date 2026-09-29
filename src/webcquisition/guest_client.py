"""Client host -> guest agent.

Canale di controllo: HTTP con token bearer su una scheda di rete *host-only*
DEDICATA, distinta dalla scheda su cui avviene la cattura (vedi
docs/ARCHITECTURE.md §9). Il traffico di controllo quindi non contamina il PCAPNG.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from webcquisition_common import PROTOCOL_VERSION
from webcquisition_common import protocol as P
from webcquisition_common.hashing import CHUNK_SIZE, StreamingHasher


class AgentUnreachable(RuntimeError):
    """Il guest agent non risponde (VM non pronta, rete di controllo assente, VM bloccata...)."""


class AgentError(RuntimeError):
    """Il guest agent ha risposto con un errore applicativo."""

    def __init__(self, code: str, message: str, status: int = 0):
        self.code = code
        self.status = status
        super().__init__(f"{code}: {message}")


class GuestClient:
    """Interfaccia comune a client HTTP reale e client fittizio."""

    def health(self) -> dict: raise NotImplementedError
    def prepare(self, request: dict) -> dict: raise NotImplementedError
    def interfaces(self) -> dict: raise NotImplementedError
    def capture_start(self, request: dict) -> dict: raise NotImplementedError
    def capture_status(self) -> dict: raise NotImplementedError
    def firefox_start(self, request: dict) -> dict: raise NotImplementedError
    def ui_start(self, request: dict) -> dict: raise NotImplementedError
    def status(self) -> dict: raise NotImplementedError
    def stop(self, request: dict) -> dict: raise NotImplementedError
    def seal(self) -> dict: raise NotImplementedError
    def list_files(self) -> dict: raise NotImplementedError
    def release(self) -> dict: raise NotImplementedError
    def recover(self, request: dict) -> dict: raise NotImplementedError

    def download(self, rel_path: str, dest: Path) -> tuple[str, int]:
        """Scarica un file in ``dest`` restituendo (sha256, size) calcolati in streaming."""
        raise NotImplementedError


class HttpGuestClient(GuestClient):
    def __init__(self, base_url: str, token: str, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout

    def _open(self, method: str, path: str, body: dict | None = None, timeout: float | None = None):
        data = json.dumps(body or {}).encode("utf-8") if method == "POST" else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header(P.AUTH_HEADER, f"Bearer {self._token}")
        req.add_header(P.PROTOCOL_HEADER, str(PROTOCOL_VERSION))
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            return urllib.request.urlopen(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
                err = payload.get("error", {})
                raise AgentError(err.get("code", "HTTP_ERROR"), err.get("message", str(exc)), exc.code) from exc
            except (ValueError, AttributeError):
                raise AgentError("HTTP_ERROR", str(exc), exc.code) from exc
        except (urllib.error.URLError, ConnectionError, socket.timeout, TimeoutError, OSError) as exc:
            raise AgentUnreachable(f"agent non raggiungibile su {self.base_url}: {exc}") from exc

    def _json(self, method: str, path: str, body: dict | None = None, timeout: float | None = None) -> dict:
        with self._open(method, path, body, timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def health(self): return self._json("GET", P.HEALTH, timeout=min(self.timeout, 10))
    def prepare(self, request): return self._json("POST", P.SESSION_PREPARE, request, timeout=120)
    def interfaces(self): return self._json("GET", P.INTERFACES, timeout=60)
    def capture_start(self, request): return self._json("POST", P.CAPTURE_START, request)
    def capture_status(self): return self._json("GET", P.CAPTURE_STATUS)
    def firefox_start(self, request): return self._json("POST", P.FIREFOX_START, request)
    def ui_start(self, request): return self._json("POST", P.UI_START, request)
    def status(self): return self._json("GET", P.STATUS)
    def stop(self, request): return self._json("POST", P.SESSION_STOP, request, timeout=300)
    def seal(self): return self._json("POST", P.SESSION_SEAL, timeout=3600)
    def list_files(self): return self._json("GET", P.FILES)
    def release(self): return self._json("POST", P.SESSION_RELEASE, {})
    def recover(self, request): return self._json("POST", P.SESSION_RECOVER, request, timeout=120)

    def download(self, rel_path: str, dest: Path) -> tuple[str, int]:
        q = urllib.parse.urlencode({"path": rel_path})
        hasher = StreamingHasher()
        with self._open("GET", f"{P.FILES_CONTENT}?{q}", timeout=max(self.timeout, 120)) as resp, open(dest, "xb") as out:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        return hasher.hexdigest(), hasher.size
