"""Local REST API: ``email-forensics serve``.

    GET  /                      web UI (static, self-contained; strict CSP; plain upload form without JavaScript)
    GET  /api/v1/health         {"status": "ok", "version": ..., "auth_required": ..., "features": {...}}
    POST /api/v1/analyze        report for the uploaded message(s); ?format=json|html|text|summary|jsonl|cef|bundle
    POST /api/v1/iocs           indicators of the uploaded message(s); ?format=stix|misp|csv

The body is either the raw .eml/.msg/mbox bytes or ``multipart/form-data`` with a
``file`` field. Uploads are analysed in memory and never written to disk.

Security: the server binds to 127.0.0.1 by default and refuses any other address
unless an API token is configured (``EMAIL_FORENSICS_API_TOKEN``); with a token every
request except the health check needs ``Authorization: Bearer <token>`` (or a
``token`` form field from the upload page). Requests larger than ``--max-upload``
are rejected with 413. Connections are handled concurrently, but analyses run one
at a time on the main thread, so the per-message timeout (SIGALRM) applies and memory
stays bounded. Put a reverse proxy in front for TLS.
"""

from __future__ import annotations

import hmac
import importlib.resources
import ipaddress
import queue
import threading
import json
import re
import sys
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from . import __version__
from .analyzer import AnalysisOptions, analyze_bytes
from .iocs import extract_iocs, to_csv, to_misp, to_stix
from .loader import EvidenceError
from .report import summary_row, to_text
from .report_html import render_html
from .siem import to_cef, to_jsonl

DEFAULT_MAX_UPLOAD = 50 * 1024 * 1024
TOKEN_ENV = "EMAIL_FORENSICS_API_TOKEN"
_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
# The web UI loads only its own script and stylesheet; everything it shows is inserted as text.
_APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
REPORT_FORMATS = ("json", "html", "text", "summary", "jsonl", "cef", "bundle")
_STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
           "/static/app.css": ("app.css", "text/css; charset=utf-8"),
           "/static/favicon.svg": ("favicon.svg", "image/svg+xml")}
IOC_FORMATS = ("stix", "misp", "csv")


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _static(name: str) -> bytes:
    return importlib.resources.files("email_forensics").joinpath("web", name).read_bytes()


def parse_multipart(content_type: str, body: bytes) -> tuple[bytes | None, str | None, dict[str, str]]:
    """Return (file bytes, filename, other form fields) from a multipart/form-data body.

    A byte-exact splitter (RFC 7578): the email package would re-interpret a part sent as
    message/rfc822 or with a Content-Transfer-Encoding, and evidence must arrive unchanged."""
    m = re.search(r'boundary=(?:"([^"]{1,200})"|([^\s;]{1,200}))', content_type, re.I)
    if not m:
        raise HttpError(400, "multipart body without a boundary")
    delimiter = b"--" + (m.group(1) or m.group(2)).encode("latin-1", "replace")
    chunks = (b"\r\n" + body).split(b"\r\n" + delimiter)  # chunks[0] is the (ignored) preamble
    if len(chunks) < 2:
        raise HttpError(400, "malformed multipart body")
    data = filename = None
    fields: dict[str, str] = {}
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            break  # closing delimiter
        head, sep, payload = chunk.partition(b"\r\n\r\n")
        head = head.split(b"\r\n", 1)[-1] if b"\r\n" in head else b""  # drop the rest of the delimiter line
        if not sep:
            raise HttpError(400, "malformed multipart part")
        disposition = next((line.decode("utf-8", "replace") for line in head.split(b"\r\n")
                            if line.lower().startswith(b"content-disposition:")), "")
        params = dict((k.lower(), v if v is not None else w) for k, v, w in
                      re.findall(r';\s*([\w*-]+)=(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))', disposition))
        name = params.get("name")
        if name == "file" and data is None:
            data, filename = payload, params.get("filename")
        elif name and len(payload) < 4096:
            fields[name] = payload.decode("utf-8", "replace").strip()
    return data, filename, fields


def _header_filename(value: str | None) -> str | None:
    """X-Filename as sent by the web UI (percent-encoded UTF-8, since browsers only allow Latin-1
    in headers) or by curl (raw UTF-8, which http.server hands over decoded as Latin-1)."""
    if not value:
        return None
    try:
        value = value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return unquote(value, errors="replace")


def _label(filename: str | None) -> str:
    """A safe evidence label from a client-supplied file name (it is display-only, never a path).

    Keeps the name readable ("Invoice – May, final.eml") but drops any directory part, characters
    Windows forbids in file names, and control/format characters (bidi overrides, zero-width
    spaces) that could disguise the name."""
    name = re.split(r"[\\/]", filename or "")[-1]
    name = "".join("_" if c in '<>:"|?*' or unicodedata.category(c)[0] == "C" else c for c in name)
    name = re.sub(r"\s+", " ", name)[:120].strip(" ._")
    return f"upload:{name or 'message'}"


class ForensicsHandler(BaseHTTPRequestHandler):
    server_version = f"email-forensics/{__version__}"
    timeout = 60  # seconds a slow client may take per socket operation
    protocol_version = "HTTP/1.1"

    # -- responses
    def _send(self, status: int, body: str | bytes, content_type: str, extra: dict | None = None,
              csp: str = _CSP) -> None:
        data = body.encode("utf-8", "backslashreplace") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, indent=2, ensure_ascii=False), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        extra = {"WWW-Authenticate": 'Bearer realm="email-forensics"'} if status == 401 else None
        if status >= 400:
            self.close_connection = True
        body = json.dumps({"error": message})
        self._send(status, body, "application/json; charset=utf-8", extra)

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, fmt: str, *args) -> None:
        if not self.server.quiet:
            sys.stderr.write(f"{self.address_string()} [{self.log_date_time_string()}] {fmt % args}\n")

    # -- auth and input
    def _authorized(self, fields: dict[str, str] | None = None) -> bool:
        token = self.server.token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        offered = header[7:].strip() if header[:7].lower() == "bearer " else (fields or {}).get("token", "")
        return hmac.compare_digest(offered.encode("utf-8", "replace"), token.encode("utf-8"))

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise HttpError(411, "chunked uploads are not supported; send Content-Length")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise HttpError(411, "Content-Length required") from None
        if length < 0:
            raise HttpError(400, "bad Content-Length")
        if length > self.server.max_upload:
            raise HttpError(413, f"upload larger than {self.server.max_upload} bytes")
        data = self.rfile.read(length)
        if len(data) != length:
            raise HttpError(400, "request body truncated")
        return data

    def _upload(self) -> tuple[bytes, str, dict[str, str]]:
        body = self._read_body()
        ctype = self.headers.get("Content-Type", "")
        if ctype.lower().startswith("multipart/form-data"):
            data, filename, fields = parse_multipart(ctype, body)
            if not data:
                raise HttpError(400, "no file in the form")
        else:
            data, fields = body, {}
            filename = _header_filename(self.headers.get("X-Filename"))
        if not self._authorized(fields):
            raise HttpError(401, "missing or wrong API token")
        if not data:
            raise HttpError(400, "empty upload")
        return data, _label(filename), fields

    # -- routes
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/v1/health":
            return self._json(200, {"status": "ok", "version": __version__, "auth_required": bool(self.server.token),
                                    "max_upload": self.server.max_upload, "features": self.server.features()})
        if path in _STATIC:
            name, ctype = _STATIC[path]
            return self._send(200, _static(name), ctype, csp=_APP_CSP)
        if path.startswith("/api/"):
            return self._error(405 if path in ("/api/v1/analyze", "/api/v1/iocs") else 404, "not found")
        return self._error(404, "not found")

    def do_POST(self) -> None:
        url = urlsplit(self.path)
        if url.path not in ("/api/v1/analyze", "/api/v1/iocs"):
            return self._error(404, "not found")
        # Check the header token before reading a body, so unauthenticated clients cannot make us buffer uploads.
        if self.server.token and self.headers.get("Authorization") and not self._authorized():
            return self._error(401, "missing or wrong API token")
        try:
            data, label, fields = self._upload()
            query = {k: v[-1] for k, v in parse_qs(url.query).items()}
            if url.path == "/api/v1/analyze":
                fmt = query.get("format") or fields.get("format") or "json"
                if fmt not in REPORT_FORMATS:
                    raise HttpError(400, f"format must be one of {', '.join(REPORT_FORMATS)}")
            else:
                fmt = query.get("format") or fields.get("format") or "stix"
                if fmt not in IOC_FORMATS:
                    raise HttpError(400, f"format must be one of {', '.join(IOC_FORMATS)}")
            started = time.monotonic()
            try:
                reports = self.server.analyze(label, data)
            except EvidenceError as exc:
                raise HttpError(422, str(exc)) from None
            if not reports:
                raise HttpError(422, "no messages found in the upload")
        except HttpError as exc:
            return self._error(exc.status, str(exc))
        self.server.analyzed += len(reports)
        if url.path == "/api/v1/iocs":
            indicators = [i for r in reports for i in extract_iocs(r)]
            if fmt == "csv":
                return self._send(200, to_csv(indicators), "text/csv; charset=utf-8")
            return self._send(200, to_stix(indicators, reports) if fmt == "stix" else to_misp(indicators, reports),
                              "application/json; charset=utf-8")
        if fmt == "html":
            return self._send(200, render_html(reports), "text/html; charset=utf-8")
        if fmt == "text":
            return self._send(200, "\n\n".join(to_text(r) for r in reports), "text/plain; charset=utf-8")
        if fmt == "summary":
            return self._json(200, [summary_row(r) for r in reports])
        if fmt == "jsonl":
            return self._send(200, to_jsonl(reports) + "\n", "application/x-ndjson; charset=utf-8")
        if fmt == "cef":
            return self._send(200, to_cef(reports) + "\n", "text/plain; charset=utf-8")
        if fmt == "bundle":  # what the web UI uses: reports plus their indicators
            items = []
            for r in reports:
                d = r.to_dict()
                d["indicators"] = [vars(i) for i in extract_iocs(r)]
                items.append(d)
            return self._json(200, {"reports": items, "elapsed_ms": round((time.monotonic() - started) * 1000)})
        return self._json(200, reports[0].to_dict() if len(reports) == 1 else [r.to_dict() for r in reports])


class ForensicsServer(ThreadingHTTPServer):
    """Connections are handled in threads (browsers open several at once and keep idle ones open),
    but analyses run one at a time on the thread that called serve(): the per-message timeout uses
    SIGALRM, which only works in the main thread, and one analysis at a time bounds memory use."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], options: AnalysisOptions | None = None, token: str | None = None,
                 max_upload: int = DEFAULT_MAX_UPLOAD, quiet: bool = False):
        host = address[0]
        if not is_loopback(host) and not token:
            raise ValueError(f"refusing to listen on {host} without an API token (set {TOKEN_ENV})")
        if token is not None and len(token) < 16:
            raise ValueError("API token must be at least 16 characters")
        self.options = options or AnalysisOptions()
        self.token = token
        self.max_upload = max_upload
        self.quiet = quiet
        self.analyzed = 0
        self._jobs: queue.Queue | None = None  # set while serve() runs the analysis loop
        self._lock = threading.Lock()  # analyses never overlap, even without serve()
        if ":" in host:
            import socket
            self.address_family = socket.AF_INET6
        super().__init__((host.strip("[]"), address[1]), ForensicsHandler)

    def features(self) -> dict:
        o = self.options
        return {"dns": o.resolver is not None, "enrichment": o.enricher is not None,
                "yara": o.yara_rules is not None, "custom_rules": len(o.custom_rules or []),
                "protected_domains": len(o.protected_domains or []), "timeout": o.timeout}

    def analyze(self, label: str, data: bytes) -> list:
        jobs = self._jobs
        if jobs is None or threading.current_thread() is threading.main_thread():
            with self._lock:
                return analyze_bytes(label, data, self.options)
        done = threading.Event()
        box: dict = {}
        jobs.put((label, data, box, done))
        done.wait()
        if "error" in box:
            raise box["error"]
        return box["reports"]

    def serve(self) -> None:
        """Serve until KeyboardInterrupt: HTTP in a background thread, analyses on this thread."""
        self._jobs = queue.Queue()
        http = threading.Thread(target=self.serve_forever, daemon=True)
        http.start()
        try:
            while True:
                try:
                    label, data, box, done = self._jobs.get(timeout=0.5)
                except queue.Empty:
                    continue
                try:
                    with self._lock:
                        box["reports"] = analyze_bytes(label, data, self.options)
                except BaseException as exc:  # handed to the waiting request thread
                    box["error"] = exc
                    if isinstance(exc, KeyboardInterrupt):
                        raise
                finally:
                    done.set()
        finally:
            self._jobs = None
            self.shutdown()
