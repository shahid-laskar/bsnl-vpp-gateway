"""Captive HTTP redirector (plan Phase 6, ADR-015).

Pre-auth tcp/80 that VPP's ABF policy steers to the gateway host is
redirected by nftables (``bsnl-vpp-portal.nft``) to this server, which answers
every request with ``302 Found`` to the fixed portal login URL.

- The Location never depends on the request (no Host/path reflection, so no
  header injection or open redirect).
- No HTTPS: TLS to arbitrary hosts cannot be intercepted (plan F-09); HTTPS
  before login fails, as documented.
- Bounded: at most ``--max-clients`` concurrent connections, a socket timeout
  per connection, ``Connection: close``; extra connections are closed.
- No per-request logging (subscriber privacy, volume).

    python3 -m controller.redirector --listen 198.51.100.2 --port 8080 \\
        --location https://wifi.bsnl.co.in/portal/login/
"""
from __future__ import annotations

import argparse
import html
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

LOG = logging.getLogger("bsnl_vpp.redirector")


def validate_location(location: str) -> str:
    parts = urlsplit(location)
    if parts.scheme not in {"http", "https"} or not parts.netloc or any(c in location for c in "\r\n\t "):
        raise ValueError(f"redirect location must be an absolute http(s) URL: {location!r}")
    return location


class RedirectHandler(BaseHTTPRequestHandler):
    server_version = "bsnl-captive-redirect"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 5

    def _redirect(self, with_body: bool = True) -> None:
        body = self.server.body
        self.send_response(302)
        self.send_header("Location", self.server.location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if with_body:
            self.wfile.write(body)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _redirect

    def do_HEAD(self) -> None:
        self._redirect(with_body=False)

    def log_message(self, *_args: Any) -> None:
        return


class RedirectServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], location: str, max_clients: int = 256) -> None:
        self.location = validate_location(location)
        link = html.escape(location, quote=True)
        self.body = (f'<!doctype html><title>Sign in</title><p>Sign in to continue: '
                     f'<a href="{link}">{link}</a></p>\n').encode()
        self._slots = threading.BoundedSemaphore(max_clients)
        super().__init__(address, RedirectHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", default="198.51.100.2")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--location", required=True)
    parser.add_argument("--max-clients", type=int, default=256)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    server = RedirectServer((args.listen, args.port), args.location, args.max_clients)
    LOG.info("redirecting HTTP on %s:%s to %s", args.listen, args.port, args.location)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
