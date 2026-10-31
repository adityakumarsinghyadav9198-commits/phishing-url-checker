#!/usr/bin/env python3
"""Serve the URL checker as a small browser app on the local machine."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from phishing_checker import analyze_url


MAX_REQUEST_BYTES = 16_384
HTML_PATH = Path(__file__).parent / "web" / "index.html"


class CheckerRequestHandler(BaseHTTPRequestHandler):
    """Serve the interface and locally analyze submitted URL text."""

    def do_GET(self) -> None:
        if urlsplit(self.path).path not in {"/", "/index.html"}:
            self.send_error(404)
            return

        try:
            page = HTML_PATH.read_bytes()
        except OSError:
            self.send_error(500, "The web interface could not be loaded.")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/api/analyze":
            self._send_json({"error": "Not found."}, status=404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"error": "Invalid request length."}, status=400)
            return

        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            self._send_json({"error": "Request body is empty or too large."}, status=400)
            return

        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"error": "Request body must be valid JSON."}, status=400)
            return

        if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
            self._send_json({"error": "Provide the URL as a string."}, status=400)
            return

        self._send_json(analyze_url(payload["url"]))

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    """Create the local HTTP server; useful for the CLI and integration tests."""
    return ThreadingHTTPServer((host, port), CheckerRequestHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the URL checker in a browser.")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="port to use (default: 8000)")
    args = parser.parse_args()

    server = create_server(args.host, args.port)
    print(f"Checker ready at http://{args.host}:{server.server_port}")
    print("Press Ctrl+C to stop the local server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()