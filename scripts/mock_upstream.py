#!/usr/bin/env python3
"""
Minimal mock upstream server for AbuseShield testing.

Accepts any HTTP method on any path and returns 200 OK with a JSON body.
Use this instead of `python3 -m http.server`, which rejects POST requests.

Usage:
    python3 scripts/mock_upstream.py [port]   (default port: 9090)
"""

import http.server
import json
import sys


class MockHandler(http.server.BaseHTTPRequestHandler):

    def _respond(self) -> None:
        body = json.dumps({
            "ok": True,
            "method": self.command,
            "path": self.path,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self)    -> None: self._respond()
    def do_POST(self)   -> None: self._respond()
    def do_PUT(self)    -> None: self._respond()
    def do_DELETE(self) -> None: self._respond()
    def do_PATCH(self)  -> None: self._respond()
    def do_HEAD(self)   -> None:
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:
        print(f"  [upstream] {self.address_string()} — {fmt % args}")


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    server = http.server.HTTPServer(("", port), MockHandler)
    print(f"Mock upstream listening on port {port}  (accepts all methods, always returns 200)")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
