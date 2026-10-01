#!/usr/bin/env python3
"""Loopback-only, offline fixtures for the copied application's license flow."""
import argparse
import hashlib
import json
import pathlib
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parent
PRODUCT_ID = "pdt_0NeAQjL4YEqzkukadjRUT"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        path = urlsplit(self.path).path
        size = int(self.headers.get("Content-Length", "0"))
        if size > 65536:
            self.send_error(413)
            return
        try:
            body = json.loads(self.rfile.read(size))
        except (ValueError, TypeError):
            self.send_error(400)
            return
        key = body.get("license_key", "")
        if not isinstance(key, str):
            self.send_error(400)
            return
        suffix = path.removeprefix("/localx")
        digest = hashlib.sha256(key.encode()).hexdigest()
        if suffix == "/licenses/activate":
            status = 201 if key else 400
            response = {"data": {"id": "lab_instance_" + digest[:16],
                                  "license_key_id": "lab_key_" + digest[:16],
                                  "product": {"product_id": PRODUCT_ID}}} if key else {"message": "Empty key"}
        elif suffix == "/licenses/validate":
            status, response = 200, {"valid": bool(key)}
        elif suffix == "/licenses/deactivate":
            status, response = 200, {"success": True}
        else:
            status, response = 404, {"message": "Unknown lab endpoint"}
        evidence = {"time": time.time(), "method": "POST", "path": path,
                    "field_names": sorted(body), "key_sha256": digest,
                    "key_length": len(key), "status": status}
        with self.server.evidence_path.open("a") as out:
            out.write(json.dumps(evidence) + "\n")
        payload = json.dumps(response).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        payload = b'{"service":"mole-offline-license-lab","ready":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=23949)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.evidence_path = ROOT / "evidence/license-lab-requests.jsonl"
    print(f"Offline license lab: http://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()
