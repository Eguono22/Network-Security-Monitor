"""Minimal Vercel-compatible API entrypoint.

This exposes a lightweight health endpoint so the repository can deploy on
Vercel's Python runtime. Live packet capture is not supported in Vercel's
serverless environment.
"""

from flask import Flask, jsonify


app = Flask(__name__)


@app.get("/")
def root():
    return jsonify(
        {
            "service": "network-security-monitor",
            "status": "ok",
            "mode": "serverless-api",
            "note": "Live packet capture is not available on Vercel.",
        }
    )


@app.get("/health")
def health():
    return jsonify({"ok": True})
