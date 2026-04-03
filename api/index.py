"""Minimal Vercel-compatible API entrypoint."""

from flask import Flask, Response, jsonify


app = Flask(__name__)


@app.get("/")
def root():
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Security Monitor</title>
  <style>
    :root {
      --bg-1: #f4f8ff;
      --bg-2: #dbeafe;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #334155;
      --accent: #0b7285;
      --accent-2: #0f766e;
      --border: #cbd5e1;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Fira Sans", "Trebuchet MS", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 15% 20%, rgba(11, 114, 133, 0.14), transparent 34%),
        radial-gradient(circle at 85% 75%, rgba(15, 118, 110, 0.14), transparent 36%),
        linear-gradient(145deg, var(--bg-1), var(--bg-2));
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .panel {
      width: min(760px, 100%);
      background: color-mix(in srgb, var(--card) 88%, #ffffff);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 14px 40px rgba(15, 23, 42, 0.12);
    }
    h1 {
      margin: 0 0 8px;
      font-size: clamp(1.7rem, 4vw, 2.4rem);
      letter-spacing: 0.01em;
    }
    p {
      margin: 0 0 18px;
      color: var(--muted);
      line-height: 1.5;
    }
    .badge {
      display: inline-block;
      padding: 7px 11px;
      border-radius: 999px;
      background: rgba(11, 114, 133, 0.1);
      color: var(--accent);
      border: 1px solid rgba(11, 114, 133, 0.25);
      font-weight: 600;
      margin-bottom: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-top: 14px;
    }
    .item {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      background: rgba(255, 255, 255, 0.7);
    }
    .item strong { color: var(--accent-2); }
    code {
      background: #e2e8f0;
      padding: 2px 6px;
      border-radius: 6px;
    }
  </style>
</head>
<body>
  <main class="panel">
    <span class="badge">Serverless API Active</span>
    <h1>Network Security Monitor</h1>
    <p>
      This Vercel deployment provides lightweight API endpoints for status and
      integration checks. Live packet capture is not available in serverless runtime.
    </p>
    <div class="grid">
      <section class="item">
        <strong>Health Check</strong>
        <p>Use <code>/health</code> for uptime probes and platform monitoring.</p>
      </section>
      <section class="item">
        <strong>Live Monitoring</strong>
        <p>Run <code>main.py --live</code> on a VM/container with packet access.</p>
      </section>
    </div>
  </main>
</body>
</html>
"""
    return Response(html, mimetype="text/html")


@app.get("/health")
def health():
    return jsonify({"ok": True})
