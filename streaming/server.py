#!/usr/bin/env python3
"""
Minimal HTTP/1.1 progressive-download streaming server. Serves one video
file with Range-request support (Flask/Werkzeug's send_file(conditional=True))
so ffplay/VLC can stream it instead of waiting for a full download.

Run on h3: python3 server.py -- listens on 0.0.0.0:8000, logs each
request's Range header so you can watch the connection die when the RST
attack lands.
"""

import logging
import os
import sys

from flask import Flask, request, send_file, abort

VIDEO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "video.mp4")

app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.setLevel(logging.INFO)


@app.before_request
def log_request():
    rng = request.headers.get("Range", "-")
    print(f"[server] {request.remote_addr} {request.method} {request.path} Range={rng}", flush=True)


@app.route("/video.mp4")
def video():
    if not os.path.exists(VIDEO_PATH):
        abort(404, "video.mp4 not found -- run generate_video.sh first")
    return send_file(VIDEO_PATH, mimetype="video/mp4", conditional=True)


@app.route("/")
def index():
    return '<a href="/video.mp4">video.mp4</a>'


if __name__ == "__main__":
    if not os.path.exists(VIDEO_PATH):
        print(f"WARNING: {VIDEO_PATH} does not exist yet. Run generate_video.sh first.", file=sys.stderr)
    app.run(host="0.0.0.0", port=8000, threaded=True)
