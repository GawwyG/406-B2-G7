#!/bin/bash
# Generates a synthetic test video for the streaming demo -- no copyrighted
# footage needed, fully reproducible from code. Includes a burnt-in running
# timestamp/frame counter so it's immediately obvious on the client's screen
# when playback stalls or freezes (i.e. when the RST attack lands).

set -euo pipefail

OUT="${1:-video.mp4}"
DURATION="${2:-120}"   # seconds

ffmpeg -y \
  -f lavfi -i "testsrc=duration=${DURATION}:size=1280x720:rate=30" \
  -f lavfi -i "sine=frequency=440:duration=${DURATION}" \
  -vf "drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf:text='%{pts\\:hms}':x=30:y=30:fontsize=48:fontcolor=white:box=1:boxcolor=black@0.6" \
  -c:v libx264 -preset veryfast -pix_fmt yuv420p \
  -c:a aac -b:a 128k \
  -movflags +faststart \
  "$OUT"

echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
