#!/usr/bin/env bash
# Regenerates the PWA / favicon PNGs from the SVG sources in this folder.
# Requires rsvg-convert (librsvg). Run from anywhere: ./frontend/assets/icons/generate.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pub="$here/../../public/icons"
app="$here/../../app"
mkdir -p "$pub"
for s in 192 512; do
  rsvg-convert -w $s -h $s "$here/icon.svg" -o "$pub/icon-$s.png"
  rsvg-convert -w $s -h $s "$here/icon-maskable.svg" -o "$pub/icon-maskable-$s.png"
done
rsvg-convert -w 180 -h 180 "$here/icon-maskable.svg" -o "$app/apple-icon.png"   # iOS home screen (iOS rounds the corners)
cp "$here/icon.svg" "$app/icon.svg"                                               # favicon
echo "Icons written to $pub and $app"
node "$here/generate-splash.mjs"   # iOS launch screens (they embed icon.svg)
