#!/usr/bin/env python3
"""
MR OSINT — Media Toolkit (Image & Video OSINT)
Copyright (c) 2026 Harsh Saini — MR CYBER
Website: https://mrcyberharsh.github.io/mrcyber/
Contact: cyber.h4rsh@zohomail.in

All rights reserved. You may use and modify this script for personal
and educational purposes. Do not redistribute as your own work without
credit to the original author.

--------------------------------------------------------------------

A dedicated toolkit for image and video OSINT — separate from the main
mr_osint_toolkit.py, focused entirely on media files.

WHAT THIS TOOL DOES:
  - Extracts EXIF/metadata from images (camera, timestamps, software)
  - Extracts metadata from videos (via ffprobe — codec, duration,
    creation date, device info if embedded)
  - Finds embedded GPS coordinates and reverse-geocodes them to a
    human-readable address (via OpenStreetMap's free Nominatim API)
  - Generates a Google Maps link and an offline HTML map for any GPS
    points found
  - Calculates file hashes (MD5/SHA1/SHA256) for verification/correlation
  - Generates reverse-image-search links (Google/Yandex/TinEye/Bing) —
    does NOT perform the search itself or identify anyone
  - Flags basic re-save/editing indicators (multiple software tags,
    missing expected camera fields)
  - Can strip metadata from images and save a clean copy

WHAT THIS TOOL DELIBERATELY DOES NOT DO:
  - It does not identify who is IN a photo (no facial recognition).
  - It does not perform reverse image searches for you — it only
    generates the search URLs, which you open yourself if you choose.
  - It only reads metadata already embedded in a file you have — it
    doesn't fetch anything about a person from the internet.
  This boundary is intentional and applies regardless of how a request
  to extend this tool is framed.

Install (optional, for full functionality):
    pip install Pillow requests
    # ffprobe (from ffmpeg) is used for video metadata if installed on your system

Usage:
    python mr_osint_media.py <file or folder>
    python mr_osint_media.py photo.jpg --geocode
    python mr_osint_media.py ./photos --recursive --map --html
    python mr_osint_media.py photo.jpg --strip
    python mr_osint_media.py photo.jpg --reverse-search
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from html import escape
from urllib.parse import quote

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS, IFD
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


BANNER = r"""
+================================================================+
|                                                                |
|          M R   O S I N T   -   M E D I A   T O O L K I T       |
|                                                                |
|            by Harsh Saini  |  Cybersecurity & OSINT            |
|            https://mrcyberharsh.github.io/mrcyber/             |
|                                                                |
+================================================================+
"""

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp", ".heic"}
VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v", ".3gp"}

# EXIF fields whose ABSENCE hints a file was re-saved/edited rather than
# straight off a camera — not proof, just a lead worth noting.
EXPECTED_CAMERA_FIELDS = {"Make", "Model", "DateTimeOriginal", "FNumber", "ExposureTime"}
EDITING_SOFTWARE_HINTS = ["photoshop", "gimp", "lightroom", "snapseed", "picsart", "canva", "paint.net"]


# ---------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------

def compute_hashes(path):
    hashers = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hashers.items()}, None
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------
# GPS helpers
# ---------------------------------------------------------------------

def dms_to_decimal(dms, ref):
    try:
        degrees, minutes, seconds = [float(x) for x in dms]
    except (TypeError, ValueError):
        return None
    dd = degrees + minutes / 60.0 + seconds / 3600.0
    if ref in ("S", "W"):
        dd = -dd
    return dd


def reverse_geocode(lat, lon):
    """Uses OpenStreetMap's free Nominatim API — no key required, but
    rate-limited and asks for a descriptive User-Agent, which we provide."""
    if not HAVE_REQUESTS:
        return None, "requests not installed — run: pip install requests"
    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json"},
            headers={"User-Agent": "MR-OSINT-Media-Toolkit (cyber.h4rsh@zohomail.in)"},
            timeout=10,
        )
        data = resp.json()
        if "display_name" in data:
            return data["display_name"], None
        return None, data.get("error", "No address found for these coordinates.")
    except Exception as e:
        return None, f"Reverse geocoding failed: {e}"


# ---------------------------------------------------------------------
# Image metadata
# ---------------------------------------------------------------------

def extract_image_metadata(path):
    if not HAVE_PIL:
        return None, "Pillow isn't installed. Run: pip install Pillow"
    try:
        img = Image.open(path)
    except Exception as e:
        return None, f"Could not open image: {e}"

    result = {
        "format": img.format, "size": f"{img.size[0]}x{img.size[1]}", "mode": img.mode,
        "exif": {}, "gps": None, "editing_flags": [],
    }

    try:
        exif = img.getexif()
        for tag_id, value in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                continue
            if isinstance(value, bytes):
                if len(value) > 80:
                    continue
                value = value.decode(errors="replace")
            result["exif"][str(tag)] = value

        gps_raw = {}
        try:
            gps_ifd = exif.get_ifd(IFD.GPSInfo)
            for gps_id, gps_val in gps_ifd.items():
                gps_raw[GPSTAGS.get(gps_id, gps_id)] = gps_val
        except Exception:
            pass

        if "GPSLatitude" in gps_raw and "GPSLongitude" in gps_raw:
            lat = dms_to_decimal(gps_raw["GPSLatitude"], gps_raw.get("GPSLatitudeRef", "N"))
            lon = dms_to_decimal(gps_raw["GPSLongitude"], gps_raw.get("GPSLongitudeRef", "E"))
            if lat is not None and lon is not None:
                result["gps"] = {
                    "lat": round(lat, 6), "lon": round(lon, 6),
                    "maps_url": f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}",
                }
    except Exception:
        pass

    # editing/re-save heuristics
    software = result["exif"].get("Software", "")
    if software:
        for hint in EDITING_SOFTWARE_HINTS:
            if hint in software.lower():
                result["editing_flags"].append(f"Software tag mentions '{software}' — image may have been edited.")
                break
    present_fields = set(result["exif"].keys())
    missing = EXPECTED_CAMERA_FIELDS - present_fields
    if result["exif"] and len(missing) >= 4:
        result["editing_flags"].append(
            "Most standard camera fields (Make/Model/exposure info) are missing — "
            "this often happens when an image is re-saved, screenshotted, or downloaded "
            "from social media (which strips EXIF), rather than being a direct camera original."
        )

    return result, None


def strip_image_metadata(path, output_path):
    if not HAVE_PIL:
        return False, "Pillow isn't installed. Run: pip install Pillow"
    try:
        img = Image.open(path)
        img.save(output_path)
        return True, None
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------
# Video metadata (via ffprobe)
# ---------------------------------------------------------------------

def extract_video_metadata(path):
    try:
        proc = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", path],
            capture_output=True, text=True, timeout=20,
        )
    except FileNotFoundError:
        return None, "ffprobe not found — install ffmpeg (which includes ffprobe) to read video metadata."
    except Exception as e:
        return None, f"Could not run ffprobe: {e}"

    if proc.returncode != 0:
        return None, f"ffprobe failed: {proc.stderr.strip()[:200]}"

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, "Could not parse ffprobe output."

    fmt = data.get("format", {})
    tags = fmt.get("tags", {})
    video_stream = next((s for s in data.get("streams", []) if s.get("codec_type") == "video"), {})

    result = {
        "duration_sec": fmt.get("duration"),
        "size_bytes": fmt.get("size"),
        "format_name": fmt.get("format_long_name"),
        "codec": video_stream.get("codec_name"),
        "resolution": f"{video_stream.get('width')}x{video_stream.get('height')}" if video_stream.get("width") else None,
        "creation_time": tags.get("creation_time"),
        "device_make": tags.get("com.apple.quicktime.make") or tags.get("make"),
        "device_model": tags.get("com.apple.quicktime.model") or tags.get("model"),
        "gps": None,
    }

    # some phone-recorded videos (notably iPhone .mov) embed GPS as a plain string tag
    gps_str = tags.get("com.apple.quicktime.location.ISO6709")
    if gps_str:
        m = re.match(r"([+\-]\d+\.\d+)([+\-]\d+\.\d+)", gps_str)
        if m:
            lat, lon = float(m.group(1)), float(m.group(2))
            result["gps"] = {
                "lat": round(lat, 6), "lon": round(lon, 6),
                "maps_url": f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}",
            }

    return result, None


# ---------------------------------------------------------------------
# Reverse image search links
# ---------------------------------------------------------------------

def reverse_search_links(path):
    """Generates search URLs only — does not upload or search anything itself.
    Google/Yandex/TinEye don't offer a simple URL-based reverse search for a
    LOCAL file without uploading it first, so these links open the tool ready
    for you to drop the file in yourself, except where a direct method exists."""
    abs_path = os.path.abspath(path)
    return {
        "Google Images": "https://images.google.com/",
        "Yandex Images": "https://yandex.com/images/",
        "TinEye": "https://tineye.com/",
        "Bing Visual Search": "https://www.bing.com/visualsearch",
    }, abs_path


# ---------------------------------------------------------------------
# HTML map generation
# ---------------------------------------------------------------------

def build_map_html(points):
    """points: list of (label, lat, lon). Uses Leaflet + OpenStreetMap tiles
    (needs internet to actually view the map tiles, same as any web map)."""
    markers_js = ",\n".join(
        f'    L.marker([{lat}, {lon}]).addTo(map).bindPopup({json.dumps(label)})'
        for label, lat, lon in points
    )
    center_lat = sum(p[1] for p in points) / len(points)
    center_lon = sum(p[2] for p in points) / len(points)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>MR OSINT — Media Geolocation Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
  body {{ margin:0; font-family:sans-serif; background:#0a0a0a; }}
  #map {{ height:90vh; }}
  .header {{ background:#0F6E56; color:#fff; padding:14px 20px; font-size:18px; font-weight:700; }}
  .footer {{ background:#111; color:#8fa898; text-align:center; padding:8px; font-size:12px; }}
</style>
</head>
<body>
  <div class="header">MR OSINT — Media Geolocation Map ({len(points)} point(s))</div>
  <div id="map"></div>
  <div class="footer">Generated by MR OSINT — Harsh Saini / MR CYBER · cyber.h4rsh@zohomail.in</div>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    const map = L.map('map').setView([{center_lat}, {center_lon}], 12);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      attribution: '&copy; OpenStreetMap contributors'
    }}).addTo(map);
{markers_js}
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------

def process_file(path, args, collected_gps_points):
    ext = os.path.splitext(path)[1].lower()
    print(f"\n  {path}")
    print("  " + "-" * 58)

    hashes, hash_err = compute_hashes(path)
    if hashes:
        print(f"    SHA256: {hashes['SHA256']}")
    else:
        print(f"    Hash error: {hash_err}")

    if ext in IMAGE_EXTS:
        data, err = extract_image_metadata(path)
        if err:
            print(f"    Error: {err}")
            return
        print(f"    Format: {data['format']}  |  Size: {data['size']}  |  Mode: {data['mode']}")
        if data["exif"]:
            for k in ("Make", "Model", "DateTimeOriginal", "Software"):
                if k in data["exif"]:
                    print(f"    {k}: {data['exif'][k]}")
        if data["editing_flags"]:
            for flag in data["editing_flags"]:
                print(f"    ⚠ {flag}")
        if data["gps"]:
            lat, lon = data["gps"]["lat"], data["gps"]["lon"]
            print(f"    ⚠ GPS found: {lat}, {lon}")
            print(f"      Maps: {data['gps']['maps_url']}")
            collected_gps_points.append((os.path.basename(path), lat, lon))
            if args.geocode:
                address, geo_err = reverse_geocode(lat, lon)
                if address:
                    print(f"      Address: {address}")
                else:
                    print(f"      Reverse geocoding failed: {geo_err}")
        else:
            print("    GPS: none found")

        if args.strip:
            out_path = os.path.splitext(path)[0] + "_stripped" + ext
            ok, strip_err = strip_image_metadata(path, out_path)
            print(f"    ✓ Stripped copy saved: {out_path}" if ok else f"    Strip failed: {strip_err}")

    elif ext in VIDEO_EXTS:
        data, err = extract_video_metadata(path)
        if err:
            print(f"    {err}")
            return
        if data["duration_sec"]:
            print(f"    Duration: {float(data['duration_sec']):.1f}s  |  Resolution: {data['resolution']}  |  Codec: {data['codec']}")
        if data["creation_time"]:
            print(f"    Creation time: {data['creation_time']}")
        if data["device_make"] or data["device_model"]:
            print(f"    Device: {data['device_make'] or ''} {data['device_model'] or ''}".strip())
        if data["gps"]:
            lat, lon = data["gps"]["lat"], data["gps"]["lon"]
            print(f"    ⚠ GPS found: {lat}, {lon}")
            print(f"      Maps: {data['gps']['maps_url']}")
            collected_gps_points.append((os.path.basename(path), lat, lon))
            if args.geocode:
                address, geo_err = reverse_geocode(lat, lon)
                if address:
                    print(f"      Address: {address}")
                else:
                    print(f"      Reverse geocoding failed: {geo_err}")
        else:
            print("    GPS: none found")

    else:
        print(f"    Unsupported file type ({ext})")
        return

    if args.reverse_search:
        links, abs_path = reverse_search_links(path)
        print(f"    Reverse image search (open manually, upload {os.path.basename(path)}):")
        for name, url in links.items():
            print(f"      {name}: {url}")


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="mr_osint_media.py",
        description="MR OSINT — Media Toolkit: metadata, geotagging, and hashing for images and videos.",
    )
    parser.add_argument("path", help="A file or folder to scan")
    parser.add_argument("--recursive", action="store_true", help="If path is a folder, scan subfolders too")
    parser.add_argument("--strip", action="store_true", help="Save a metadata-stripped copy of any images found")
    parser.add_argument("--geocode", action="store_true", help="Reverse-geocode any GPS coordinates found into a readable address (needs internet)")
    parser.add_argument("--reverse-search", action="store_true", help="Print reverse-image-search links for each image (does not search automatically)")
    parser.add_argument("--map", action="store_true", help="Generate an HTML map (map_report.html) of all GPS points found")
    args = parser.parse_args()

    if not HAVE_PIL:
        print("[!] Pillow not installed — image metadata will be skipped. Run: pip install Pillow")
    if args.geocode and not HAVE_REQUESTS:
        print("[!] requests not installed — --geocode needs it. Run: pip install requests")

    targets = []
    if os.path.isdir(args.path):
        if args.recursive:
            for root, _, files in os.walk(args.path):
                for fname in files:
                    targets.append(os.path.join(root, fname))
        else:
            targets = [os.path.join(args.path, f) for f in os.listdir(args.path) if os.path.isfile(os.path.join(args.path, f))]
    elif os.path.isfile(args.path):
        targets = [args.path]
    else:
        print(f"\nPath not found: {args.path}")
        return

    supported = IMAGE_EXTS | VIDEO_EXTS
    targets = [t for t in targets if os.path.splitext(t)[1].lower() in supported]

    if not targets:
        print("\nNo supported image/video files found.")
        return

    print(f"\nFound {len(targets)} supported file(s).")
    gps_points = []
    for t in targets:
        process_file(t, args, gps_points)

    if args.map:
        if gps_points:
            html = build_map_html(gps_points)
            with open("map_report.html", "w", encoding="utf-8") as f:
                f.write(html)
            print(f"\n✓ Map saved: map_report.html ({len(gps_points)} point(s)) — open it in any browser.")
        else:
            print("\nNo GPS points found — skipping map generation.")

    print(
        "\nNote: metadata reflects what's embedded in the file — it can be missing,\n"
        "incomplete, or altered, so treat it as a lead, not proof. This tool never\n"
        "identifies people in media, only what the file itself contains.\n"
    )


if __name__ == "__main__":
    main()
