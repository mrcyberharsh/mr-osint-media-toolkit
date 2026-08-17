<p align="center">
  <img src="mrcyber_logo.svg" alt="MR.CYBER" width="420">
</p>

# MR OSINT — Media Toolkit

A dedicated toolkit for **image and video OSINT** — separate from the main [MR OSINT Toolkit](https://github.com/<your-username>/mr-osint-toolkit), focused entirely on media files.

Built by **Harsh Saini** — [MR CYBER](https://mrcyberharsh.github.io/mrcyber/)

---

## What it does

| Feature | Details |
|---|---|
| Image metadata | Camera make/model, timestamps, software used |
| Video metadata | Duration, codec, resolution, creation time, device info (via ffprobe) |
| GPS geotagging | Extracts embedded GPS from photos and phone-recorded videos |
| Reverse geocoding | Converts GPS coordinates into a readable address (OpenStreetMap, free, no API key) |
| Offline HTML map | Plots all found GPS points on one map you can open in a browser |
| File hashing | MD5 / SHA1 / SHA256 for verification and correlation |
| Reverse image search links | Generates Google/Yandex/TinEye/Bing search links (doesn't search automatically) |
| Edit detection | Flags likely re-saved/edited images (missing camera fields, known editing software tags) |
| Metadata stripping | Saves a clean, metadata-free copy of any image before you share it |

## Installation

```bash
pip install Pillow requests
```

`ffprobe` (from [ffmpeg](https://ffmpeg.org)) is needed for video metadata — install ffmpeg via your system package manager:
```bash
sudo apt-get install ffmpeg     # Debian/Ubuntu/Puppy Linux
```

## Usage

```bash
# Basic scan
python mr_osint_media.py photo.jpg

# With reverse geocoding (GPS -> readable address)
python mr_osint_media.py photo.jpg --geocode

# Scan a whole folder, recursively, and build a map of every GPS point found
python mr_osint_media.py ./photos --recursive --map

# Strip metadata before sharing
python mr_osint_media.py photo.jpg --strip

# Get reverse-image-search links
python mr_osint_media.py photo.jpg --reverse-search

# Combine everything
python mr_osint_media.py ./case-files --recursive --geocode --map --reverse-search
```

## Ethical boundaries — read before using

Built for: auditing your own media before sharing it, authorized investigation of files you legitimately possess, and general OSINT/forensics education.

**Not built for, and won't be extended to do:**
- Identifying who is *in* a photo or video (no facial recognition)
- Performing reverse image searches automatically — it only generates the search URLs, you choose whether to open them
- Fetching anything about a person from the internet — it only reads what's already embedded in a file you have

If a request would cross these lines, the answer is no, regardless of framing.

## License

All rights reserved — see [`LICENSE`](LICENSE). Free for personal/educational use; don't redistribute as your own work without credit.

## Contact

- Email: cyber.h4rsh@zohomail.in
- Website: https://mrcyberharsh.github.io/mrcyber/

---

*"Complex ko simple. Simple ko powerful."* — MR CYBER
