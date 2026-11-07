<p align="center">
  <img src="mrcyber_logo.svg" alt="MR CYBER logo" width="360">
</p>

# MR OSINT — Media Toolkit

A local utility for inspecting metadata and technical properties of image and video files you are authorized to handle. It focuses on file metadata, hashes, and privacy-aware cleanup—not identifying people.

Built by **Harsh Saini · MR CYBER**.

## Features

| Capability | Description |
|---|---|
| Image metadata | Reads available camera, timestamp, and software fields |
| Video metadata | Reads duration, codec, resolution, and related fields using ffprobe |
| GPS metadata | Extracts embedded location metadata when present |
| Reverse geocoding | Can convert embedded coordinates to a readable place name |
| Local map | Can create an HTML map from extracted GPS points |
| File hashes | Calculates MD5, SHA-1, and SHA-256 checksums |
| Reverse-search links | Generates links for manual reverse-image-search services |
| Edit indicators | Flags selected metadata patterns that may indicate re-saving or editing |
| Metadata removal | Creates a metadata-cleaned image copy for safer sharing |

Metadata can be missing, modified, or inaccurate. An edit indicator is only a clue, not proof that a file was manipulated.

## Requirements

- Python 3
- Pillow
- requests
- Optional: ffmpeg/ffprobe for video metadata

## Installation

```bash
git clone https://github.com/mrcyberharsh/mr-osint-media-toolkit.git
cd mr-osint-media-toolkit
python -m pip install --upgrade pip
python -m pip install Pillow requests
```

Install ffmpeg using the package manager for your operating system if you need video metadata support. See the [official FFmpeg site](https://ffmpeg.org/) for platform guidance.

## Usage

Inspect a file:

```bash
python mr_osint_media.py photo.jpg
```

Use the optional features documented by the command:

```bash
python mr_osint_media.py --help
```

Examples:

```bash
# Read metadata and request reverse geocoding
python mr_osint_media.py photo.jpg --geocode

# Inspect a folder and create a map from available GPS metadata
python mr_osint_media.py ./photos --recursive --map

# Create a metadata-cleaned copy before sharing
python mr_osint_media.py photo.jpg --strip

# Generate manual reverse-image-search links
python mr_osint_media.py photo.jpg --reverse-search

# Batch JSON/CSV manifests (GPS redacted by default)
python mr_osint_media.py ./photos --recursive --report-json manifest.json --report-csv manifest.csv

# Include GPS only when you intentionally need it in the report
python mr_osint_media.py ./photos --recursive --report-json manifest.json --include-gps-in-report
```

## Batch manifests and privacy

Use `--report-json` and `--report-csv` to export a manifest for multiple files. Reports include hashes and selected metadata; exact GPS coordinates are excluded by default. Add `--include-gps-in-report` only when you intentionally need precise location data in the export. Keep reports private because they may contain device identifiers, timestamps, local file paths, and other sensitive metadata.

The `--strip` option writes a new image copy using pixel data without carrying over EXIF or ancillary metadata. Keep the original file unchanged if you need to preserve evidence.

## Privacy and responsible use

Use this toolkit only with files you own or are authorized to inspect.

- Do not use extracted metadata to stalk, threaten, or target anyone.
- Location metadata can reveal sensitive places; avoid publishing it without permission.
- Review generated files before sharing them.
- The tool does not perform facial recognition or identify people in media.
- Reverse-image-search links are generated for the user; the toolkit does not automatically identify a person.

## Limitations

- Not every file contains metadata.
- Apps and platforms may remove or rewrite metadata during upload.
- Reverse geocoding requires an internet connection.
- Video metadata features require ffprobe to be installed and available on PATH.
- Metadata patterns cannot conclusively establish authenticity or editing history.

## Contributing

Please open an issue with a minimal reproducible example and sanitized logs. Pull requests should include clear descriptions and avoid committing private media files or extracted personal data.

## License and contact

See [LICENSE](LICENSE) for the project's terms.

- GitHub: https://github.com/mrcyberharsh
- Main toolkit: https://github.com/mrcyberharsh/mr-osint-toolkit
- Website: https://mrcyberharsh.github.io/mrcyber/
