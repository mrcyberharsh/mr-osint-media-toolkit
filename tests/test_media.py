"""Tests for MR OSINT Media Toolkit privacy-safe exports."""
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from mr_osint_media import compute_hashes, dms_to_decimal, strip_image_metadata, write_manifest


class MediaHelperTests(unittest.TestCase):
    def test_hashes_match_sha256(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.bin"
            path.write_bytes(b"sample-data")
            hashes, error = compute_hashes(path)
            self.assertIsNone(error)
            self.assertEqual(hashes["SHA256"], hashlib.sha256(b"sample-data").hexdigest())

    def test_dms_to_decimal_handles_south_west(self):
        self.assertAlmostEqual(dms_to_decimal((10, 30, 0), "S"), -10.5)
        self.assertAlmostEqual(dms_to_decimal((20, 15, 0), "W"), -20.25)

    def test_manifest_redacts_gps_by_default(self):
        record = {"file": "photo.jpg", "type": "image", "hashes": {"SHA256": "abc"},
                  "metadata": {"format": "JPEG", "size": "10x10"}}
        with tempfile.TemporaryDirectory() as folder:
            json_path = Path(folder) / "manifest.json"
            csv_path = Path(folder) / "manifest.csv"
            write_manifest([record], json_path, csv_path)
            loaded = json.loads(json_path.read_text())
            self.assertNotIn("gps", loaded[0])
            rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
            self.assertEqual(rows[0]["gps_included"], "no")

    def test_image_metadata_stripping_removes_exif(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow is not installed")
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.jpg"
            output = Path(folder) / "clean.jpg"
            exif = Image.Exif()
            exif[270] = "private description"
            Image.new("RGB", (8, 8), "white").save(source, exif=exif)
            ok, error = strip_image_metadata(source, output)
            self.assertTrue(ok, error)
            with Image.open(output) as clean:
                self.assertEqual(len(clean.getexif()), 0)


if __name__ == "__main__":
    unittest.main()
