"""Offline checks against the separately downloaded official 3.1.2 S3 image."""
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from xmc70_bootloader import correct_image, PATCHED_SHA256

SOURCE_SHA = "b8447c5ca535ee2f288097ccb52de548beb8d8f2412b35024a85913844a60b8e"
OUTPUT_SHA = "e76ca44658249e45568c6546533199f05ad2221b12d48a588b839bfe46d0f528"

class ReleaseChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = RELEASE.read_bytes()
        if hashlib.sha256(cls.image).hexdigest() != SOURCE_SHA:
            raise ValueError("Fixture is not the published 3.1.2 ESP32-S3 release")
        cls.bootloader = cls.image[:18976]

    def run_tool(self, source, output, digest):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/prepare_xmc70_release.py"),
             str(source), str(output), "--expected-sha256", digest],
            capture_output=True, text=True)

    def test_bootloader_hash_checksum_and_idempotence(self):
        patched = correct_image(self.bootloader)
        self.assertEqual(hashlib.sha256(patched).hexdigest(), PATCHED_SHA256)
        self.assertEqual(correct_image(patched), patched)
        pos, checksum = 24, 0xef
        for _ in range(patched[1]):
            _, length = struct.unpack_from("<II", patched, pos)
            pos += 8
            for value in patched[pos:pos + length]:
                checksum ^= value
            pos += length
        end = ((pos + 16) // 16) * 16
        self.assertEqual(patched[end - 1], checksum)
        self.assertEqual(patched[end:], hashlib.sha256(patched[:end]).digest())

    def test_golden_release_and_unchanged_application(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "corrected.bin"
            result = self.run_tool(RELEASE, output, SOURCE_SHA)
            self.assertEqual(result.returncode, 0, result.stderr)
            image = output.read_bytes()
            self.assertEqual(len(image), len(self.image))
            self.assertEqual(hashlib.sha256(image).hexdigest(), OUTPUT_SHA)
            self.assertEqual(image[18976:], self.image[18976:])

    def test_wrong_download_hash_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bad.bin"
            self.assertNotEqual(self.run_tool(RELEASE, output, "0" * 64).returncode, 0)
            self.assertFalse(output.exists())

    def test_existing_destination_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "existing.bin"
            output.write_bytes(b"preserve this file")
            self.assertNotEqual(self.run_tool(RELEASE, output, SOURCE_SHA).returncode, 0)
            self.assertEqual(output.read_bytes(), b"preserve this file")

    def test_unknown_bootloader_is_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = bytearray(self.image)
            changed[100] ^= 1
            source, output = Path(tmp) / "unknown.bin", Path(tmp) / "output.bin"
            source.write_bytes(changed)
            digest = hashlib.sha256(changed).hexdigest()
            self.assertNotEqual(self.run_tool(source, output, digest).returncode, 0)
            self.assertFalse(output.exists())

    def test_invalid_bootloaders_are_rejected(self):
        for image in [b"", self.bootloader[:100], b"\0" * len(self.bootloader)]:
            with self.subTest(size=len(image)):
                with self.assertRaises(ValueError):
                    correct_image(image)

    def test_source_cannot_be_overwritten(self):
        result = self.run_tool(RELEASE, RELEASE, SOURCE_SHA)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(hashlib.sha256(RELEASE.read_bytes()).hexdigest(), SOURCE_SHA)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    RELEASE = args.release.resolve()
    unittest.main(argv=[sys.argv[0]] + remaining)
