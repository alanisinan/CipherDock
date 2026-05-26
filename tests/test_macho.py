"""Tests for Mach-O section and platform parsing."""

import struct
import tempfile
import unittest
from pathlib import Path

from ire_zero.macho import extract_platform, extract_sections


class MachOTests(unittest.TestCase):
    def test_extracts_section_metadata_and_entropy(self) -> None:
        section_payload = bytes(range(16))
        header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 152, 0, 0)
        segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT\0" * 2, 0x100000000, 16, 184, 16, 7, 5, 1, 0)
        section = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text\0" * 2,
            b"__TEXT\0" * 2,
            0x100000000,
            16,
            184,
            2,
            0,
            0,
            0x80000400,
            0,
            0,
            0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "App"
            binary.write_bytes(header + segment + section + section_payload)

            sections = extract_sections(binary)

        self.assertEqual(sections[0].name, "__text")
        self.assertEqual(sections[0].segment, "__TEXT")
        self.assertEqual(sections[0].size, 16)
        self.assertGreater(sections[0].entropy, 0)

    def test_extracts_simulator_platform_from_build_version(self) -> None:
        build_version = struct.pack("<IIIIII", 0x32, 24, 7, 0, 0, 0)
        header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(build_version), 0, 0)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "App"
            binary.write_bytes(header + build_version)

            platform = extract_platform(binary)

        self.assertEqual(platform, "IOSSIMULATOR")


if __name__ == "__main__":
    unittest.main()
