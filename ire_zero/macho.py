"""Parse Mach-O platform load commands, sections, and section entropy."""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import List, Optional, Tuple

from .models import BinarySection

LC_SEGMENT_64 = 0x19
LC_BUILD_VERSION = 0x32
CPU_TYPE_ARM64 = 0x0100000C
PLATFORM_NAMES = {
    1: "MACOS",
    2: "IOS",
    3: "TVOS",
    4: "WATCHOS",
    6: "MACCATALYST",
    7: "IOSSIMULATOR",
    8: "TVOSSIMULATOR",
    9: "WATCHOSSIMULATOR",
    11: "VISIONOS",
    12: "VISIONOSSIMULATOR",
}


def extract_sections(path: Path) -> List[BinarySection]:
    data = path.read_bytes()
    header = _mach_header(data)
    if header is None:
        return []
    offset, endian = header
    if offset + 32 > len(data):
        return []
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from(endian + "IiiIIIII", data, offset)
    command_offset = offset + 32
    sections: List[BinarySection] = []
    for _ in range(ncmds):
        if command_offset + 8 > len(data):
            break
        command, command_size = struct.unpack_from(endian + "II", data, command_offset)
        if command_size < 8 or command_offset + command_size > len(data):
            break
        if command == LC_SEGMENT_64 and command_size >= 72:
            segment = struct.unpack_from(endian + "II16sQQQQiiII", data, command_offset)
            segment_name = _cstring(segment[2])
            nsects = segment[9]
            section_offset = command_offset + 72
            for _ in range(nsects):
                if section_offset + 80 > command_offset + command_size:
                    break
                raw = struct.unpack_from(endian + "16s16sQQIIIIIIII", data, section_offset)
                name = _cstring(raw[0])
                section_segment = _cstring(raw[1]) or segment_name
                address, size, file_offset, flags = raw[2], raw[3], raw[4], raw[8]
                payload = data[file_offset : file_offset + size] if file_offset < len(data) else b""
                sections.append(
                    BinarySection(
                        segment=section_segment,
                        name=name,
                        address=f"0x{address:x}",
                        offset=file_offset,
                        size=size,
                        entropy=round(_entropy(payload), 3),
                        flags=f"0x{flags:08x}",
                    )
                )
                section_offset += 80
        command_offset += command_size
    return sections


def extract_platform(path: Path) -> Optional[str]:
    return extract_platform_data(path.read_bytes())


def extract_platform_data(data: bytes) -> Optional[str]:
    header = _mach_header(data)
    if header is None:
        return None
    offset, endian = header
    if offset + 32 > len(data):
        return None
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from(endian + "IiiIIIII", data, offset)
    command_offset = offset + 32
    for _ in range(ncmds):
        if command_offset + 8 > len(data):
            break
        command, command_size = struct.unpack_from(endian + "II", data, command_offset)
        if command_size < 8 or command_offset + command_size > len(data):
            break
        if command == LC_BUILD_VERSION and command_size >= 24:
            platform = struct.unpack_from(endian + "I", data, command_offset + 8)[0]
            return PLATFORM_NAMES.get(platform, f"PLATFORM_{platform}")
        command_offset += command_size
    return None


def _mach_header(data: bytes) -> Optional[Tuple[int, str]]:
    if len(data) < 4:
        return None
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        return 0, "<"
    if magic == b"\xfe\xed\xfa\xcf":
        return 0, ">"
    if magic in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        endian = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        if len(data) < 8:
            return None
        nfat = struct.unpack_from(endian + "I", data, 4)[0]
        candidate: Optional[Tuple[int, str]] = None
        for index in range(nfat):
            entry_offset = 8 + index * 20
            if entry_offset + 20 > len(data):
                break
            cpu_type, _, file_offset, _, _ = struct.unpack_from(endian + "iiIII", data, entry_offset)
            nested = _thin_header_at(data, file_offset)
            if nested is not None:
                candidate = nested
                if cpu_type == CPU_TYPE_ARM64:
                    return nested
        return candidate
    return None


def _thin_header_at(data: bytes, offset: int) -> Optional[Tuple[int, str]]:
    if offset + 4 > len(data):
        return None
    magic = data[offset : offset + 4]
    if magic == b"\xcf\xfa\xed\xfe":
        return offset, "<"
    if magic == b"\xfe\xed\xfa\xcf":
        return offset, ">"
    return None


def _cstring(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("ascii", errors="replace")


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = [0] * 256
    for byte in payload:
        counts[byte] += 1
    length = len(payload)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )
