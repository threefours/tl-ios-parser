from __future__ import annotations

import re
import shutil
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .swift_mangling import attach_binary_methods, extract_method_cstrings

MANGLED_FN = re.compile(
    rb"TelegramApi0B0O9functionsO((?:\d+[A-Za-z][A-Za-z0-9]*O)*\d+[A-Za-z][A-Za-z0-9]*)"
)

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19
CPU_TYPE_ARM64 = 0x0100000C
RET = 0xD65F03C0


@dataclass(slots=True)
class LayerHit:
    file_offset: int
    layer: int
    paired: bool


def _parse_len_idents(blob: str) -> list[str]:
    parts: list[str] = []
    i = 0
    while i < len(blob) and blob[i].isdigit():
        n = 0
        while i < len(blob) and blob[i].isdigit():
            n = n * 10 + int(blob[i])
            i += 1
        ident = blob[i : i + n]
        if len(ident) != n or not ident:
            break
        parts.append(ident)
        i += n
        if i < len(blob) and blob[i] == "O":
            i += 1
        else:
            break
    return parts


def find_core_framework(root: Path) -> Path:
    matches = list(root.rglob("TelegramCoreFramework"))
    matches = [p for p in matches if p.is_file() and "TelegramCoreFramework.framework" in str(p)]
    if not matches:
        matches = [p for p in root.rglob("TelegramCoreFramework") if p.is_file()]
    if not matches:
        raise FileNotFoundError(f"TelegramCoreFramework not found under {root}")
    return max(matches, key=lambda p: p.stat().st_size)


def unpack_ipa(ipa: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ipa) as zf:
        zf.extractall(dest)
    payload = dest / "Payload"
    if not payload.is_dir():
        raise FileNotFoundError(f"IPA has no Payload/: {ipa}")
    return find_core_framework(payload)


def resolve_binary(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.suffix.lower() == ".ipa":
        tmp = Path(tempfile.mkdtemp(prefix="tl-ipa-"))
        try:
            binary = unpack_ipa(path, tmp)
            # Keep extracted tree next to temp until caller copies; return binary path.
            return binary
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
    if path.name == "TelegramCoreFramework" and path.is_file():
        return path
    if path.is_dir():
        return find_core_framework(path)
    raise FileNotFoundError(f"Need .ipa, Payload dir, or TelegramCoreFramework, got {path}")


def _iter_text_sections(data: bytes) -> list[tuple[int, int]]:
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic == FAT_CIGAM else "<"
        nfat = struct.unpack_from(endian + "I", data, 4)[0]
        for i in range(nfat):
            off = 8 + i * 20
            cputype, _, offset, size, _ = struct.unpack_from(endian + "IIIII", data, off)
            if cputype == CPU_TYPE_ARM64:
                return _iter_text_sections(data[offset : offset + size])
        raise ValueError("FAT binary has no ARM64 slice")
    if magic != MH_MAGIC_64:
        # Still scan whole file if header is unexpected.
        return [(0, len(data))]

    ncmds = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    sections: list[tuple[int, int]] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", data, cursor + 64)[0]
            sect = cursor + 72
            for _s in range(nsects):
                name = data[sect : sect + 16].split(b"\x00", 1)[0]
                size, fileoff = struct.unpack_from("<QI", data, sect + 40)
                if name == b"__text" and size and fileoff:
                    sections.append((fileoff, size))
                sect += 80
        cursor += cmdsize
        if cursor >= len(data):
            break
    return sections or [(0, len(data))]


def find_layer_number(data: bytes) -> LayerHit:
    hits: list[LayerHit] = []
    for fileoff, size in _iter_text_sections(data):
        end = min(len(data) - 8, fileoff + size)
        i = fileoff - (fileoff % 4)
        while i <= end:
            w, w2 = struct.unpack_from("<II", data, i)
            if w2 == RET and (w & 0xFF80001F) == 0x52800000 and ((w >> 21) & 3) == 0:
                imm = (w >> 5) & 0xFFFF
                if 50 <= imm <= 400:
                    paired = False
                    if i + 8 <= end:
                        w3, w4 = struct.unpack_from("<II", data, i + 8)
                        if w4 == RET and w3 == w:
                            paired = True
                    hits.append(LayerHit(file_offset=i, layer=imm, paired=paired))
            i += 4

    if not hits:
        raise ValueError("currentLayer getter not found (no MOV W0, #layer; RET)")

    paired = [h for h in hits if h.paired]
    if paired:
        # Serialization.currentLayer is two identical 8-byte functions in a row.
        return paired[0]
    # Unique value in typical API-layer range is the next best guess.
    counts: dict[int, int] = {}
    for hit in hits:
        counts[hit.layer] = counts.get(hit.layer, 0) + 1
    best = min(hits, key=lambda h: (counts[h.layer] != 1, abs(h.layer - 200)))
    return best


def extract_method_names(data: bytes) -> list[str]:
    names: set[str] = set(extract_method_cstrings(data))
    for match in MANGLED_FN.finditer(data):
        parts = _parse_len_idents(match.group(1).decode("ascii", "ignore"))
        if len(parts) >= 2:
            names.add(".".join(parts[:2]))
        elif parts:
            names.add(parts[0])
    return sorted(names)


def extract_from_binary(binary: Path) -> dict:
    data = binary.read_bytes()
    hit = find_layer_number(data)
    methods = attach_binary_methods(data)
    names = sorted({m["name"] for m in methods})
    has_marker = b"currentLayerSuyF" in data or b"currentLayer" in data
    with_params = sum(1 for m in methods if m.get("params"))
    with_sig = sum(1 for m in methods if not m.get("missing_signature"))
    return {
        "binary": str(binary),
        "binary_size": len(data),
        "layer": hit.layer,
        "layer_offset": hex(hit.file_offset),
        "layer_paired_thunks": hit.paired,
        "currentLayer_marker": has_marker,
        "source_kind": "ipa",
        "method_names": names,
        "methods": methods,
        "methods_in_ipa_count": len(methods),
        "methods_with_params": with_params,
        "methods_with_signature": with_sig,
    }


def extract_from_path(path: Path) -> dict:
    path = path.expanduser().resolve()
    tmp: Path | None = None
    ipa = str(path) if path.suffix.lower() == ".ipa" else None
    try:
        if path.suffix.lower() == ".ipa":
            tmp = Path(tempfile.mkdtemp(prefix="tl-ipa-"))
            binary = unpack_ipa(path, tmp)
        else:
            binary = resolve_binary(path)
        info = extract_from_binary(binary)
        info["source"] = str(path)
        info["ipa"] = ipa
        return info
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def format_layer_report(info: dict) -> str:
    """Human-readable listing of the IPA extract (same data as ipa_layer.json)."""
    methods = info.get("methods") or []
    subst = 0
    unknown = 0
    missing = 0
    for method in methods:
        if method.get("missing_signature"):
            missing += 1
        if method.get("result_type") == "Unknown":
            unknown += 1
        for param in method.get("params") or []:
            name = (param.get("type") or {}).get("name") or ""
            if str(name).startswith("subst"):
                subst += 1
    lines = [
        f"layer {info.get('layer')}",
        f"methods {info.get('methods_in_ipa_count', len(methods))}",
        f"with Swift signature {info.get('methods_with_signature', 0)}",
        f"with arguments {info.get('methods_with_params', 0)}",
        f"no signature {missing}",
        f"unresolved subst_N {subst}",
        f"Unknown result {unknown}",
        "",
        "Types come from the IPA mangled names only. subst_N means the Swift",
        "back-reference had no identifier in this fragment (not a guessed type).",
        "",
    ]
    current_ns = None
    for method in methods:
        name = method.get("name") or ""
        ns = name.split(".", 1)[0] if "." in name else "(root)"
        if ns != current_ns:
            current_ns = ns
            lines.append(f"[{ns}]")
        lines.append(f"  {method.get('tl') or name}")
    return "\n".join(lines) + "\n"
