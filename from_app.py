"""Extract the MTProto API layer from a macOS **Telegram.app** binary.

Same idea as :mod:`from_ipa`, adapted to the macOS build (Telegram-Swift,
`ru.keepcoder.Telegram`). The differences from the iOS IPA are structural:

* The client is a single monolithic Mach-O at
  ``Telegram.app/Contents/MacOS/Telegram`` - there is no separate
  ``TelegramCoreFramework``.
* The executable is a **universal (FAT)** binary; the layer thunk and the
  Swift metadata are read from the **arm64** slice.
* The macOS binary does **not** carry clean ``namespace.method`` C-strings,
  Swift symbols, or per-method namespace pointers. The ~850 method
  ``FunctionDescription`` signatures are present and fully demanglable, but the
  Swift *word-compression* in those fragments is relative to the enclosing
  ``TelegramApi.Api.functions.<namespace>`` context, so the namespace is needed
  both to group the methods and to demangle the argument labels correctly.

Namespace recovery is therefore a **hybrid**: the methods are read from the
binary (names, argument labels, argument types, result type) and the namespace
of each method is taken from the checked-in ``schema/api.tl`` used purely as a
``method name -> namespace`` oracle. Types and argument names are never taken
from ``api.tl`` - only the namespace label (and the word-table seed it enables).
Methods are contiguously grouped by namespace in the binary, so the oracle's
unambiguous hits anchor whole runs and collisions are resolved by the run they
sit in. Methods whose namespace cannot be established (macOS-only namespaces
absent from the snapshot, e.g. ``communities``/``feed``/``wallet``) keep their
binary-derived signature and are flagged instead of being guessed.
"""

from __future__ import annotations

import plistlib
import struct
from pathlib import Path

from .from_ipa import find_layer_number
from .parser import load_layer_schema, schema_dir
from .swift_mangling import (
    _method_row,
    _render_tl,
    iter_raw_signatures,
    name_fragment,
    parse_signature,
)

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
LC_SEGMENT_64 = 0x19


# --------------------------------------------------------------------------- #
# Mach-O: locate binary and pick the arm64 slice
# --------------------------------------------------------------------------- #
def _app_executable(app: Path) -> Path:
    """Return ``Contents/MacOS/<CFBundleExecutable>`` for a .app bundle."""
    contents = app / "Contents"
    info = contents / "Info.plist"
    exe_name = None
    if info.is_file():
        try:
            exe_name = plistlib.loads(info.read_bytes()).get("CFBundleExecutable")
        except Exception:
            exe_name = None
    macos = contents / "MacOS"
    if exe_name:
        cand = macos / exe_name
        if cand.is_file():
            return cand
    files = [p for p in macos.glob("*") if p.is_file()]
    # Prefer a real Mach-O, biggest wins (skip e.g. a .i64 IDA database).
    machos = [p for p in files if _looks_macho(p)]
    pool = machos or files
    if not pool:
        raise FileNotFoundError(f"no executable under {macos}")
    return max(pool, key=lambda p: p.stat().st_size)


def _looks_macho(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            magic = struct.unpack(">I", fh.read(4))[0]
    except OSError:
        return False
    return magic in (FAT_MAGIC, FAT_CIGAM, MH_MAGIC_64, MH_CIGAM_64)


def resolve_macos_binary(path: Path) -> Path:
    """Accept a .app bundle, its Contents dir, or a Mach-O file directly."""
    path = path.expanduser().resolve()
    if path.is_dir():
        if path.suffix == ".app" or (path / "Contents" / "MacOS").is_dir():
            app = path if path.suffix == ".app" else path
            if (path / "Contents").is_dir():
                return _app_executable(path)
        # a directory that *is* Contents/
        if (path / "MacOS").is_dir():
            return _app_executable(path.parent)
        # fall back: search for a .app inside
        apps = sorted(path.rglob("*.app"))
        if apps:
            return _app_executable(apps[0])
        raise FileNotFoundError(f"no Telegram.app under {path}")
    if path.is_file():
        return path
    raise FileNotFoundError(f"need a .app bundle or Mach-O file, got {path}")


def _arm64_slice(data: bytes) -> bytes:
    """Return the arm64 (preferred) or x86_64 Mach-O slice of a FAT binary."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_CIGAM):
        return data  # already a thin Mach-O
    nfat = struct.unpack_from(">I", data, 4)[0]
    slices: dict[int, bytes] = {}
    for i in range(nfat):
        cputype, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, 8 + i * 20)
        slices[cputype] = data[offset : offset + size]
    for cpu in (CPU_TYPE_ARM64, CPU_TYPE_X86_64):
        if cpu in slices:
            return slices[cpu]
    # last resort: the first slice
    return next(iter(slices.values()))


# --------------------------------------------------------------------------- #
# Swift reflection: namespaces declared under TelegramApi.Api.functions
# --------------------------------------------------------------------------- #
def _sections(slice_: bytes) -> dict:
    """Parse segments/sections of a thin arm64 Mach-O slice."""
    segs: list[tuple[int, int, int, int]] = []  # (vmaddr, vmsize, fileoff, filesize)
    sect: dict[str, tuple[int, int, int]] = {}  # name -> (addr, size, fileoff)
    ncmds = struct.unpack_from("<I", slice_, 16)[0]
    cur = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", slice_, cur)
        if cmd == LC_SEGMENT_64:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", slice_, cur + 24)
            nsects = struct.unpack_from("<I", slice_, cur + 64)[0]
            segs.append((vmaddr, vmsize, fileoff, filesize))
            sp = cur + 72
            for _s in range(nsects):
                sname = slice_[sp : sp + 16].split(b"\x00", 1)[0].decode("latin-1")
                addr, size = struct.unpack_from("<QQ", slice_, sp + 32)
                soff = struct.unpack_from("<I", slice_, sp + 48)[0]
                sect[sname] = (addr, size, soff)
                sp += 80
        cur += cmdsize
        if cur >= len(slice_):
            break
    return {"segs": segs, "sect": sect}


def _reflection_info(slice_: bytes) -> tuple[set[str], dict[str, set[str]]]:
    """Walk ``__swift5_types`` for the API's declared namespaces and types.

    Returns ``(function_namespaces, type_namespaces)`` where

    * ``function_namespaces`` are the ``TelegramApi.Api.functions.<ns>`` enum
      names (the method namespaces), and
    * ``type_namespaces`` maps a constructor-type leaf name to the namespace(s)
      it is declared in (``TelegramApi.Api.<ns>.<Type>``).

    The type map lets us label macOS-only method clusters (``feed`` / ``wallet``
    / ``toncenter``) that api.tl does not know: such a cluster's methods
    reference their own namespace's types (e.g. ``feed`` methods return
    ``feed.FeedMessages`` / ``feed.ForYouFeed``). Returns empty structures if the
    metadata layout is unexpected, so recovery falls back to the api.tl oracle.
    """
    empty: tuple[set[str], dict[str, set[str]]] = (set(), {})
    try:
        meta = _sections(slice_)
    except Exception:
        return empty
    segs = meta["segs"]
    sect = meta["sect"]
    if "__swift5_types" not in sect:
        return empty

    def f2v(o: int) -> int | None:
        for vmaddr, _vs, fo, fs in segs:
            if fo <= o < fo + fs:
                return vmaddr + (o - fo)
        return None

    def v2o(v: int) -> int | None:
        for vmaddr, _vs, fo, fs in segs:
            if vmaddr <= v < vmaddr + fs:
                return v - vmaddr + fo
        return None

    def cstr(o: int) -> str:
        end = slice_.find(b"\x00", o)
        return slice_[o:end].decode("latin-1", "replace")

    def name_of(desc: int) -> str:
        nval = struct.unpack_from("<i", slice_, desc + 8)[0]
        fva = f2v(desc + 8)
        return cstr(v2o(fva + nval))

    def parent_off(desc: int) -> int | None:
        pval = struct.unpack_from("<i", slice_, desc + 4)[0]
        if pval == 0:
            return None
        fva = f2v(desc + 4)
        tva = fva + (pval & ~1)
        if pval & 1:  # indirect through a pointer slot
            po = v2o(tva)
            if po is None:
                return None
            tva = struct.unpack_from("<Q", slice_, po)[0]
        return v2o(tva)

    def fullpath(desc: int) -> list[str]:
        parts: list[str] = []
        seen = 0
        while desc is not None and seen < 12:
            try:
                parts.append(name_of(desc))
            except Exception:
                break
            desc = parent_off(desc)
            seen += 1
        return list(reversed(parts))

    addr, size, soff = sect["__swift5_types"]
    namespaces: set[str] = set()
    type_ns: dict[str, set[str]] = {}
    for i in range(size // 4):
        fo = soff + i * 4
        val = struct.unpack_from("<i", slice_, fo)[0]
        if val == 0:
            continue
        fva = f2v(fo)
        if fva is None:
            continue
        to = v2o(fva + val)
        if to is None:
            continue
        try:
            path = fullpath(to)
        except Exception:
            continue
        if "functions" in path:
            idx = path.index("functions")
            if idx + 1 < len(path):
                namespaces.add(path[idx + 1])
        elif (
            len(path) >= 4
            and path[0] == "TelegramApi"
            and path[1] == "Api"
            and not path[-1].startswith("Cons_")
        ):
            # TelegramApi.Api.<ns>.<Type> -> remember Type belongs to <ns>.
            type_ns.setdefault(path[3], set()).add(path[2])
    return namespaces, type_ns


# --------------------------------------------------------------------------- #
# Namespace oracle (schema/api.tl)
# --------------------------------------------------------------------------- #
def _oracle(schema_path: Path | None) -> dict[str, set[str]]:
    """Build ``short method name -> {namespaces}`` from the checked-in api.tl."""
    schema = load_layer_schema(schema_path or schema_dir())
    table: dict[str, set[str]] = {}
    for m in schema.methods:
        if m.namespace:
            short = m.name.rsplit(".", 1)[-1]
            table.setdefault(short, set()).add(m.namespace)
    return table


def _norm(frag: str) -> str:
    """Normalise a demangled method fragment to an api.tl lookup key."""
    if frag and frag[0].isupper():
        frag = frag[0].lower() + frag[1:]
    return frag


def _suffix_match(apiname: str, frag: str) -> bool:
    """True if `frag` is a camel-boundary suffix of the real `apiname`.

    `name_fragment` often drops a leading verb (``getAllSecureValues`` arrives
    as ``allSecureValues``), so the binary fragment is a tail of the true name.
    """
    if not frag or not apiname:
        return False
    for f in (frag, frag[0].upper() + frag[1:]):
        if apiname == f:
            return True
        if apiname.endswith(f):
            cut = len(apiname) - len(f)
            if cut > 0 and (f[0].isupper() or not apiname[cut - 1].isalpha()):
                return True
    return False


def _best_name_in_ns(frag: str, names: list[str]) -> str | None:
    """Pick the real method name in a namespace for a (possibly mangled) fragment.

    `name_fragment` can drop a leading verb (``getAllSecureValues`` ->
    ``allSecureValues``) or glue a stray word-substitution byte onto the front
    (``getAccountTTL`` -> ``jetAccountTTL``). Both leave the tail intact, so the
    real name is the one sharing the longest common suffix.
    """
    if not frag or not names:
        return None
    norm = _norm(frag)
    if norm in names:
        return norm
    fl = frag.lower()
    best: str | None = None
    best_k = 0
    for a in names:
        al = a.lower()
        k = 0
        while k < len(fl) and k < len(al) and fl[-1 - k] == al[-1 - k]:
            k += 1
        # Accept when the shared tail covers almost all of the real name and
        # only a few leading characters differ (the dropped/garbled verb).
        if k > best_k and k >= 4 and k >= len(a) - 3 and abs(len(a) - len(frag)) <= 4:
            best_k = k
            best = a
    return best


def _candidates(frag: str, by_short: dict[str, set[str]]) -> dict[str, str]:
    """Map namespace -> best real method name for a binary fragment."""
    norm = _norm(frag)
    out: dict[str, str] = {}
    if norm in by_short:
        for ns in by_short[norm]:
            out[ns] = norm
        return out
    # Fuzzy: the true name ends with the fragment (dropped leading verb).
    best: dict[str, tuple[int, str]] = {}
    for short, nss in by_short.items():
        if _suffix_match(short, frag):
            score = -len(short)  # prefer the shortest (closest) match
            for ns in nss:
                if ns not in best or score > best[ns][0]:
                    best[ns] = (score, short)
    for ns, (_s, short) in best.items():
        out[ns] = short
    return out


# --------------------------------------------------------------------------- #
# Hybrid namespace assignment over the binary's monotonic clusters
# --------------------------------------------------------------------------- #
def _resolve(
    frags: list[str], by_short: dict[str, set[str]]
) -> list[tuple[str | None, str]]:
    """Resolve (namespace, real_name) for each fragment, in file order.

    Methods are contiguously grouped by namespace in the binary, so unambiguous
    api.tl hits anchor whole runs; collisions and dropped-verb fragments are
    resolved by the run they sit in. All-unknown runs (macOS-only namespaces
    absent from the snapshot) keep the binary fragment and a None namespace.
    """
    n = len(frags)
    cands: list[dict[str, str]] = [_candidates(f, by_short) for f in frags]
    ns: list[str | None] = [None] * n

    # Pass 1: confident single-namespace anchors.
    for i, c in enumerate(cands):
        if len(c) == 1:
            ns[i] = next(iter(c))

    # Pass 2: nearest confident anchor on each side.
    fwd: list[str | None] = [None] * n
    last: str | None = None
    for i in range(n):
        if ns[i]:
            last = ns[i]
        fwd[i] = last
    bwd: list[str | None] = [None] * n
    nxt: str | None = None
    for i in range(n - 1, -1, -1):
        if ns[i]:
            nxt = ns[i]
        bwd[i] = nxt

    # Pass 3: fill the gaps using the neighbouring runs.
    for i in range(n):
        if ns[i]:
            continue
        c = cands[i]
        if c:  # collision: pick the neighbour run it belongs to
            if fwd[i] in c:
                ns[i] = fwd[i]
            elif bwd[i] in c:
                ns[i] = bwd[i]
            else:
                ns[i] = sorted(c)[0]
        elif fwd[i] and fwd[i] == bwd[i]:
            ns[i] = fwd[i]  # inside a single known run
        # else: boundary gap / all-unknown cluster -> leave as None.

    out: list[tuple[str | None, str]] = []
    for i, frag in enumerate(frags):
        name = cands[i].get(ns[i]) if ns[i] else None
        out.append((ns[i], name or _norm(frag)))
    return out


def _label_exclusive_clusters(
    raw_sigs: list[tuple[str, str]],
    frags: list[str],
    ns_list: list[str | None],
    candidates: set[str],
    type_ns: dict[str, set[str]],
) -> set[str]:
    """Label still-unresolved runs with a macOS-only namespace from reflection.

    ``candidates`` are the reflection namespaces api.tl did not account for
    (e.g. ``feed`` / ``wallet`` / ``toncenter``). Methods of such a namespace
    return/accept its own types, so for each contiguous unresolved run we seed
    every candidate and keep the one whose signatures reference that namespace's
    reflection types the most. Boundary gaps (which reference no exclusive type)
    stay unresolved. Mutates ``ns_list`` in place; returns the namespaces used.
    """
    typesets: dict[str, set[str]] = {ns: set() for ns in candidates}
    for leaf, nss in type_ns.items():
        for ns in nss:
            if ns in typesets:
                typesets[ns].add(leaf)
    typesets = {ns: ts for ns, ts in typesets.items() if ts}
    if not typesets:
        return set()

    used: set[str] = set()
    n = len(ns_list)
    i = 0
    while i < n:
        if ns_list[i] is not None:
            i += 1
            continue
        j = i
        while j < n and ns_list[j] is None:
            j += 1
        best_ns: str | None = None
        best_score = 0
        for ns_c, ts in typesets.items():
            score = 0
            for k in range(i, j):
                head, tail = raw_sigs[k]
                sig = parse_signature(head, tail, namespace=ns_c, method=_norm(frags[k]))
                if sig is None:
                    continue
                leaves = {sig.result.name} | {p.type.name for p in sig.params}
                if leaves & ts:
                    score += 1
            if score > best_score:
                best_score = score
                best_ns = ns_c
        if best_ns and best_score > 0:
            for k in range(i, j):
                ns_list[k] = best_ns
            used.add(best_ns)
        i = j
    return used


# --------------------------------------------------------------------------- #
# Public extraction
# --------------------------------------------------------------------------- #
def extract_from_app(path: Path, *, schema_path: Path | None = None) -> dict:
    binary = resolve_macos_binary(Path(path))
    raw = binary.read_bytes()
    is_fat = struct.unpack_from(">I", raw, 0)[0] in (FAT_MAGIC, FAT_CIGAM)
    slice_ = _arm64_slice(raw)
    arch = "arm64" if is_fat else "thin"

    hit = find_layer_number(slice_)
    known_ns, type_ns = _reflection_info(slice_)
    oracle = _oracle(schema_path)
    by_ns: dict[str, list[str]] = {}
    for short, nss in oracle.items():
        for ns in nss:
            by_ns.setdefault(ns, []).append(short)

    # Raw FunctionDescription signatures, in file order (monotonic by namespace).
    raw_sigs = iter_raw_signatures(slice_)
    frags = [name_fragment(head) for head, _tail in raw_sigs]
    resolved = _resolve(frags, oracle)
    ns_list: list[str | None] = [ns for ns, _name in resolved]

    # Label macOS-only clusters (feed / wallet / toncenter) that api.tl lacks,
    # using the binary's own reflection types.
    exclusive = known_ns - {n for n in ns_list if n}
    reflection_ns = _label_exclusive_clusters(raw_sigs, frags, ns_list, exclusive, type_ns)

    methods: list[dict] = []
    seen: set[str] = set()
    no_ns = 0
    for (head, tail), frag, ns in zip(raw_sigs, frags, ns_list):
        short = _norm(frag)
        if not short:
            continue
        confirmed = False
        if ns:
            # Repair a garbled/truncated fragment against the real names in ns.
            fixed = _best_name_in_ns(frag, by_ns.get(ns, []))
            if fixed:
                short, confirmed = fixed, True
        sig = parse_signature(head, tail, namespace=ns or "", method=short)
        if sig is None:
            continue
        if ns:
            name = f"{ns}.{short}"
            row = _method_row(name, short, ns, sig)
            row["source"] = "app"
            if ns in reflection_ns:
                # Namespace recovered from the binary (reflection), not api.tl.
                row["namespace_source"] = "reflection"
            if not confirmed:
                # Fragment matched no api.tl name in this namespace: the name is
                # the raw binary fragment and may be a truncated/garbled label.
                row["name_uncertain"] = True
        else:
            no_ns += 1
            name = short
            row = _method_row(name, short, None, sig)
            row["source"] = "app"
            row["namespace_unresolved"] = True
            row["name_uncertain"] = True
            row["tl"] = _render_tl(short, sig.params, sig.result)
        if name in seen:
            continue
        seen.add(name)
        methods.append(row)

    methods.sort(key=lambda m: m["name"].lower())
    with_params = sum(1 for m in methods if m.get("params"))
    with_sig = sum(1 for m in methods if not m.get("missing_signature"))
    uncertain = sum(1 for m in methods if m.get("name_uncertain"))
    via_reflection = sum(1 for m in methods if m.get("namespace_source") == "reflection")
    return {
        "binary": str(binary),
        "binary_size": len(raw),
        "arch": arch,
        "layer": hit.layer,
        "layer_offset": hex(hit.file_offset),
        "layer_paired_thunks": hit.paired,
        "source_kind": "app",
        "namespaces_in_binary": sorted(known_ns),
        "namespaces_from_reflection": sorted(reflection_ns),
        "method_names": sorted(m["name"] for m in methods),
        "methods": methods,
        "methods_in_app_count": len(methods),
        "methods_with_params": with_params,
        "methods_with_signature": with_sig,
        "methods_without_namespace": no_ns,
        "methods_name_uncertain": uncertain,
        "methods_namespace_from_reflection": via_reflection,
    }


def format_app_report(info: dict) -> str:
    """Human-readable listing, grouped by namespace (mirrors format_layer_report)."""
    methods = info.get("methods") or []
    subst = unknown = 0
    for method in methods:
        if method.get("result_type") == "Unknown":
            unknown += 1
        for param in method.get("params") or []:
            name = (param.get("type") or {}).get("name") or ""
            if str(name).startswith("subst"):
                subst += 1
    lines = [
        f"layer {info.get('layer')}",
        f"binary {info.get('binary')}",
        f"methods {info.get('methods_in_app_count', len(methods))}",
        f"with Swift signature {info.get('methods_with_signature', 0)}",
        f"with arguments {info.get('methods_with_params', 0)}",
        f"without namespace {info.get('methods_without_namespace', 0)}",
        f"namespace from reflection {info.get('methods_namespace_from_reflection', 0)} "
        f"({', '.join(info.get('namespaces_from_reflection') or []) or '-'})",
        f"name uncertain {info.get('methods_name_uncertain', 0)}",
        f"unresolved subst_N {subst}",
        f"Unknown result {unknown}",
        f"namespaces in binary {len(info.get('namespaces_in_binary') or [])}",
        "",
        "Names, argument labels and types come from the binary. The namespace",
        "label is taken from schema/api.tl (name -> namespace oracle) plus the",
        "binary's contiguous per-namespace grouping; types are never guessed",
        "from api.tl. Methods under [?] had no namespace in the snapshot.",
        "",
    ]
    current_ns = object()
    for method in methods:
        ns = method.get("namespace") or "?"
        if ns != current_ns:
            current_ns = ns
            lines.append(f"[{ns}]")
        lines.append(f"  {method.get('tl') or method.get('name')}")
    return "\n".join(lines) + "\n"
