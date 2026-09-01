from __future__ import annotations

import argparse
import json
from pathlib import Path

from .catalog import build_method_index, build_type_index, load_ida_methods
from .from_ipa import extract_from_binary, extract_from_path
from .models import Combinator, Schema
from .parser import load_layer_schema, schema_dir


def extract_methods_from_binary(path: str | Path) -> dict:
    info = extract_from_binary(Path(path))
    return {
        "binary": info["binary"],
        "size": info["binary_size"],
        "swift_methods": [],
        "string_methods": info["method_names"],
        "layer": info["layer"],
    }


def cross_check(schema: Schema, extracted: dict) -> dict:
    schema_methods = {m.name for m in schema.methods}
    swift = set(extracted.get("swift_methods", []))
    strings = set(extracted.get("string_methods", []))
    found = swift | strings
    api_methods = {m.name for m in schema.methods if m.namespace}
    return {
        "schema_methods": len(schema_methods),
        "ipa_swift_methods": len(swift),
        "ipa_string_methods": len(strings),
        "in_ipa_not_in_schema": sorted(found - schema_methods)[:80],
        "in_schema_not_in_ipa": sorted(api_methods - found)[:80],
        "matched": len(api_methods & found),
        "schema_api_methods": len(api_methods),
    }


def dump_schema(schema: Schema, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(schema.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def lookup(schema: Schema, query: str) -> list[Combinator]:
    hits = schema.by_name(query)
    if not hits:
        try:
            found = schema.by_id(query)
            if found:
                hits = [found]
        except ValueError:
            hits = []
    if not hits:
        hits = schema.constructors_of(query)
    if not hits:
        hits = schema.methods_in(query)
    return hits


def print_combinator(item: Combinator) -> None:
    kind = "method" if item.kind == "method" else "constructor"
    print(f"[{kind}] {item.render()}")
    print(f"  id: #{item.id_hex} ({item.id_signed})")
    print(f"  result: {item.result.render()}")
    if item.generic_params:
        print("  generics:", ", ".join(g.render() for g in item.generic_params))
    if item.params:
        print("  params:")
        for param in item.params:
            extra = ""
            if param.optional and param.type.flag:
                extra = f"  (if {param.type.flag.field} bit {param.type.flag.bit})"
            print(f"    - {param.render()}{extra}")


def _default_ipa() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "Payload"
        / "Telegram.app"
        / "Frameworks"
        / "TelegramCoreFramework.framework"
        / "TelegramCoreFramework"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse Telegram MTProto TL layer (methods, types, constructors)."
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=schema_dir(),
        help="Directory with api.tl / mtproto.tl",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    dump = sub.add_parser("dump", help="Dump parsed layer to JSON")
    dump.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "out" / "layer.json",
    )

    look = sub.add_parser("lookup", help="Find a method, constructor, type or namespace")
    look.add_argument("query")

    sub.add_parser("stats", help="Print layer totals")

    extract = sub.add_parser("extract", help="Extract methods from the IPA binary and compare")
    extract.add_argument("--ipa", type=Path, default=_default_ipa())
    extract.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "out" / "ipa_methods.json",
    )

    index = sub.add_parser("index", help="Write compact method/type indexes (optionally with IDA addrs)")
    index.add_argument(
        "--ida",
        type=Path,
        default=Path(__file__).resolve().parent / "out" / "ida_methods.json",
    )
    index.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "out",
    )

    fromipa = sub.add_parser(
        "from-ipa",
        help="Unpack IPA, read currentLayer and methods/args from the binary only",
    )
    fromipa.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Path to .ipa, Payload/, or TelegramCoreFramework (default: first .ipa in repo)",
    )
    fromipa.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "out" / "ipa_layer.json",
    )

    args = parser.parse_args(argv)

    if args.cmd in {"stats", "lookup", "dump", "extract", "index"}:
        schema = load_layer_schema(args.schema_dir)
    else:
        schema = None

    if args.cmd == "stats":
        data = schema.to_dict()["stats"]
        print(f"layer: {schema.layer}")
        for key, value in data.items():
            print(f"{key}: {value}")
        print("namespaces:")
        for ns, names in sorted(schema.namespaces().items(), key=lambda kv: kv[0]):
            label = ns or "(root)"
            print(f"  {label}: {len(names)}")
        return 0

    if args.cmd == "lookup":
        hits = lookup(schema, args.query)
        if not hits:
            print(f"nothing found for {args.query!r}")
            return 1
        for item in hits:
            print_combinator(item)
            print()
        return 0

    if args.cmd == "dump":
        dump_schema(schema, args.output)
        print(
            f"wrote {args.output} (layer {schema.layer}, "
            f"{len(schema.methods)} methods, {len(schema.constructors)} constructors)"
        )
        return 0

    if args.cmd == "extract":
        extracted = extract_methods_from_binary(args.ipa)
        extracted["cross_check"] = cross_check(schema, extracted)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(extracted, indent=2) + "\n", encoding="utf-8")
        check = extracted["cross_check"]
        print(f"layer {schema.layer}")
        print(f"schema methods: {check['schema_methods']}")
        print(f"ipa swift methods: {check['ipa_swift_methods']}")
        print(f"ipa string methods: {check['ipa_string_methods']}")
        print(f"matched: {check['matched']} / {check['schema_api_methods']}")
        print(f"wrote {args.output}")
        return 0

    if args.cmd == "index":
        ida_rows = load_ida_methods(args.ida) if args.ida.exists() else []
        methods = build_method_index(schema, ida_rows)
        types = build_type_index(schema)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        methods_path = args.output_dir / "methods.json"
        types_path = args.output_dir / "types.json"
        methods_path.write_text(json.dumps(methods, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        types_path.write_text(json.dumps(types, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        matched = sum(1 for m in methods if m.get("ipa_id_match") is True)
        with_addr = sum(1 for m in methods if m.get("ipa_addr"))
        print(f"layer {schema.layer}")
        print(f"wrote {methods_path} ({len(methods)} methods, {with_addr} in IPA, {matched} id matches)")
        print(f"wrote {types_path} ({len(types)} types, {sum(len(v) for v in types.values())} constructors)")
        return 0

    if args.cmd == "from-ipa":
        src = args.path
        if src is None:
            repo = Path(__file__).resolve().parents[1]
            ipas = sorted(repo.glob("*.ipa"))
            src = ipas[0] if ipas else repo / "Payload"
        info = extract_from_path(src)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(info, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"source: {info['source']}")
        print(f"binary: {info['binary']}")
        print(f"layer:  {info['layer']} (offset {info['layer_offset']}, paired={info['layer_paired_thunks']})")
        print(f"methods: {info['methods_in_ipa_count']} ({info.get('methods_with_signature', 0)} from Swift signatures, {info['methods_with_params']} with arguments)")
        print(f"wrote {args.output}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
