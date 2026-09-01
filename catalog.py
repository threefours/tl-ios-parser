from __future__ import annotations

import json
from pathlib import Path

from .models import Schema
from .parser import load_layer_schema


def demangle_api_function(mangled: str) -> str | None:
    marker = "9functionsO"
    idx = mangled.find(marker)
    if idx < 0:
        return None
    blob = mangled[idx + len(marker) :]
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
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    if parts:
        return parts[0]
    return None


def load_ida_methods(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = []
    for item in data.get("methods", []):
        name = demangle_api_function(item.get("name") or item.get("mangled") or "")
        if not name:
            continue
        imms = [int(x, 16) for x in item.get("immediates", [])]
        rows.append(
            {
                "name": name,
                "addr": item.get("addr"),
                "size": item.get("size"),
                "immediates": imms,
            }
        )
    return rows


def build_method_index(schema: Schema, ida_rows: list[dict] | None = None) -> list[dict]:
    ida_by_name = {}
    for row in ida_rows or []:
        ida_by_name.setdefault(row["name"], row)

    index = []
    for method in schema.methods:
        row = {
            "name": method.name,
            "namespace": method.namespace,
            "id_hex": method.id_hex,
            "id": method.id_signed,
            "result": method.result.render(),
            "params": [p.render() for p in method.params],
            "tl": method.render(),
        }
        ipa = ida_by_name.get(method.name)
        if ipa:
            imms = set(ipa["immediates"])
            row["ipa_addr"] = ipa["addr"]
            row["ipa_size"] = ipa["size"]
            row["ipa_id_match"] = method.id is not None and (method.id & 0xFFFFFFFF) in imms
        else:
            row["ipa_addr"] = None
            row["ipa_id_match"] = None
        index.append(row)
    return index


def build_type_index(schema: Schema) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for ctor in schema.constructors:
        grouped.setdefault(ctor.result_type, []).append(
            {
                "name": ctor.name,
                "id_hex": ctor.id_hex,
                "id": ctor.id_signed,
                "params": [p.render() for p in ctor.params],
                "tl": ctor.render(),
            }
        )
    return grouped
