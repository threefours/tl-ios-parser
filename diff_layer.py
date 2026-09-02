"""Readable diff of two IPA layer dumps (or two IPAs / binaries)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .from_ipa import extract_from_path


def _type_str(typ: Any) -> str:
    if not isinstance(typ, dict):
        return str(typ or "?")
    if typ.get("nat") or typ.get("name") == "#":
        return "#"
    prefix = ""
    if typ.get("bang"):
        prefix += "!"
    if typ.get("bare"):
        prefix += "%"
    name = typ.get("name") or "?"
    ns = typ.get("namespace")
    core = f"{ns}.{name}" if ns else name
    args = typ.get("args") or []
    if typ.get("bracket"):
        inner = _type_str(args[0]) if args else core
        n = typ.get("multiplicity")
        core = f"{n}*[{inner}]" if n is not None else f"[{inner}]"
    elif args:
        core += "<" + ",".join(_type_str(a) for a in args) + ">"
    rendered = prefix + core
    flag = typ.get("flag")
    if isinstance(flag, dict) and flag.get("field") is not None:
        rendered = f"{flag['field']}.{flag.get('bit', '?')}?{rendered}"
    return rendered


def _param_str(param: dict) -> str:
    name = param.get("name") or "_"
    typ = param.get("type") or {}
    if param.get("flags_field") or (isinstance(typ, dict) and typ.get("nat")):
        return f"{name}:#"
    rendered = _type_str(typ)
    if param.get("optional") and "?" not in rendered:
        return f"{name}:{rendered}?"
    return f"{name}:{rendered}"


def _result_str(method: dict) -> str:
    if method.get("result_type"):
        return str(method["result_type"])
    result = method.get("result")
    if isinstance(result, dict):
        return _type_str(result)
    if isinstance(result, str):
        return result
    return "Unknown"


def _params_list(item: dict) -> list[dict]:
    return [p for p in (item.get("params") or []) if isinstance(p, dict)]


def _signature(item: dict) -> dict[str, Any]:
    params = _params_list(item)
    return {
        "param_text": [_param_str(p) for p in params],
        "result": _result_str(item),
        "id_hex": item.get("id_hex"),
        "tl": item.get("tl") or "",
    }


def _looks_like_json(path: Path) -> bool:
    if path.suffix.lower() == ".json":
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(64).lstrip()
    except OSError:
        return False
    return chunk.startswith(b"{") or chunk.startswith(b"[")


def _load(path: Path) -> dict:
    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    if path.is_file() and _looks_like_json(path):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not a layer JSON object")
        return data
    return extract_from_path(path)


def _methods_map(data: dict) -> dict[str, dict]:
    methods = data.get("methods")
    if isinstance(methods, list):
        return {m["name"]: m for m in methods if isinstance(m, dict) and m.get("name")}
    if isinstance(methods, dict):
        out: dict[str, dict] = {}
        for items in methods.values():
            for method in items or []:
                if isinstance(method, dict) and method.get("name"):
                    out[method["name"]] = method
        return out
    names = data.get("method_names") or []
    return {name: {"name": name, "params": [], "result_type": "Unknown"} for name in names}


def _constructors_map(data: dict) -> dict[str, dict]:
    types = data.get("types")
    if not isinstance(types, dict):
        return {}
    out: dict[str, dict] = {}
    for blob in types.values():
        if not isinstance(blob, dict):
            continue
        for ctor in blob.get("constructors") or []:
            if isinstance(ctor, dict) and ctor.get("name"):
                out[ctor["name"]] = ctor
    return out


def _namespace(name: str) -> str:
    return name.split(".", 1)[0] if "." in name else "(root)"


def _param_changes(old_item: dict, new_item: dict) -> list[dict[str, Any]]:
    old_params = _params_list(old_item)
    new_params = _params_list(new_item)
    old_by: dict[str, dict] = {}
    new_by: dict[str, dict] = {}
    for param in old_params:
        old_by.setdefault(param.get("name") or "_", param)
    for param in new_params:
        new_by.setdefault(param.get("name") or "_", param)

    changes: list[dict[str, Any]] = []
    for name in new_by:
        if name not in old_by:
            changes.append({"kind": "param+", "text": _param_str(new_by[name])})
        else:
            old_text = _param_str(old_by[name])
            new_text = _param_str(new_by[name])
            if old_text != new_text:
                changes.append(
                    {
                        "kind": "param~",
                        "name": name,
                        "old": old_text.split(":", 1)[-1],
                        "new": new_text.split(":", 1)[-1],
                    }
                )
    for name in old_by:
        if name not in new_by:
            changes.append({"kind": "param-", "text": _param_str(old_by[name])})

    old_order = [p.get("name") or "_" for p in old_params]
    new_order = [p.get("name") or "_" for p in new_params]
    if old_order != new_order and set(old_order) == set(new_order):
        changes.append(
            {
                "kind": "params-order",
                "old": [_param_str(p) for p in old_params],
                "new": [_param_str(p) for p in new_params],
            }
        )
    return changes


def _diff_named(old_map: dict[str, dict], new_map: dict[str, dict]) -> dict[str, Any]:
    old_names = set(old_map)
    new_names = set(new_map)
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)
    changed: list[dict[str, Any]] = []

    for name in sorted(old_names & new_names):
        left = _signature(old_map[name])
        right = _signature(new_map[name])
        if left == right:
            continue
        entry: dict[str, Any] = {"name": name, "changes": _param_changes(old_map[name], new_map[name])}
        if left["result"] != right["result"]:
            entry["changes"].append(
                {"kind": "result", "old": left["result"], "new": right["result"]}
            )
        if left["id_hex"] != right["id_hex"] and (left["id_hex"] or right["id_hex"]):
            entry["changes"].append(
                {"kind": "id", "old": left["id_hex"], "new": right["id_hex"]}
            )
        if not entry["changes"]:
            if left["tl"] != right["tl"]:
                entry["changes"].append({"kind": "tl", "old": left["tl"], "new": right["tl"]})
            else:
                continue
        changed.append(entry)

    return {
        "added": [{"name": name, "tl": new_map[name].get("tl") or name} for name in added],
        "removed": [{"name": name, "tl": old_map[name].get("tl") or name} for name in removed],
        "changed": changed,
    }


def diff_dumps(old: dict, new: dict) -> dict[str, Any]:
    methods = _diff_named(_methods_map(old), _methods_map(new))
    result: dict[str, Any] = {
        "old_layer": old.get("layer"),
        "new_layer": new.get("layer"),
        "added": methods["added"],
        "removed": methods["removed"],
        "changed": methods["changed"],
    }
    old_ctors = _constructors_map(old)
    new_ctors = _constructors_map(new)
    if old_ctors or new_ctors:
        ctors = _diff_named(old_ctors, new_ctors)
        result["constructors_added"] = ctors["added"]
        result["constructors_removed"] = ctors["removed"]
        result["constructors_changed"] = ctors["changed"]
    return result


def _grouped(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        buckets.setdefault(_namespace(item["name"]), []).append(item)
    return buckets


def _format_named(lines: list[str], title: str, added: list, removed: list, changed: list) -> None:
    if added:
        lines.append("")
        lines.append(f"{title} added ({len(added)})")
        for ns, items in _grouped(added).items():
            lines.append(f"  [{ns}]")
            for item in items:
                lines.append(f"    + {item['tl']}")
    if removed:
        lines.append("")
        lines.append(f"{title} removed ({len(removed)})")
        for ns, items in _grouped(removed).items():
            lines.append(f"  [{ns}]")
            for item in items:
                lines.append(f"    - {item['tl']}")
    if changed:
        lines.append("")
        lines.append(f"{title} changed ({len(changed)})")
        for item in changed:
            lines.append(f"  {item['name']}")
            for change in item["changes"]:
                kind = change["kind"]
                if kind == "param+":
                    lines.append(f"    + {change['text']}")
                elif kind == "param-":
                    lines.append(f"    - {change['text']}")
                elif kind == "param~":
                    lines.append(f"    ~ {change['name']}: {change['old']} -> {change['new']}")
                elif kind == "params-order":
                    lines.append("    ~ param order")
                    lines.append(f"        old: {' '.join(change['old'])}")
                    lines.append(f"        new: {' '.join(change['new'])}")
                elif kind == "result":
                    lines.append(f"    ~ result {change['old']} -> {change['new']}")
                elif kind == "id":
                    lines.append(f"    ~ id #{change['old']} -> #{change['new']}")
                elif kind == "tl":
                    lines.append(f"    ~ {change['old']}")
                    lines.append(f"      {change['new']}")


def format_diff(diff: dict[str, Any], *, brief: bool = False) -> str:
    lines: list[str] = []
    old_layer = diff.get("old_layer")
    new_layer = diff.get("new_layer")
    if old_layer != new_layer:
        lines.append(f"layer {old_layer} -> {new_layer}")
    else:
        lines.append(f"layer {new_layer}")

    added = diff["added"]
    removed = diff["removed"]
    changed = diff["changed"]
    ctor_added = diff.get("constructors_added") or []
    ctor_removed = diff.get("constructors_removed") or []
    ctor_changed = diff.get("constructors_changed") or []
    lines.append(
        f"methods  +{len(added)}  -{len(removed)}  ~{len(changed)}"
    )
    if ctor_added or ctor_removed or ctor_changed:
        lines.append(
            f"types    +{len(ctor_added)}  -{len(ctor_removed)}  ~{len(ctor_changed)}"
        )

    empty = not (
        added or removed or changed or ctor_added or ctor_removed or ctor_changed
    )
    if empty:
        if old_layer != new_layer:
            lines.append("no method differences")
        else:
            lines.append("no API differences")
        return "\n".join(lines) + "\n"
    if brief:
        return "\n".join(lines) + "\n"

    _format_named(lines, "methods", added, removed, changed)
    if ctor_added or ctor_removed or ctor_changed:
        _format_named(lines, "types", ctor_added, ctor_removed, ctor_changed)
    return "\n".join(lines) + "\n"


def diff_paths(old_path: Path, new_path: Path) -> dict[str, Any]:
    return diff_dumps(_load(old_path), _load(new_path))


def has_changes(diff: dict[str, Any]) -> bool:
    if diff.get("old_layer") != diff.get("new_layer"):
        return True
    return bool(
        diff["added"]
        or diff["removed"]
        or diff["changed"]
        or diff.get("constructors_added")
        or diff.get("constructors_removed")
        or diff.get("constructors_changed")
    )
