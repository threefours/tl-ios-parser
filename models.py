from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Kind = Literal["constructor", "method"]


@dataclass(slots=True)
class FlagCondition:
    """Optional field gated by `flags.N?` / `flags2.N?`."""

    field: str
    bit: int

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "bit": self.bit}

    def __str__(self) -> str:
        return f"{self.field}.{self.bit}?"


@dataclass(slots=True)
class TypeExpr:
    """A TL type expression: `User`, `Vector<int>`, `flags.0?string`, `!X`, `%Message`."""

    name: str
    namespace: str | None = None
    args: list[TypeExpr] = field(default_factory=list)
    bare: bool = False
    bang: bool = False
    flag: FlagCondition | None = None
    is_nat: bool = False
    multiplicity: int | None = None
    bracket: bool = False

    @property
    def qualified(self) -> str:
        if self.is_nat:
            return "#"
        if self.namespace:
            return f"{self.namespace}.{self.name}"
        return self.name

    def render(self) -> str:
        if self.flag:
            return f"{self.flag}{self._render_core()}"
        return self._render_core()

    def _render_core(self) -> str:
        if self.is_nat:
            return "#"
        if self.multiplicity is not None:
            inner = self.args[0].render() if self.args else self.name
            return f"{self.multiplicity}*[{inner}]"
        if self.bracket:
            inner = self.args[0].render() if self.args else self.name
            return f"[{inner}]"
        prefix = ("!" if self.bang else "") + ("%" if self.bare else "")
        core = self.qualified
        if self.args:
            core += "<" + ",".join(a.render() for a in self.args) + ">"
        return prefix + core

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name}
        if self.namespace:
            data["namespace"] = self.namespace
        if self.args:
            data["args"] = [a.to_dict() for a in self.args]
        if self.bare:
            data["bare"] = True
        if self.bang:
            data["bang"] = True
        if self.flag:
            data["flag"] = self.flag.to_dict()
        if self.is_nat:
            data["nat"] = True
        if self.multiplicity is not None:
            data["multiplicity"] = self.multiplicity
        if self.bracket:
            data["bracket"] = True
        return data


@dataclass(slots=True)
class Parameter:
    name: str | None
    type: TypeExpr

    @property
    def optional(self) -> bool:
        return self.type.flag is not None

    @property
    def is_flags_field(self) -> bool:
        return self.type.is_nat

    def render(self) -> str:
        if self.name is None:
            return self.type.render()
        if self.type.is_nat:
            return f"{self.name}:#"
        return f"{self.name}:{self.type.render()}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.to_dict(),
            "optional": self.optional,
            "flags_field": self.is_flags_field,
        }


@dataclass(slots=True)
class GenericParam:
    name: str
    bound: str

    def render(self) -> str:
        return f"{{{self.name}:{self.bound}}}"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "bound": self.bound}


@dataclass(slots=True)
class Combinator:
    """A TL constructor (type/class case) or method (function)."""

    name: str
    kind: Kind
    id: int | None
    params: list[Parameter]
    result: TypeExpr
    generic_params: list[GenericParam] = field(default_factory=list)
    native: bool = False
    source: str = ""
    line: int = 0

    @property
    def namespace(self) -> str | None:
        if "." in self.name:
            return self.name.rsplit(".", 1)[0]
        return None

    @property
    def short_name(self) -> str:
        return self.name.rsplit(".", 1)[-1]

    @property
    def id_hex(self) -> str | None:
        if self.id is None:
            return None
        return f"{self.id & 0xFFFFFFFF:08x}"

    @property
    def id_signed(self) -> int | None:
        if self.id is None:
            return None
        value = self.id & 0xFFFFFFFF
        return value - 0x100000000 if value >= 0x80000000 else value

    @property
    def result_type(self) -> str:
        return self.result.qualified

    def render(self) -> str:
        left = self.name
        if self.id is not None:
            left += f"#{self.id_hex}"
        if self.native:
            left += " ?"
        generics = "".join(" " + g.render() for g in self.generic_params)
        args = "".join(" " + p.render() for p in self.params)
        return f"{left}{generics}{args} = {self.result.render()};"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "short_name": self.short_name,
            "namespace": self.namespace,
            "kind": self.kind,
            "id": self.id,
            "id_hex": self.id_hex,
            "id_signed": self.id_signed,
            "generic_params": [g.to_dict() for g in self.generic_params],
            "params": [p.to_dict() for p in self.params],
            "result": self.result.to_dict(),
            "result_type": self.result_type,
            "native": self.native,
            "tl": self.render(),
            "line": self.line,
        }


@dataclass(slots=True)
class Schema:
    layer: int | None
    constructors: list[Combinator]
    methods: list[Combinator]
    source_files: list[str] = field(default_factory=list)

    def combinators(self) -> list[Combinator]:
        return [*self.constructors, *self.methods]

    def by_name(self, name: str) -> list[Combinator]:
        key = name.lower()
        return [
            c
            for c in self.combinators()
            if c.name.lower() == key or c.short_name.lower() == key
        ]

    def by_id(self, ident: int | str) -> Combinator | None:
        if isinstance(ident, str):
            text = ident.strip().lower().removeprefix("#").removeprefix("0x")
            ident = int(text, 16) if any(ch in text for ch in "abcdef") or len(text) >= 7 else int(text, 0)
        want = ident & 0xFFFFFFFF
        for combinator in self.combinators():
            if combinator.id is not None and (combinator.id & 0xFFFFFFFF) == want:
                return combinator
        return None

    def constructors_of(self, type_name: str) -> list[Combinator]:
        key = type_name.lower()
        return [
            c
            for c in self.constructors
            if c.result.qualified.lower() == key or c.result.name.lower() == key
        ]

    def methods_in(self, namespace: str) -> list[Combinator]:
        key = namespace.lower()
        return [m for m in self.methods if (m.namespace or "").lower() == key]

    def types(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for c in self.constructors:
            grouped.setdefault(c.result_type, []).append(c.name)
        return grouped

    def namespaces(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for m in self.methods:
            grouped.setdefault(m.namespace or "", []).append(m.name)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        types = {
            type_name: {
                "constructors": [c.to_dict() for c in cons],
            }
            for type_name, cons in sorted(
                _group(self.constructors).items(), key=lambda kv: kv[0].lower()
            )
        }
        methods_ns = {
            ns: [m.to_dict() for m in items]
            for ns, items in sorted(
                _group_ns(self.methods).items(), key=lambda kv: kv[0].lower()
            )
        }
        return {
            "layer": self.layer,
            "source_files": self.source_files,
            "stats": {
                "constructors": len(self.constructors),
                "methods": len(self.methods),
                "types": len(types),
                "method_namespaces": len(methods_ns),
            },
            "types": types,
            "methods": methods_ns,
        }


def _group(items: list[Combinator]) -> dict[str, list[Combinator]]:
    out: dict[str, list[Combinator]] = {}
    for item in items:
        out.setdefault(item.result_type, []).append(item)
    return out


def _group_ns(items: list[Combinator]) -> dict[str, list[Combinator]]:
    out: dict[str, list[Combinator]] = {}
    for item in items:
        out.setdefault(item.namespace or "", []).append(item)
    return out
