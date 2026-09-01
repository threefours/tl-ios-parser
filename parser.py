from __future__ import annotations

import re
from pathlib import Path

from .models import (
    Combinator,
    FlagCondition,
    GenericParam,
    Kind,
    Parameter,
    Schema,
    TypeExpr,
)

LAYER_RE = re.compile(r"LAYER\s+(\d+)", re.IGNORECASE)
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class TLParseError(ValueError):
    pass


class Cursor:
    def __init__(self, text: str, *, line: int = 0, source: str = ""):
        self.text = text
        self.i = 0
        self.line = line
        self.source = source

    def remaining(self) -> str:
        return self.text[self.i :]

    def skip(self) -> None:
        while self.i < len(self.text) and self.text[self.i] in " \t":
            self.i += 1

    def eof(self) -> bool:
        self.skip()
        return self.i >= len(self.text)

    def peek(self) -> str:
        self.skip()
        return self.text[self.i] if self.i < len(self.text) else ""

    def startswith(self, token: str) -> bool:
        self.skip()
        return self.text.startswith(token, self.i)

    def consume(self, token: str) -> bool:
        self.skip()
        if self.text.startswith(token, self.i):
            self.i += len(token)
            return True
        return False

    def expect(self, token: str) -> None:
        if not self.consume(token):
            raise TLParseError(
                f"{self.source}:{self.line}: expected {token!r} at {self.remaining()!r}"
            )

    def parse_ident(self) -> str:
        self.skip()
        match = IDENT_RE.match(self.text, self.i)
        if not match:
            raise TLParseError(
                f"{self.source}:{self.line}: expected identifier at {self.remaining()!r}"
            )
        self.i = match.end()
        return match.group()

    def parse_int(self) -> int:
        self.skip()
        start = self.i
        while self.i < len(self.text) and self.text[self.i].isdigit():
            self.i += 1
        if start == self.i:
            raise TLParseError(
                f"{self.source}:{self.line}: expected integer at {self.remaining()!r}"
            )
        return int(self.text[start : self.i])

    def parse_hex(self) -> int:
        self.skip()
        start = self.i
        while self.i < len(self.text) and self.text[self.i] in "0123456789abcdefABCDEF":
            self.i += 1
        if start == self.i:
            raise TLParseError(
                f"{self.source}:{self.line}: expected hex at {self.remaining()!r}"
            )
        return int(self.text[start : self.i], 16)


def parse_type(cur: Cursor) -> TypeExpr:
    cur.skip()
    bang = cur.consume("!")
    bare = cur.consume("%")

    if cur.consume("#"):
        return TypeExpr(name="#", is_nat=True, bang=bang, bare=bare)

    if cur.peek() == "[":
        cur.expect("[")
        inner = parse_type(cur)
        cur.expect("]")
        return TypeExpr(name="Vector", args=[inner], bang=bang, bare=bare, bracket=True)

    if cur.peek().isdigit():
        count = cur.parse_int()
        cur.expect("*")
        cur.expect("[")
        inner = parse_type(cur)
        cur.expect("]")
        return TypeExpr(
            name="tuple",
            args=[inner],
            multiplicity=count,
            bang=bang,
            bare=bare,
        )

    name = cur.parse_ident()
    namespace_parts: list[str] = []

    while cur.peek() == ".":
        nxt = cur.text[cur.i + 1 : cur.i + 2] if cur.i + 1 < len(cur.text) else ""
        if nxt.isdigit():
            cur.expect(".")
            bit = cur.parse_int()
            cur.expect("?")
            inner = parse_type(cur)
            inner.flag = FlagCondition(field=name, bit=bit)
            inner.bang = inner.bang or bang
            inner.bare = inner.bare or bare
            return inner
        cur.expect(".")
        namespace_parts.append(name)
        name = cur.parse_ident()

    namespace = ".".join(namespace_parts) if namespace_parts else None
    args: list[TypeExpr] = []
    if cur.consume("<"):
        if cur.peek() != ">":
            args.append(parse_type(cur))
            while cur.consume(","):
                args.append(parse_type(cur))
        cur.expect(">")

    # Result types like `Vector t` (generic application without <>).
    if not args:
        saved = cur.i
        try:
            if not cur.eof() and cur.peek() not in "=;>{},[]":
                maybe = cur.peek()
                if maybe.isalpha() or maybe in "_%!":
                    # Only treat as application for known generic heads.
                    if name in {"Vector", "vector"}:
                        args.append(parse_type(cur))
                    else:
                        cur.i = saved
        except TLParseError:
            cur.i = saved

    return TypeExpr(
        name=name,
        namespace=namespace,
        args=args,
        bang=bang,
        bare=bare,
    )


def parse_generic_param(cur: Cursor) -> GenericParam:
    cur.expect("{")
    name = cur.parse_ident()
    cur.expect(":")
    bound = cur.parse_ident()
    cur.expect("}")
    return GenericParam(name=name, bound=bound)


def parse_parameter(cur: Cursor) -> Parameter:
    saved = cur.i
    if cur.peek().isalpha() or cur.peek() == "_":
        name = cur.parse_ident()
        if cur.consume(":"):
            return Parameter(name=name, type=parse_type(cur))
        cur.i = saved
    return Parameter(name=None, type=parse_type(cur))


def parse_combinator(line: str, *, kind: Kind, source: str, lineno: int) -> Combinator:
    cur = Cursor(line.rstrip(), line=lineno, source=source)
    name_head = cur.parse_ident()
    parts = [name_head]
    while cur.peek() == ".":
        nxt = cur.text[cur.i + 1 : cur.i + 2] if cur.i + 1 < len(cur.text) else ""
        if nxt.isdigit():
            break
        cur.expect(".")
        parts.append(cur.parse_ident())
    name = ".".join(parts)

    ident: int | None = None
    if cur.peek() == "#":
        lookahead = cur.text[cur.i + 1 : cur.i + 2] if cur.i + 1 < len(cur.text) else ""
        if lookahead and lookahead in "0123456789abcdefABCDEF":
            cur.expect("#")
            ident = cur.parse_hex()

    native = cur.consume("?")

    generics: list[GenericParam] = []
    while cur.peek() == "{":
        generics.append(parse_generic_param(cur))

    params: list[Parameter] = []
    while not cur.eof() and cur.peek() != "=":
        params.append(parse_parameter(cur))

    cur.expect("=")
    result = parse_type(cur)
    cur.consume(";")
    if not cur.eof():
        raise TLParseError(
            f"{source}:{lineno}: trailing input {cur.remaining()!r} in {line!r}"
        )

    return Combinator(
        name=name,
        kind=kind,
        id=ident,
        params=params,
        result=result,
        generic_params=generics,
        native=native,
        source=source,
        line=lineno,
    )


def parse_text(text: str, *, source: str = "<memory>", default_kind: Kind = "constructor") -> Schema:
    layer: int | None = None
    kind: Kind = default_kind
    constructors: list[Combinator] = []
    methods: list[Combinator] = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("//"):
            match = LAYER_RE.search(line)
            if match:
                layer = int(match.group(1))
            continue
        if line.startswith("---") and line.endswith("---"):
            section = line.strip("-").strip().lower()
            if section == "functions":
                kind = "method"
            elif section in {"types", "constructors"}:
                kind = "constructor"
            else:
                raise TLParseError(f"{source}:{lineno}: unknown section {line!r}")
            continue

        combinator = parse_combinator(line, kind=kind, source=source, lineno=lineno)
        if combinator.kind == "method":
            methods.append(combinator)
        else:
            constructors.append(combinator)

    return Schema(
        layer=layer,
        constructors=constructors,
        methods=methods,
        source_files=[source],
    )


def parse_file(path: str | Path, *, default_kind: Kind = "constructor") -> Schema:
    path = Path(path)
    return parse_text(
        path.read_text(encoding="utf-8"),
        source=str(path),
        default_kind=default_kind,
    )


def merge_schemas(*schemas: Schema) -> Schema:
    layer = next((s.layer for s in schemas if s.layer is not None), None)
    constructors: list[Combinator] = []
    methods: list[Combinator] = []
    files: list[str] = []
    seen_ctor: set[tuple[str, int | None]] = set()
    seen_method: set[tuple[str, int | None]] = set()
    for schema in schemas:
        files.extend(schema.source_files)
        if schema.layer is not None:
            layer = schema.layer
        for item in schema.constructors:
            key = (item.name, item.id)
            if key in seen_ctor:
                continue
            seen_ctor.add(key)
            constructors.append(item)
        for item in schema.methods:
            key = (item.name, item.id)
            if key in seen_method:
                continue
            seen_method.add(key)
            methods.append(item)
    return Schema(
        layer=layer,
        constructors=constructors,
        methods=methods,
        source_files=files,
    )


def schema_dir() -> Path:
    return Path(__file__).resolve().parent / "schema"


def load_layer_schema(directory: str | Path | None = None) -> Schema:
    directory = Path(directory) if directory else schema_dir()
    mtproto = parse_file(directory / "mtproto.tl")
    api = parse_file(directory / "api.tl")
    return merge_schemas(mtproto, api)
