"""Decode TelegramApi FunctionDescription signatures from the IPA binary.

The compiled Swift methods live in LINKEDIT as mangled fragments:

    [optional truncated name][labels]AA19FunctionDescriptionC_[types]tFZ

Word substitutions (`0I6Markup` → `replyMarkup`) are resolved by replaying
the identifier words from `TelegramApi` / `Api` / `functions` / namespace /
method name, matching Swift's 26-word table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Parameter, TypeExpr

MARKER = "AA19FunctionDescriptionC_"
MAX_WORDS = 26

KNOWN_S = {
    "A": "AutoreleasingUnsafeMutablePointer",
    "a": "Array",
    "b": "Bool",
    "d": "Float64",
    "f": "Float32",
    "h": "Set",
    "i": "Int",
    "q": "Optional",
    "S": "String",
    "s": "Substring",
    "u": "UInt",
}

SWIFT_PRIMITIVE = {
    "Int32": "int",
    "Int64": "long",
    "UInt32": "int",
    "UInt64": "long",
    "Int": "int",
    "String": "string",
    "Bool": "Bool",
    "Float32": "double",
    "Float64": "double",
    "Double": "double",
}

METHOD_STRING = re.compile(
    r"(?:account|auth|bots|channels|chatlists|communities|contacts|ephemeral|"
    r"folders|fragment|help|langpack|messages|payments|phone|photos|premium|"
    r"smsjobs|stats|stickers|stories|updates|upload|users|aicompose)"
    r"\.[a-zA-Z][a-zA-Z0-9]*"
)


def is_lower(ch: str) -> bool:
    return "a" <= ch <= "z"


def is_upper(ch: str) -> bool:
    return "A" <= ch <= "Z"


def is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def is_letter(ch: str) -> bool:
    return is_lower(ch) or is_upper(ch)


def is_word_start(ch: str) -> bool:
    return bool(ch) and not is_digit(ch) and ch != "_"


def is_word_end(ch: str, prev: str) -> bool:
    if ch in ("_", "") or ch == "\0":
        return True
    return (not is_upper(prev)) and is_upper(ch)


def ident_words(ident: str) -> list[str]:
    words: list[str] = []
    start = -1
    n = len(ident)
    for idx in range(n + 1):
        ch = ident[idx] if idx < n else ""
        if start >= 0 and is_word_end(ch, ident[idx - 1]):
            if idx - start >= 2:
                words.append(ident[start:idx])
            start = -1
        if start < 0 and ch and is_word_start(ch):
            start = idx
    return words


class WordTable:
    def __init__(self) -> None:
        self.words: list[str] = []

    def add_ident(self, ident: str) -> None:
        for word in ident_words(ident):
            if len(self.words) >= MAX_WORDS:
                return
            if word not in self.words:
                self.words.append(word)

    def seed(self, namespace: str, method: str) -> None:
        for ident in ("TelegramApi", "functions", namespace, method):
            if ident:
                self.add_ident(ident)

    def snapshot(self) -> list[str]:
        return list(self.words)

    def restore(self, words: list[str]) -> None:
        self.words = list(words)


def _natural(text: str, i: int) -> tuple[int | None, int]:
    if i >= len(text) or not is_digit(text[i]) or text[i] == "0":
        return None, i
    j = i
    while j < len(text) and is_digit(text[j]):
        j += 1
    return int(text[i:j]), j


def parse_identifier(text: str, i: int, words: WordTable) -> tuple[str | None, int]:
    """Parse one Swift identifier. Returns (name, new_index) or (None, i)."""
    if i >= len(text) or not is_digit(text[i]):
        return None, i
    has_word = False
    puny = False
    if text[i] == "0":
        i += 1
        if i < len(text) and text[i] == "0":
            i += 1
            puny = True
        else:
            has_word = True
    out: list[str] = []
    while True:
        while has_word and i < len(text) and is_letter(text[i]):
            ch = text[i]
            i += 1
            if is_lower(ch):
                idx = ord(ch) - ord("a")
            else:
                idx = ord(ch) - ord("A")
                has_word = False
            if idx >= len(words.words):
                return None, i
            out.append(words.words[idx])
        if i < len(text) and text[i] == "0":
            i += 1
            break
        n, j = _natural(text, i)
        if n is None or n <= 0:
            if out:
                break
            return None, i
        i = j
        if puny and i < len(text) and text[i] == "_":
            i += 1
        if i + n > len(text):
            return None, i
        slice_ = text[i : i + n]
        i += n
        out.append(slice_)
        if not puny:
            words.add_ident(slice_)
        if not has_word:
            break
    name = "".join(out)
    if not name:
        return None, i
    return name, i


def parse_bare_ident(text: str, i: int) -> tuple[str, int]:
    j = i
    while j < len(text) and (text[j].isalnum() or text[j] == "_"):
        if j > i and is_digit(text[j]):
            break
        j += 1
    return text[i:j], j


@dataclass
class ParsedSig:
    name_fragment: str
    labels: list[str]
    params: list[Parameter]
    result: TypeExpr
    raw_head: str
    raw_types: str
    truncated: bool = False
    parse_ok: bool = True
    notes: list[str] = field(default_factory=list)


def _skip_junk(text: str) -> int:
    i = 0
    while i < len(text) and not (text[i].isalnum()):
        i += 1
    return i


_METHOD_PREFIXES = (
    "get", "set", "send", "load", "save", "init", "drop", "read", "edit", "join",
    "leave", "create", "delete", "update", "toggle", "check", "clear", "confirm",
    "cancel", "accept", "request", "report", "search", "query", "bind", "apply",
    "import", "export", "upload", "download", "install", "reset", "start", "stop",
    "add", "remove", "register", "enable", "disable", "fetch", "resolve",
    "discard", "process", "finish", "begin", "complete", "verify", "validate",
    "translate", "forward", "invite", "hide", "show", "mark", "reorder",
    "transfer", "convert", "upgrade", "refund", "fulfill", "change", "decline",
    "resend", "sign", "auth", "connect", "disconnect", "count", "list", "find",
    "archive", "pin", "unpin", "mute", "block", "unblock", "ban", "unban",
    "promote", "restrict", "reject", "approve", "grant", "revoke", "share",
    "collect", "claim", "boost", "gift", "buy", "pay", "withdraw", "compose",
    "summarize", "transcribe", "click", "open", "close", "parse", "increment",
    "log", "restore", "backup", "migrate", "replace", "append", "preview",
    "publish", "unpublish", "subscribe", "unsubscribe", "notify", "broadcast",
)


def _looks_like_method(name: str) -> bool:
    if not name or not name[0].islower():
        return False
    lower = name.lower()
    return any(lower.startswith(p) for p in _METHOD_PREFIXES)


def name_fragment(head: str) -> str:
    best = ""
    best_score = (-1, -1)
    limit = min(len(head), 40)
    for i in range(limit):
        if is_digit(head[i]) and head[i] != "0":
            n, j = _natural(head, i)
            if n and j + n <= len(head):
                ident = head[j : j + n]
                rest = head[j + n :]
                if ident and ident[0].isalpha() and (not rest or is_digit(rest[0])):
                    score = (2 if _looks_like_method(ident) else 1 if ident[0].islower() else 0, len(ident))
                    if score > best_score:
                        best, best_score = ident, score
        if is_letter(head[i]):
            if i > 0 and is_letter(head[i - 1]):
                isolated_upper = is_upper(head[i - 1]) and is_lower(head[i]) and (
                    i < 2 or not is_letter(head[i - 2])
                )
                glued, _ = parse_bare_ident(head, i)
                if not (isolated_upper and _looks_like_method(glued)):
                    continue
            frag, k = parse_bare_ident(head, i)
            rest = head[k:]
            if len(frag) >= 4 and (not rest or is_digit(rest[0])):
                if _looks_like_method(frag):
                    score = (2, len(frag))
                elif is_upper(frag[0]) and any(is_upper(c) for c in frag[1:]):
                    score = (1, len(frag))
                else:
                    score = (0, len(frag))
                if score > best_score:
                    best, best_score = frag, score
    if best and not _looks_like_method(best) and is_upper(best[0]) and len(best) > 4 and _looks_like_method(best[1:]):
        best = best[1:]
    return best


def parse_all_labels(text: str, i: int, words: WordTable) -> tuple[list[str] | None, int]:
    labels: list[str] = []
    while i < len(text):
        lab, i2 = parse_identifier(text, i, words)
        if lab is None:
            return None, i
        labels.append(lab)
        i = i2
    return labels, i


def parse_head(text: str, words: WordTable, *, expect_method: str | None = None) -> tuple[str, list[str], bool] | None:
    """Return (method_fragment, labels, truncated) or None."""
    i = _skip_junk(text)
    if i >= len(text):
        return None

    if expect_method:
        pref = f"{len(expect_method)}{expect_method}"
        saved = words.snapshot()
        for start in range(min(len(text), 40)):
            words.restore(saved)
            if text.startswith(pref, start):
                labels, end = parse_all_labels(text, start + len(pref), words)
                if labels is not None and end == len(text):
                    return expect_method, labels, False
            for cut in range(0, max(1, len(expect_method) - 2)):
                words.restore(saved)
                suf = expect_method[cut:]
                if len(suf) < 3 or not text.startswith(suf, start):
                    continue
                labels, end = parse_all_labels(text, start + len(suf), words)
                if labels is not None and end == len(text):
                    return expect_method, labels, cut > 0 or start > 0
        words.restore(saved)
        return None

    truncated = False
    if is_digit(text[i]) and text[i] != "0":
        n, j = _natural(text, i)
        ident = text[j : j + n] if n and j + n <= len(text) else ""
        rest = text[j + n :] if n and j + n <= len(text) else "x"
        if ident and ident[0].isalpha() and (not rest or rest[0].isdigit() or rest.startswith("AA")):
            words.add_ident(ident)
            labels, end = parse_all_labels(text, j + n, words)
            if labels is not None and end == len(text):
                return ident, labels, False
        while i < len(text) and is_digit(text[i]):
            i += 1
        truncated = True
    elif text[i] == "0" and i + 1 < len(text) and is_letter(text[i + 1]):
        name, i2 = parse_identifier(text, i, words)
        if name is not None:
            labels, end = parse_all_labels(text, i2, words)
            if labels is not None and end == len(text):
                return name, labels, False
        i += 1
        truncated = True
    elif is_letter(text[i]):
        truncated = True
    else:
        return None

    name, i = parse_bare_ident(text, i)
    if not name:
        return None
    words.add_ident(name)
    labels, end = parse_all_labels(text, i, words)
    if labels is None or end != len(text):
        return None
    return name, labels, truncated


def _parse_subst_indices(text: str, i: int) -> tuple[list[int] | None, int]:
    """Parse `A…` substitution. Returns substitution indices."""
    if i >= len(text) or text[i] != "A":
        return None, i
    i += 1
    if i >= len(text):
        return None, i
    if is_digit(text[i]):
        n, j = _natural(text, i)
        if n is None:
            return None, i
        if j < len(text) and text[j] == "_":
            return [n], j + 1
        if j < len(text) and is_letter(text[j]):
            i = j
        else:
            return [n + 26], j
    if text[i] == "_":
        return [0], i + 1
    indices: list[int] = []
    while i < len(text):
        repeat = 1
        if is_digit(text[i]) and text[i] != "0":
            n, i = _natural(text, i)
            if n is None:
                break
            repeat = n
        if i >= len(text) or not is_letter(text[i]):
            break
        ch = text[i]
        i += 1
        if is_lower(ch):
            idx = ord(ch) - ord("a")
            indices.extend([idx] * repeat)
        else:
            idx = ord(ch) - ord("A")
            indices.extend([idx] * repeat)
            return indices, i
    return (indices if indices else None), i


class TypeParser:
    def __init__(self, words: WordTable) -> None:
        self.words = words
        self.substs: list[str] = []

    def remember(self, name: str) -> str:
        if name and name not in ("Vector", "Optional"):
            self.substs.append(name)
        return name

    def parse_type(self, text: str, i: int) -> tuple[TypeExpr | None, int]:
        if i >= len(text):
            return None, i
        t, j = self._parse_nominal(text, i)
        if t is None:
            return None, i
        while j < len(text) - 1 and text[j : j + 2] == "Sg":
            t = TypeExpr(name="Optional", args=[t], flag=None)
            j += 2
        return t, j

    def _parse_nominal(self, text: str, i: int) -> tuple[TypeExpr | None, int]:
        if text.startswith("Say", i):
            inner, j = self.parse_type(text, i + 3)
            if inner is None or j >= len(text) or text[j] != "G":
                return None, i
            return TypeExpr(name="Vector", args=[inner]), j + 1

        if i < len(text) and text[i] == "S":
            j = i + 1
            repeat = 1
            if j < len(text) and is_digit(text[j]) and text[j] != "0":
                n, j2 = _natural(text, j)
                if n is not None:
                    repeat = n
                    j = j2
            if j < len(text) and text[j] in KNOWN_S:
                name = KNOWN_S[text[j]]
                j += 1
                mapped = SWIFT_PRIMITIVE.get(name, name)
                if repeat == 1:
                    return TypeExpr(name=mapped), j
                return TypeExpr(name="Repeat", args=[TypeExpr(name=mapped)], multiplicity=repeat), j

        if text.startswith("s", i) and i + 1 < len(text) and is_digit(text[i + 1]):
            ident, j = parse_identifier(text, i + 1, self.words)
            if ident is None:
                return None, i
            if j < len(text) and text[j] in "COV":
                j += 1
            mapped = SWIFT_PRIMITIVE.get(ident, ident)
            self.remember(mapped)
            return TypeExpr(name=mapped), j

        if i < len(text) and text[i] == "A":
            idxs, j = _parse_subst_indices(text, i)
            if idxs is None:
                return None, i
            base = None
            if len(idxs) == 1 and idxs[0] < len(self.substs):
                base = self.substs[idxs[0]]
            if j < len(text) and (is_digit(text[j]) or text[j] == "0"):
                ident, k = parse_identifier(text, j, self.words)
                if ident is None:
                    if base:
                        return TypeExpr(name=base), j
                    return TypeExpr(name=f"subst_{idxs[0]}" if idxs else "subst"), j
                j = k
                if j < len(text) and text[j] in "COV":
                    j += 1
                self.remember(ident)
                return TypeExpr(name=ident), j
            if base:
                return TypeExpr(name=base), j
            return TypeExpr(name=f"subst_{idxs[0]}" if idxs else "subst"), j

        if i < len(text) and is_digit(text[i]):
            ident, j = parse_identifier(text, i, self.words)
            if ident is None:
                return None, i
            if j < len(text) and text[j] in "COV":
                j += 1
            self.remember(ident)
            return TypeExpr(name=ident), j

        return None, i

    def parse_type_list(self, text: str) -> list[TypeExpr] | None:
        if not text:
            return []
        i = 0
        first, i = self.parse_type(text, i)
        if first is None:
            return None
        types = [first]
        if i < len(text) and text[i] == "_":
            i += 1
            while i < len(text):
                t, i = self.parse_type(text, i)
                if t is None:
                    return None
                types.extend(self._flatten(t))
            return types if i == len(text) else None
        types = self._flatten(first)
        return types if i == len(text) else None

    @staticmethod
    def _flatten(t: TypeExpr) -> list[TypeExpr]:
        if t.name == "Repeat" and t.multiplicity and t.args:
            return [t.args[0]] * t.multiplicity
        return [t]


def _unwrap_optional(t: TypeExpr) -> tuple[TypeExpr, bool]:
    if t.name == "Optional" and t.args:
        inner, inner_opt = _unwrap_optional(t.args[0])
        return inner, True
    return t, False


def _is_word_subst_g(text: str, g_index: int) -> bool:
    """True if G at g_index is the last-word letter inside a `0…G0` substitution."""
    i = g_index
    if i + 1 < len(text) and text[i + 1] == "0":
        k = i - 1
        while k >= 0 and is_lower(text[k]):
            k -= 1
        if k >= 0 and text[k] == "0":
            return True
    return False


def split_result_and_params(type_blob: str) -> tuple[str, str]:
    """Split FunctionDescription type payload into (result_mangled, params_mangled)."""
    if type_blob.endswith("tyFZ"):
        return type_blob[:-4], ""
    if not type_blob.endswith("tFZ"):
        return type_blob, ""
    body = type_blob[:-3]
    last_gt = -1
    i = 0
    while i < len(body) - 1:
        if body[i] == "0" and i + 1 < len(body) and is_letter(body[i + 1]):
            ident, j = parse_identifier(body, i, WordTable())
            if ident is not None and j > i:
                i = j
                continue
        if body[i : i + 2] == "Gt" and not _is_word_subst_g(body, i):
            last_gt = i
        i += 1
    if last_gt >= 0:
        return body[: last_gt + 2], body[last_gt + 2 :]
    return body, ""


def _result_name(result_blob: str, words: WordTable) -> TypeExpr:
    y = result_blob.rfind("y")
    chunk = result_blob[y + 1 :] if y >= 0 else result_blob
    if chunk.endswith("Gt"):
        chunk = chunk[:-2]
    elif chunk.endswith("G"):
        chunk = chunk[:-1]
    parser = TypeParser(words)
    t, j = parser.parse_type(chunk, 0)
    if t is not None and j == len(chunk):
        inner, _ = _unwrap_optional(t)
        if inner.name not in {"", "Unknown"} and not inner.name.startswith("subst"):
            return inner
    i = 0
    last = None
    while i < len(chunk):
        if is_digit(chunk[i]) or (chunk[i] == "0" and i + 1 < len(chunk) and is_letter(chunk[i + 1])):
            ident, j = parse_identifier(chunk, i, words)
            if ident:
                last = ident
                i = j
                continue
        i += 1
    if last:
        return TypeExpr(name=last)
    idents = re.findall(r"[1-9][0-9]*([A-Za-z][A-Za-z0-9]*)", chunk)
    if idents:
        return TypeExpr(name=idents[-1])
    return TypeExpr(name=chunk or "Unknown")


_FALLBACK_BY_LABEL = {
    "scheduleDate": "int",
    "scheduleRepeatPeriod": "int",
    "sendAs": "InputPeer",
    "effect": "long",
    "allowPaidStars": "long",
    "randomId": "long",
    "offset": "int",
    "limit": "int",
    "hash": "long",
    "topMsgId": "int",
    "msgId": "int",
    "queryId": "long",
    "minId": "int",
    "maxId": "int",
    "addOffset": "int",
    "maxId": "int",
}


def zip_params(labels: list[str], types: list[TypeExpr] | None) -> list[Parameter]:
    types = types or []
    n = max(len(labels), len(types))
    out: list[Parameter] = []
    for i in range(n):
        name = labels[i] if i < len(labels) else None
        if i < len(types):
            typ, optional = _unwrap_optional(types[i])
        else:
            typ, optional = TypeExpr(name="Unknown"), False
        if name == "flags" and typ.name in {"int", "Int32"}:
            typ = TypeExpr(name="#", is_nat=True)
            optional = False
        elif name and typ.name.startswith("subst_") and name in _FALLBACK_BY_LABEL:
            typ = TypeExpr(name=_FALLBACK_BY_LABEL[name], args=typ.args)
        out.append(Parameter(name=name, type=_mark_optional(typ, optional)))
    return out


def _mark_optional(typ: TypeExpr, optional: bool) -> TypeExpr:
    if not optional or typ.is_nat:
        return typ
    if typ.flag is not None:
        return typ
    from .models import FlagCondition

    return TypeExpr(
        name=typ.name,
        namespace=typ.namespace,
        args=typ.args,
        bare=typ.bare,
        bang=typ.bang,
        flag=FlagCondition(field="flags", bit=-1),
        is_nat=typ.is_nat,
        multiplicity=typ.multiplicity,
        bracket=typ.bracket,
    )


def absorb_idents(text: str, words: WordTable) -> None:
    i = 0
    while i < len(text):
        if is_digit(text[i]) and text[i] != "0":
            ident, j = parse_identifier(text, i, words)
            if ident is not None:
                i = j
                continue
        i += 1


def camel_suffix_ok(short: str, frag: str) -> bool:
    if short == frag:
        return True
    if not frag or not short.endswith(frag):
        return False
    cut = len(short) - len(frag)
    if cut <= 0:
        return False
    return is_upper(frag[0]) or not is_letter(short[cut - 1])


def parse_signature(head: str, type_blob: str, *, namespace: str = "", method: str = "") -> ParsedSig | None:
    words = WordTable()
    words.seed(namespace, method or "")
    parsed = parse_head(head, words, expect_method=method or None)
    if parsed is None:
        words = WordTable()
        words.seed(namespace, method or "")
        parsed = parse_head(head, words, expect_method=None)
        if parsed is None:
            return None
    name, labels, truncated = parsed
    result_blob, params_blob = split_result_and_params(type_blob)
    words.add_ident("FunctionDescription")
    absorb_idents(result_blob, words)
    tparser = TypeParser(words)
    types = tparser.parse_type_list(params_blob)
    result = _result_name(result_blob, words)
    notes = []
    if types is None:
        notes.append("param_types_unparsed")
        types = []
    elif labels and types and len(types) != len(labels):
        notes.append(f"arity {len(labels)} labels vs {len(types)} types")
    params = zip_params(labels, types)
    return ParsedSig(
        name_fragment=name,
        labels=labels,
        params=params,
        result=result,
        raw_head=head,
        raw_types=type_blob,
        truncated=truncated,
        parse_ok=not notes,
        notes=notes,
    )


def iter_raw_signatures(data: bytes) -> list[tuple[str, str]]:
    marker = MARKER.encode("ascii")
    out: list[tuple[str, str]] = []
    pos = 0
    while True:
        j = data.find(marker, pos)
        if j < 0:
            break
        start = data.rfind(b"\x00", max(0, j - 500), j) + 1
        end = data.find(b"\x00", j)
        if end < 0:
            end = min(len(data), j + 400)
        head = data[start:j].decode("latin-1")
        tail = data[j + len(marker) : end].decode("latin-1")
        out.append((head, tail))
        pos = j + 1
    return out


def extract_method_cstrings(data: bytes) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for match in METHOD_STRING.finditer(data.decode("latin-1", "ignore")):
        name = match.group()
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _fragment_candidates(frag: str, by_short: dict[str, list[str]], *, unused: set[str] | None = None) -> list[str]:
    if not frag:
        return []
    hits = list(by_short.get(frag, []))
    if hits:
        return [h for h in hits if unused is None or h in unused] or hits
    scored: list[tuple[int, str]] = []
    for short, names in by_short.items():
        if camel_suffix_ok(short, frag):
            for name in names:
                if unused is not None and name not in unused:
                    continue
                scored.append((len(short), name))
        elif len(frag) >= 8 and frag.endswith(short):
            for name in names:
                if unused is not None and name not in unused:
                    continue
                scored.append((len(short), name))
    scored.sort(key=lambda kv: -kv[0])
    return list(dict.fromkeys(name for _, name in scored))


def _bind(head: str, tail: str, name: str) -> ParsedSig | None:
    ns, short = name.split(".", 1)
    return parse_signature(head, tail, namespace=ns, method=short)


def _nearby_namespace(slots: list[tuple[str | None, ParsedSig | None] | None], index: int) -> str | None:
    for j in range(index - 1, -1, -1):
        slot = slots[j]
        if slot and slot[0] and "." in slot[0]:
            return slot[0].split(".", 1)[0]
    for j in range(index + 1, len(slots)):
        slot = slots[j]
        if slot and slot[0] and "." in slot[0]:
            return slot[0].split(".", 1)[0]
    return None


def attach_binary_methods(data: bytes) -> list[dict]:
    names = extract_method_cstrings(data)
    by_short: dict[str, list[str]] = {}
    for name in names:
        by_short.setdefault(name.rsplit(".", 1)[-1], []).append(name)

    sigs = iter_raw_signatures(data)
    unused = set(names)
    slots: list[tuple[str | None, ParsedSig | None] | None] = [None] * len(sigs)

    def take(i: int, name: str) -> None:
        head, tail = sigs[i]
        slots[i] = (name, _bind(head, tail, name))
        unused.discard(name)

    for i, (head, tail) in enumerate(sigs):
        frag = name_fragment(head)
        exact = [n for n in by_short.get(frag, []) if n in unused]
        if len(exact) == 1:
            take(i, exact[0])

    for i, (head, tail) in enumerate(sigs):
        if slots[i] is not None:
            continue
        frag = name_fragment(head)
        exact = [n for n in by_short.get(frag, []) if n in unused]
        cands = exact or _fragment_candidates(frag, by_short, unused=unused)
        if not cands:
            frag = name_fragment(head)
            hint = _nearby_namespace(slots, i)
            parsed = parse_signature(head, tail, namespace=hint or "", method=frag)
            synth = None
            if hint and frag and _looks_like_method(frag):
                synth = f"{hint}.{frag}"
                unused.discard(synth)
            slots[i] = (synth, parsed)
            continue
        if len(cands) > 1:
            hint = _nearby_namespace(slots, i)
            if hint:
                filtered = [c for c in cands if c.startswith(hint + ".")]
                if len(filtered) == 1:
                    cands = filtered
        take(i, cands[0])

    methods: list[dict] = []
    seen_names: set[str] = set()
    orphans: list[ParsedSig] = []
    for i, slot in enumerate(slots):
        if not slot:
            continue
        name, sig = slot
        if sig is None:
            continue
        if name and "." in name:
            ns, short = name.split(".", 1)
        else:
            short = (name or sig.name_fragment)
            ns = None
            name = short
        if name and "." in name:
            seen_names.add(name)
            methods.append(_method_row(name, short, ns, sig))
        elif sig.params or sig.labels:
            orphans.append(sig)

    for sig in orphans:
        frag = name_fragment(sig.raw_head) or sig.name_fragment
        hit = None
        for cname in names:
            if cname in seen_names:
                continue
            short = cname.split(".", 1)[-1]
            if camel_suffix_ok(short, frag) or (
                len(frag) >= 5 and short.endswith(frag)
            ) or (
                len(frag) >= 5 and frag[0].isupper() and short.endswith(frag[1:])
            ):
                hit = cname
                break
        if hit:
            ns, short = hit.split(".", 1)
            parsed = parse_signature(sig.raw_head, sig.raw_types, namespace=ns, method=short)
            methods.append(_method_row(hit, short, ns, parsed or sig))
            seen_names.add(hit)
        # unmatched truncated signatures are dropped (names recovered via cstrings)

    for name in names:
        if name not in seen_names:
            ns, short = name.split(".", 1)
            methods.append(
                {
                    "name": name,
                    "short_name": short,
                    "namespace": ns,
                    "kind": "method",
                    "id": None,
                    "id_hex": None,
                    "id_signed": None,
                    "generic_params": [],
                    "params": [],
                    "result": {"name": "Unknown"},
                    "result_type": "Unknown",
                    "native": False,
                    "tl": f"{name} = Unknown;",
                    "source": "ipa_cstring",
                    "missing_signature": True,
                }
            )

    methods.sort(key=lambda m: m["name"].lower())
    dedup: dict[str, dict] = {}
    for row in methods:
        prev = dedup.get(row["name"])
        if prev is None or (len(row["params"]) > len(prev["params"])):
            dedup[row["name"]] = row
    return sorted(dedup.values(), key=lambda m: m["name"].lower())


def _method_row(name: str, short: str, ns: str | None, sig: ParsedSig) -> dict:
    row = {
        "name": name,
        "short_name": short,
        "namespace": ns,
        "kind": "method",
        "id": None,
        "id_hex": None,
        "id_signed": None,
        "generic_params": [],
        "params": [_param_dict(p) for p in sig.params],
        "result": sig.result.to_dict(),
        "result_type": sig.result.qualified,
        "native": False,
        "tl": _render_tl(name, sig.params, sig.result),
        "source": "ipa",
        "truncated_name": sig.truncated,
    }
    if sig.notes:
        row["notes"] = sig.notes
    return row


def _param_dict(param: Parameter) -> dict:
    optional = param.optional or (param.type.flag is not None and param.type.flag.bit < 0)
    data = {
        "name": param.name,
        "type": _type_dict(param.type),
        "optional": optional and not param.is_flags_field,
        "flags_field": param.is_flags_field,
    }
    return data


def _type_dict(t: TypeExpr) -> dict:
    if t.flag is not None and t.flag.bit < 0:
        t = TypeExpr(
            name=t.name,
            namespace=t.namespace,
            args=t.args,
            bare=t.bare,
            bang=t.bang,
            is_nat=t.is_nat,
            multiplicity=t.multiplicity,
            bracket=t.bracket,
        )
    return t.to_dict()


def _render_tl(name: str, params: list[Parameter], result: TypeExpr) -> str:
    parts = [name]
    for p in params:
        if p.name == "flags" and p.type.is_nat:
            parts.append("flags:#")
            continue
        label = p.name or "_"
        typ = p.type
        optional = typ.flag is not None and typ.flag.bit < 0
        rendered = typ.render() if not optional else typ._render_core()
        if optional:
            parts.append(f"{label}:{rendered}?")
        else:
            parts.append(f"{label}:{rendered}")
    return " ".join(parts) + f" = {result.render()};"
