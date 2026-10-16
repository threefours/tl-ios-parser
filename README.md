# telegrammm

Extract the MTProto API **layer** from a decrypted Telegram iOS IPA. Methods, argument names, and types come from the binary — not from `api.tl`.

The app stub in `Telegram.app` is tiny. The real client lives in:

```text
Payload/Telegram.app/Frameworks/TelegramCoreFramework.framework/TelegramCoreFramework
```

This tree is **layer 229** (`Serialization.currentLayer()` is `MOV W0, #229; RET`).

## Requirements

- Python 3.10+
- A decrypted IPA, an unpacked `Payload/` directory, or the `TelegramCoreFramework` Mach-O

No third-party packages.

## Extract from an IPA

From the repo root:

```text
python -m tl_layer from-ipa
python -m tl_layer from-ipa path\to\app.ipa -o tl_layer/out/ipa_layer.json
python -m tl_layer from-ipa Payload
python -m tl_layer from-ipa Payload\Telegram.app\Frameworks\TelegramCoreFramework.framework\TelegramCoreFramework
```

With no path, the command uses the first `*.ipa` in the repo, or `Payload/` if there is no IPA.

What it reads in the Mach-O:

1. **Layer number** — ARM64 `MOV W0, #n; RET` pair for `currentLayer`.
2. **Method names** — `namespace.method` cstrings (`payments.getStarsStatus`, …).
3. **Arguments** — Swift `FunctionDescription` mangled signatures (labels + types).

It does **not** load `api.tl`.

### Output

Default file: `tl_layer/out/ipa_layer.json`.

| Field | Meaning |
| --- | --- |
| `layer` | API layer (229 here) |
| `layer_offset` | File offset of the layer thunk |
| `method_names` | Sorted method list |
| `methods` | Per-method params / result / TL-like render |
| `methods_with_signature` | Rows recovered from Swift signatures |
| `methods_with_params` | Rows that have at least one argument |

Names follow Swift (`botId`, `replyMarkup`), not TL snake_case (`bot_id`).

```json
{
  "name": "payments.getStarsStatus",
  "params": [
    { "name": "flags", "type": { "name": "#" }, "flags_field": true },
    { "name": "peer", "type": { "name": "InputPeer" }, "optional": false }
  ],
  "result_type": "StarsStatus",
  "tl": "payments.getStarsStatus flags:# peer:InputPeer = StarsStatus;",
  "source": "ipa"
}
```

`source` is `ipa` when a Swift signature was decoded, or `ipa_cstring` when only the name string was found (`missing_signature: true`).

Optional fields from `T?` become `optional: true`. Flag **bit numbers** (`flags.0?`) are not in the mangled name, so they are omitted. Constructor ids (`#4ea9b3bf`) are ARM immediates in the function body and are not filled in.

If a Swift type substitution cannot be resolved from this mangled string, the type is left as `subst_N`. Argument types are never guessed from parameter names.

## Extract from a macOS Telegram.app

The macOS client (Telegram-Swift, `ru.keepcoder.Telegram`) is a single
**universal (FAT)** Mach-O at `Telegram.app/Contents/MacOS/Telegram` — there is
no separate `TelegramCoreFramework`. The layer thunk and Swift metadata are read
from the **arm64** slice.

```text
python -m tl_layer from-app
python -m tl_layer from-app path\to\Telegram.app
python -m tl_layer from-app path\to\Telegram.app\Contents\MacOS\Telegram
python -m tl_layer from-app Telegram.app -o tl_layer\out\app_layer.json
```

With no path, the command uses the first `*.app` next to the repo.

What it reads in the Mach-O:

1. **Layer number** — same ARM64 `MOV W0, #n; RET` thunk as the IPA path.
2. **Method signatures** — the ~850 Swift `FunctionDescription` fragments
   (method name, argument labels, argument types, result type).
3. **Namespaces** — the macOS binary has **no** clean `namespace.method` strings,
   no Swift symbols, and no per-method namespace pointers. The methods are
   contiguously grouped by namespace in the binary, and each fragment's word
   compression is relative to its `TelegramApi.Api.functions.<namespace>`
   context, so the namespace is needed to demangle the labels. It is taken from
   the checked-in `schema/api.tl` used **only** as a `method name → namespace`
   oracle (anchoring the binary's contiguous runs). **Types and argument names
   still come from the binary** — `api.tl` never supplies a type.
4. **macOS-only namespaces** — namespaces missing from the `api.tl` snapshot
   (e.g. `feed` / `wallet` / `toncenter`) are labelled **from the binary alone**:
   the Swift reflection (`__swift5_types`) lists every namespace and its types,
   and a method cluster is attributed to the namespace whose own types its
   signatures return/accept (`feed` methods return `feed.FeedMessages`,
   `feed.ForYouFeed`, …). Those methods carry `namespace_source: "reflection"`.

### Output

Default file: `tl_layer/out/app_layer.json` (plus a readable `app_layer.txt`).

Same per-method shape as `from-ipa`, with `source: "app"`. Extra flags:

| Flag | Meaning |
| --- | --- |
| `namespace_source: "reflection"` | the namespace was recovered from the binary's Swift reflection (a macOS-only namespace such as `feed` / `wallet` / `toncenter`), not from `api.tl` |
| `name_uncertain` | the method name is the raw binary fragment; it matched no `api.tl` name in its namespace (a macOS-only / newly-added method, or a fragment the demangler truncated) |
| `namespace_unresolved` | the namespace could not be established at all (a boundary fragment, or a cluster whose types were not conclusive); the signature is still binary-derived |

The header of `app_layer.txt` reports totals: methods, with-signature,
with-arguments, without-namespace, namespace-from-reflection (and which), and
name-uncertain. `[?]` groups the still-unresolved methods.

Example — comparing two macOS builds shows the `feed` namespace is new in
`13.0 (283323)`, layer 232: it is absent from `namespaces_in_binary` in the
older `283309` (layer 230), which carries only `toncenter` / `wallet` as
reflection-only namespaces.

## Diff two layers

Pass two `ipa_layer.json` dumps, or two IPAs / `Payload` trees / binaries:

```text
python -m tl_layer diff old.json new.json
python -m tl_layer diff old.ipa new.ipa
python -m tl_layer diff old.json new.json --brief
python -m tl_layer diff old.json new.json -o diff.json
```

Prints added / removed / changed methods (arguments, result type, constructor id when present), grouped by namespace. Does **not** load `api.tl`. Exit code is `1` if anything differs, `0` if the APIs match.

## Optional schema tools

`tl_layer/schema/api.tl` and `mtproto.tl` are a checked-in official TL snapshot. They are used only by these commands:

```text
python -m tl_layer stats
python -m tl_layer lookup payments.getStarsStatus
python -m tl_layer dump -o tl_layer/out/layer.json
python -m tl_layer extract --ipa Payload\...\TelegramCoreFramework
python -m tl_layer index
```

`lookup` accepts a method, constructor, type, namespace, or `#id`.

## Layout

```text
tl_layer/
  from_ipa.py         IPA unpack, layer thunk, Core framework
  from_app.py         macOS .app (FAT arm64), reflection namespaces, api.tl oracle
  swift_mangling.py   FunctionDescription demangle (labels + types)
  diff_layer.py       Readable diff of two layer dumps
  parser.py           TL language parser (optional schema commands)
  models.py           Combinator / Parameter / TypeExpr
  schema/             api.tl, mtproto.tl (optional)
  out/ipa_layer.json  last from-ipa dump
  out/ipa_layer.txt   readable listing (same as the GitHub Action report)
Payload/              unpacked IPA (not required if you pass a .ipa)
```

## GitHub Actions

Do **not** commit the IPA into git. The website caps uploads to the repo at **25MB**; `git push` caps a blob at **100MB**. A Telegram IPA is larger than both.

Put the file on a **GitHub Release** instead (assets up to **2GB**):

1. Repo → **Releases → Draft a new release**
2. Tag e.g. `ipa` (reuse the same tag next time, or make `ipa-12.9.3`)
3. Attach the decrypted `.ipa` under **Attach binaries**
4. Publish. The **Extract IPA layer** workflow starts automatically.
5. Download the `ipa-layer` artifact (`ipa_layer.json` + readable `ipa_layer.txt`).

The Action log prints the same text report (every method as a TL-like line). `subst_N` is an unresolved Swift back-reference, not a guessed type.

To run again without a new release: **Actions → Extract IPA layer → Run workflow** (empty tag = latest release, or type the tag name).

From the CLI:

```text
gh release create ipa path\to\app.ipa --title "IPA" --notes ""
```

The GitHub repo root *is* this package. The workflow symlinks the checkout as `tl_layer` so `python -m tl_layer` works.

`CI` runs on push/PR and only executes `stats` / `lookup` (no IPA).

### Local equivalent of the Action

```text
mkdir -p /tmp/src && ln -s "$(pwd)" /tmp/src/tl_layer
PYTHONPATH=/tmp/src python -m tl_layer from-ipa app.ipa -o out/ipa_layer.json
```

On Windows (from the parent of this folder, if the folder is named `tl_layer`):

```text
python -m tl_layer from-ipa app.ipa -o tl_layer\out\ipa_layer.json
```

## Library

```python
from pathlib import Path
from tl_layer import diff_paths, extract_from_path

info = extract_from_path(Path("Payload"))
print(info["layer"], info["methods_with_params"])

diff = diff_paths(Path("old.json"), Path("new.json"))
```
