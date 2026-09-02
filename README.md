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
  swift_mangling.py   FunctionDescription demangle (labels + types)
  parser.py           TL language parser (optional schema commands)
  models.py           Combinator / Parameter / TypeExpr
  schema/             api.tl, mtproto.tl (optional)
  out/ipa_layer.json  last from-ipa dump
Payload/              unpacked IPA (not required if you pass a .ipa)
```

## GitHub Actions

Do **not** commit the IPA into git. The website caps uploads to the repo at **25MB**; `git push` caps a blob at **100MB**. A Telegram IPA is larger than both.

Put the file on a **GitHub Release** instead (assets up to **2GB**):

1. Repo → **Releases → Draft a new release**
2. Tag e.g. `ipa` (reuse the same tag next time, or make `ipa-12.9.3`)
3. Attach the decrypted `.ipa` under **Attach binaries**
4. Publish. The **Extract IPA layer** workflow starts automatically.
5. Download the `ipa-layer` artifact (`ipa_layer.json`).

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
from tl_layer import extract_from_path

info = extract_from_path(Path("Payload"))
print(info["layer"], info["methods_with_params"])
```
