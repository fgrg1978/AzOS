#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""azpkg — build, sign, verify and inspect AzOS application packages (plan D14).

A package is images plus a manifest of what they ask for, signed by their
AUTHOR (crates/core/pkg is the device side; this is the author's and the
reviewer's). The container, the signed message and the metadata are specified
in crates/core/pkg/src/{container,meta}.rs; this file mirrors them byte for
byte, and tests/host/pkg-tests builds a package with this tool and verifies it
with the Rust crate.

    azpkg.py keygen  PREFIX                   # PREFIX.priv (32-byte seed), PREFIX.pub
    azpkg.py keyid   PUBFILE                  # the id a [signer.NAME] key_id names
    azpkg.py build   package.toml -o X.azpkg  # unsigned container + X.spdx.json (SBOM)
    azpkg.py sign    X.azpkg --key PREFIX.priv [-o Y.azpkg]
    azpkg.py verify  X.azpkg (--signer KEYID ... | --signers FILE) [--sbom X.spdx.json]
    azpkg.py inspect X.azpkg
    azpkg.py lint    package.toml | --sbom X.spdx.json   # licence allowlist
    azpkg.py selftest                          # every refusal, on a package it builds

package.toml (TOML; paths relative to the file):

    [package]
    name = "acme-vision"
    version = "1.2.0"
    hardware = ["sbc", "desktop"]       # embedded | sbc | desktop | server
    licence = "Apache-2.0"              # SPDX expression of the package itself
    rows = "rows.toml"                  # [task.NAME] sections, CAPS.TOM syntax
    abi = 2                             # default: ABI_VERSION of crates/core/abi
    supplier = "Organization: Acme"     # optional
    sources = ["src"]                   # optional: trees whose SPDX tags are linted

    [api]                               # lowest level needed of each IDL interface
    Names = 1

    [image."ACME.ELF"]                  # 8.3, upper case, .ELF; exactly one row each
    path = "build/acme.elf"
    licence = "Apache-2.0 OR MIT"

    [[component]]                       # third-party code inside the images (SBOM)
    name = "libfoo"
    version = "1.0"
    licence = "MIT"
    in = ["ACME.ELF"]                   # optional: default every image

    [sbom]
    created = "2026-10-01T00:00:00Z"    # optional; else SOURCE_DATE_EPOCH, else 1970

The SBOM is SPDX 2.3 JSON, deterministic, and its SHA-256 is a signed key of the
manifest (`sbom_sha256`), so the document that travels beside the package is the
one the author signed. The licence allowlist is tools/azpkg_licences.txt.

Exit status: 0 ok, 1 refused (what is wrong is printed), 2 usage.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ImportError:
    print("error: azpkg needs Python 3.11+ (tomllib); the Makefile's PYTHON is one", file=sys.stderr)
    sys.exit(2)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:
    print("error: install the 'cryptography' package: pip install cryptography", file=sys.stderr)
    sys.exit(2)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# ── the container (crates/core/pkg/src/container.rs) ────────────────────────
MAGIC = b"AZPK"
FORMAT = 1
HEADER_LEN = 24
DOMAIN = b"azos-pkg-v1\0"
ALG_NONE = 0
ALG_ED25519 = 1
ALG_KEY_SIG = {ALG_ED25519: (32, 64)}   # algorithm id -> (key length, signature length)
KEY_LEN_MAX = 4096
SIG_LEN_MAX = 8192
HW_BITS = {"embedded": 1, "sbc": 2, "desktop": 4, "server": 8}

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9._+-]{1,24}$")
IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,23}$")
IMAGE_RE = re.compile(r"^[A-Z0-9_]{1,8}\.ELF$")


class Refused(Exception):
    pass


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def key_id(alg: int, key: bytes) -> bytes:
    """sha256(alg_le16 || key): what a topology's [signer.NAME] key_id names."""
    return sha(struct.pack("<H", alg) + key)


def message(alg: int, meta: bytes, rows: bytes) -> bytes:
    """The bytes the author signs: crates/core/pkg container::message."""
    return DOMAIN + struct.pack("<H", alg) + sha(meta) + sha(rows)


def package_id(alg: int, key: bytes, meta: bytes, rows: bytes) -> bytes:
    """sha256(message || key_id): crates/core/pkg Package::id."""
    return sha(message(alg, meta, rows) + key_id(alg, key))


def pack(alg: int, key: bytes, sig: bytes, meta: bytes, rows: bytes, images: bytes) -> bytes:
    head = MAGIC + struct.pack("<HHHHIII", FORMAT, alg, len(key), len(sig), len(meta), len(rows), len(images))
    assert len(head) == HEADER_LEN
    return head + key + sig + meta + rows + images


def unpack(data: bytes) -> dict:
    if len(data) < HEADER_LEN:
        raise Refused("short: not a package")
    if data[:4] != MAGIC:
        raise Refused("not a package (magic)")
    fmt, alg, kl, sl, ml, rl, il = struct.unpack("<HHHHIII", data[4:HEADER_LEN])
    if fmt != FORMAT:
        raise Refused(f"container format {fmt}")
    if kl > KEY_LEN_MAX or sl > SIG_LEN_MAX:
        raise Refused("key or signature length past its ceiling")
    if HEADER_LEN + kl + sl + ml + rl + il != len(data):
        raise Refused("the declared parts do not add up to the file")
    at = HEADER_LEN
    parts = {}
    for name, n in (("key", kl), ("sig", sl), ("meta", ml), ("rows", rl), ("images", il)):
        parts[name] = data[at:at + n]
        at += n
    parts["alg"] = alg
    return parts


# ── licences ─────────────────────────────────────────────────────────────────
def allowlist(extra=()) -> set:
    ids = set(extra)
    for line in (HERE / "azpkg_licences.txt").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ids.add(line)
    return ids


TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9.+:-]+")


def licence_ok(expr: str, allowed: set) -> bool:
    """An SPDX expression passes when every AND operand does and some OR operand does.

    `X WITH exception` is X: an exception only loosens a licence, so it cannot
    make an allowed one unacceptable. `NONE`, `NOASSERTION` and `LicenseRef-*`
    are not on any allowlist.
    """
    toks = TOKEN_RE.findall(expr)
    if not toks or "".join(toks).replace(" ", "") != expr.replace(" ", ""):
        return False
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def atom():
        nonlocal pos
        t = peek()
        if t == "(":
            pos += 1
            v = orx()
            if peek() != ")":
                raise ValueError("unclosed (")
            pos += 1
            return v
        if t is None or t in (")", "AND", "OR", "WITH"):
            raise ValueError("operand expected")
        pos += 1
        ok = t in allowed or (t.endswith("+") and t[:-1] in allowed)
        if peek() == "WITH":
            pos += 1
            if peek() is None:
                raise ValueError("exception expected")
            pos += 1
        return ok

    def andx():
        nonlocal pos
        v = atom()
        while peek() == "AND":
            pos += 1
            v = atom() and v
        return v

    def orx():
        nonlocal pos
        v = andx()
        while peek() == "OR":
            pos += 1
            v = andx() or v
        return v

    try:
        v = orx()
    except ValueError:
        return False
    return v and pos == len(toks)


SPDX_TAG_RE = re.compile(rb"SPDX-License-Identifier:[ \t]*([^\r\n*]*?)[ \t]*(?:\*/|-->)?[ \t]*(?:\r?\n|$)")


def scan_sources(trees, base: Path):
    """(path, expression) for every SPDX tag in the first 4 KiB of a file."""
    for t in trees:
        for p in sorted((base / t).rglob("*")):
            if not p.is_file():
                continue
            try:
                head = p.read_bytes()[:4096]
            except OSError:
                continue
            for m in SPDX_TAG_RE.finditer(head):
                yield p, m.group(1).decode("utf-8", "replace")


def lint_items(items, allowed) -> list:
    """items: (what, expression). The refusals, as lines."""
    return [f"licence not on the allowlist: {what}: {expr!r}" for what, expr in items if not licence_ok(expr, allowed)]


# ── package.toml ─────────────────────────────────────────────────────────────
def abi_version() -> int:
    m = re.search(r"pub const ABI_VERSION: u32 = (\d+);", (ROOT / "crates/core/abi/src/lib.rs").read_text())
    if not m:
        raise Refused("cannot read ABI_VERSION from crates/core/abi/src/lib.rs; set abi in [package]")
    return int(m.group(1))


def rows_ok(rows: bytes) -> list:
    """Section names of the rows; only [task.NAME] is allowed (admit.rs)."""
    names = []
    for line in rows.decode("utf-8").split("\n"):
        s = line.lstrip(" \t")
        if s.startswith("["):
            if not s.startswith("[task."):
                raise Refused(f"rows hold a section other than [task.NAME]: {s.strip()!r}")
            names.append(s[len("[task."):].split("]", 1)[0].strip())
    return names


def load_spec(path: Path) -> dict:
    spec = tomllib.loads(path.read_text())
    pk = spec.get("package") or {}
    base = path.parent
    for k in ("name", "version", "hardware", "licence", "rows"):
        if k not in pk:
            raise Refused(f"package.toml: [package] lacks {k}")
    if not NAME_RE.match(pk["name"]):
        raise Refused(f"package name {pk['name']!r} outside [A-Za-z0-9._-]{{1,32}}")
    if not VERSION_RE.match(pk["version"]):
        raise Refused(f"version {pk['version']!r} outside [A-Za-z0-9._+-]{{1,24}}")
    hw = pk["hardware"]
    if not hw or len(set(hw)) != len(hw) or any(h not in HW_BITS for h in hw):
        raise Refused(f"hardware {hw!r}: one or more of {sorted(HW_BITS)}, none twice")
    api = spec.get("api", {})
    for n, lvl in api.items():
        if not IFACE_RE.match(n) or not isinstance(lvl, int) or not 0 < lvl <= 0xFFFF:
            raise Refused(f"[api] {n} = {lvl!r}")
    images = []
    for name, im in spec.get("image", {}).items():
        if not IMAGE_RE.match(name):
            raise Refused(f"image {name!r}: 8.3, upper case, .ELF")
        if "path" not in im or "licence" not in im:
            raise Refused(f"image {name}: path and licence are required")
        data = (base / im["path"]).read_bytes()
        if not data:
            raise Refused(f"image {name} is empty")
        images.append((name, data, im["licence"]))
    if not images:
        raise Refused("a package carries at least one image")
    rows = (base / pk["rows"]).read_bytes()
    row_names = rows_ok(rows)
    if sorted(row_names) != sorted(n for n, _, _ in images):
        raise Refused(f"rows {sorted(row_names)} and images {sorted(n for n, _, _ in images)} are not one to one")
    return {"pk": pk, "api": api, "images": images, "rows": rows, "components": spec.get("component", []),
            "sbom": spec.get("sbom", {}), "base": base, "abi": pk.get("abi", None)}


# ── SBOM (SPDX 2.3 JSON) ─────────────────────────────────────────────────────
def created(spec) -> str:
    if "created" in spec["sbom"]:
        return spec["sbom"]["created"]
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def spdx_id(s: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", s)


def make_sbom(spec) -> bytes:
    pk = spec["pk"]
    root = spdx_id("Package-" + pk["name"])
    packages = [{
        "SPDXID": root, "name": pk["name"], "versionInfo": pk["version"],
        "supplier": pk.get("supplier", "NOASSERTION"), "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": pk["licence"], "licenseDeclared": pk["licence"], "copyrightText": "NOASSERTION",
    }]
    files, rels = [], [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}]
    for name, data, lic in spec["images"]:
        fid = spdx_id("File-" + name)
        files.append({
            "SPDXID": fid, "fileName": "./" + name, "fileTypes": ["BINARY"],
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha(data).hex()}],
            "licenseConcluded": lic, "licenseInfoInFiles": [lic], "copyrightText": "NOASSERTION",
        })
        rels.append({"spdxElementId": root, "relationshipType": "CONTAINS", "relatedSpdxElement": fid})
    names = [n for n, _, _ in spec["images"]]
    for c in spec["components"]:
        cid = spdx_id("Component-" + c["name"] + "-" + c.get("version", ""))
        packages.append({
            "SPDXID": cid, "name": c["name"], "versionInfo": c.get("version", "NOASSERTION"),
            "supplier": c.get("supplier", "NOASSERTION"), "downloadLocation": c.get("download", "NOASSERTION"),
            "filesAnalyzed": False, "licenseConcluded": c["licence"], "licenseDeclared": c["licence"],
            "copyrightText": "NOASSERTION",
        })
        rels.append({"spdxElementId": root, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": cid})
        for im in c.get("in", names):
            rels.append({"spdxElementId": spdx_id("File-" + im), "relationshipType": "STATIC_LINK", "relatedSpdxElement": cid})
    doc = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{pk['name']}-{pk['version']}",
        "creationInfo": {"created": created(spec), "creators": ["Tool: azpkg"]},
        "packages": packages, "files": files, "relationships": rels,
    }
    # The namespace names the content, so two builds of one package agree.
    seed = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    doc["documentNamespace"] = f"https://azos.invalid/spdx/{pk['name']}-{pk['version']}-{sha(seed).hex()[:16]}"
    return json.dumps(doc, sort_keys=True, indent=1).encode() + b"\n"


def sbom_licences(sbom: bytes):
    d = json.loads(sbom)
    for p in d.get("packages", []):
        for k in ("licenseConcluded", "licenseDeclared"):
            yield f"package {p.get('name')} {k}", p.get(k, "NOASSERTION")
    for f in d.get("files", []):
        yield f"file {f.get('fileName')}", f.get("licenseConcluded", "NOASSERTION")


# ── metadata text (crates/core/pkg/src/meta.rs) ──────────────────────────────
def make_meta(spec, sbom: bytes) -> bytes:
    pk = spec["pk"]
    abi = spec["abi"] if spec["abi"] is not None else abi_version()
    hw = ", ".join(f'"{h}"' for h in pk["hardware"])
    out = [
        "format = 1", f'name = "{pk["name"]}"', f'version = "{pk["version"]}"', f"abi = {abi}",
        f"hardware = [{hw}]", f'sbom_sha256 = "{sha(sbom).hex()}"',
    ]
    if spec["api"]:
        out += ["", "[api]"] + [f"{n} = {lvl}" for n, lvl in spec["api"].items()]
    for name, data, _ in spec["images"]:
        out += ["", f"[image.{name}]", f"size = {len(data)}", f'sha256 = "{sha(data).hex()}"']
    return ("\n".join(out) + "\n").encode()


def parse_meta(meta: bytes) -> dict:
    """The metadata as data, with the checks meta.rs makes (same grammar)."""
    try:
        text = meta.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("metadata: not UTF-8")
    top, api, images = {}, {}, {}
    sect, cur = "top", None

    def quoted(v):
        m = re.fullmatch(r'"([^"\\]*)"', v)
        if not m:
            raise Refused(f"metadata: {v!r} is not a quoted string")
        return m.group(1)

    def uint(v):
        if not re.fullmatch(r"0|[1-9][0-9]{0,9}", v) or int(v) > 0xFFFFFFFF:
            raise Refused(f"metadata: {v!r} is not an unsigned integer")
        return int(v)

    for raw in text.split("\n"):
        line = raw.strip(" \t\r")
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                raise Refused("metadata: unterminated section")
            if len(top) != 6:
                raise Refused("metadata: a section before every top-level key")
            inner = line[1:-1]
            if inner == "api" and sect != "api" and not images and not api:
                sect = "api"
            elif inner.startswith("image."):
                n = inner[len("image."):]
                if not IMAGE_RE.match(n) or n in images:
                    raise Refused(f"metadata: image {n!r}")
                cur = images.setdefault(n, {})
                sect = "image"
            else:
                raise Refused(f"metadata: section {inner!r}")
            continue
        if "=" not in line:
            raise Refused(f"metadata: {line!r}")
        k, v = (x.strip(" \t") for x in line.split("=", 1))
        if sect == "top":
            if not top and k != "format":
                raise Refused("metadata: format leads")
            if k in top or k not in ("format", "name", "version", "abi", "hardware", "sbom_sha256"):
                raise Refused(f"metadata: key {k!r}")
            if k == "abi" or k == "format":
                top[k] = uint(v)
            elif k == "hardware":
                m = re.fullmatch(r"\[(.*)\]", v)
                top[k] = [quoted(x.strip(" \t")) for x in m.group(1).split(",")] if m else None
                if not m:
                    raise Refused("metadata: hardware")
            else:
                top[k] = quoted(v)
        elif sect == "api":
            if not IFACE_RE.match(k) or k in api:
                raise Refused(f"metadata: interface {k!r}")
            api[k] = uint(v)
            if not 0 < api[k] <= 0xFFFF:
                raise Refused(f"metadata: level of {k}")
        else:
            if k not in ("size", "sha256") or k in cur:
                raise Refused(f"metadata: image key {k!r}")
            cur[k] = uint(v) if k == "size" else quoted(v)
    if len(top) != 6 or top["format"] != 1 or not images:
        raise Refused("metadata: missing keys or no image")
    if not NAME_RE.match(top["name"]) or not VERSION_RE.match(top["version"]):
        raise Refused("metadata: name or version")
    hw = top["hardware"]
    if not hw or len(set(hw)) != len(hw) or any(h not in HW_BITS for h in hw):
        raise Refused("metadata: hardware")
    if not re.fullmatch(r"[0-9a-f]{64}", top["sbom_sha256"]):
        raise Refused("metadata: sbom_sha256")
    for n, im in images.items():
        if set(im) != {"size", "sha256"} or not im["size"] or not re.fullmatch(r"[0-9a-f]{64}", im["sha256"]):
            raise Refused(f"metadata: image {n!r}")
    return {**top, "api": api, "image": images}


# ── commands ─────────────────────────────────────────────────────────────────
def cmd_keygen(a):
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    Path(a.prefix + ".priv").write_bytes(seed)
    os.chmod(a.prefix + ".priv", 0o600)
    Path(a.prefix + ".pub").write_bytes(pub)
    print(f'key_id = "{key_id(ALG_ED25519, pub).hex()}"   # for [signer.NAME] in CAPS.TOM')
    return 0


def cmd_keyid(a):
    pub = Path(a.pub).read_bytes()
    if len(pub) != 32:
        raise Refused("an Ed25519 public key is 32 bytes")
    print(key_id(ALG_ED25519, pub).hex())
    return 0


def cmd_lint(a):
    allowed = allowlist(a.allow)
    if a.sbom:
        items = list(sbom_licences(Path(a.sbom).read_bytes()))
    else:
        spec = load_spec(Path(a.package))
        items = lint_items_of(spec)
    bad = lint_items(items, allowed)
    for b in bad:
        print(b, file=sys.stderr)
    if not bad:
        print(f"licences: {len(items)} checked, all on the allowlist")
    return 1 if bad else 0


def lint_items_of(spec):
    pk = spec["pk"]
    items = [("package", pk["licence"])]
    items += [(f"image {n}", lic) for n, _, lic in spec["images"]]
    items += [(f"component {c['name']}", c["licence"]) for c in spec["components"]]
    items += [(f"{p.relative_to(spec['base'])}", e) for p, e in scan_sources(pk.get("sources", []), spec["base"])]
    return items


def cmd_build(a):
    spec = load_spec(Path(a.package))
    bad = lint_items(lint_items_of(spec), allowlist(a.allow))
    if bad:
        for b in bad:
            print(b, file=sys.stderr)
        return 1
    sbom = make_sbom(spec)
    meta = make_meta(spec, sbom)
    images = b"".join(d for _, d, _ in spec["images"])
    out = Path(a.out)
    out.write_bytes(pack(ALG_NONE, b"", b"", meta, spec["rows"], images))
    sbom_out = Path(a.sbom_out) if a.sbom_out else out.with_suffix(".spdx.json")
    sbom_out.write_bytes(sbom)
    print(f"built {out} ({out.stat().st_size} bytes, unsigned) and {sbom_out}")
    return 0


def read_key(path: str) -> Ed25519PrivateKey:
    seed = Path(path).read_bytes()
    if len(seed) != 32:
        raise Refused("a private key is a raw 32-byte seed (azpkg keygen)")
    return Ed25519PrivateKey.from_private_bytes(seed)


def cmd_sign(a):
    p = unpack(Path(a.package).read_bytes())
    priv = read_key(a.key)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = priv.sign(message(ALG_ED25519, p["meta"], p["rows"]))
    out = Path(a.out or a.package)
    out.write_bytes(pack(ALG_ED25519, pub, sig, p["meta"], p["rows"], p["images"]))
    print(f"signed {out}: key_id {key_id(ALG_ED25519, pub).hex()}")
    return 0


def check(data: bytes, signers: set, sbom: bytes | None):
    """Everything the device's verify checks, but admission; returns (parts, meta, kid)."""
    p = unpack(data)
    alg = p["alg"]
    if alg not in ALG_KEY_SIG or (len(p["key"]), len(p["sig"])) != ALG_KEY_SIG[alg]:
        raise Refused(f"unsigned or unsupported signature algorithm {alg}")
    kid = key_id(alg, p["key"]).hex()
    if signers is not None and kid not in signers:
        raise Refused(f"signer {kid} is not one the device admits")
    try:
        Ed25519PublicKey.from_public_bytes(p["key"]).verify(p["sig"], message(alg, p["meta"], p["rows"]))
    except InvalidSignature:
        raise Refused("the signature does not verify")
    meta = parse_meta(p["meta"])
    names = list(meta["image"])
    if sum(meta["image"][n]["size"] for n in names) != len(p["images"]):
        raise Refused("the images are not the length the metadata says")
    at = 0
    for n in names:
        size = meta["image"][n]["size"]
        if sha(p["images"][at:at + size]).hex() != meta["image"][n]["sha256"]:
            raise Refused(f"image {n} is not the signed one")
        at += size
    if sorted(rows_ok(p["rows"])) != sorted(names):
        raise Refused("rows and images are not one to one")
    if sbom is not None and sha(sbom).hex() != meta["sbom_sha256"]:
        raise Refused("the SBOM is not the one the manifest names")
    return p, meta, kid


def signer_set(a):
    ids = {s.lower() for s in (a.signer or [])}
    if a.signers:
        for line in Path(a.signers).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                ids.add(line.lower())
    if not ids and not a.any_signer:
        raise Refused("name the signers the device admits (--signer, --signers) or pass --any-signer")
    return None if a.any_signer else ids


def cmd_verify(a):
    sbom = Path(a.sbom).read_bytes() if a.sbom else None
    p, meta, kid = check(Path(a.package).read_bytes(), signer_set(a), sbom)
    if sbom is not None:
        bad = lint_items(sbom_licences(sbom), allowlist(a.allow))
        if bad:
            raise Refused("; ".join(bad))
    print(f"ok: {meta['name']} {meta['version']} signed by {kid}, id {package_id(p['alg'], p['key'], p['meta'], p['rows']).hex()}")
    return 0


def cmd_inspect(a):
    data = Path(a.package).read_bytes()
    p = unpack(data)
    print(f"container   {len(data)} bytes: key {len(p['key'])}, signature {len(p['sig'])}, metadata {len(p['meta'])}, "
          f"rows {len(p['rows'])}, images {len(p['images'])}")
    if p["alg"] == ALG_NONE:
        print("signature   none (unsigned: a device refuses it)")
    else:
        print(f"signature   algorithm {p['alg']}{' (Ed25519)' if p['alg'] == ALG_ED25519 else ' (unsupported)'}")
        print(f"signer      key_id {key_id(p['alg'], p['key']).hex()}")
        print(f"id          {package_id(p['alg'], p['key'], p['meta'], p['rows']).hex()}")
    print("\n-- metadata --\n" + p["meta"].decode("utf-8", "replace").rstrip())
    print("\n-- rows (warrants and scheduling budgets) --\n" + p["rows"].decode("utf-8", "replace").rstrip())
    return 0


def cmd_selftest(_):
    """Build a package and show that each refusal fires: the tool's own canary."""
    allowed = allowlist()
    fails = []

    def expect(what, fn):
        try:
            fn()
        except Refused:
            return
        fails.append(what)

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "a.elf").write_bytes(bytes(range(200)))
        (d / "rows.toml").write_text(
            'format = 5\n[task.ACME.ELF]\nclass = "best_effort"\npriority = 20\nmem_pages = 32\n'
            'caps = [\n    { kind = "endpoint", target = "endpoint.acme", perm = "rw" },\n]\n')
        (d / "package.toml").write_text(
            '[package]\nname = "acme"\nversion = "1"\nhardware = ["sbc"]\nlicence = "Apache-2.0"\nrows = "rows.toml"\nabi = 2\n'
            '[image."ACME.ELF"]\npath = "a.elf"\nlicence = "MIT OR GPL-3.0-only"\n'
            '[[component]]\nname = "z"\nversion = "1"\nlicence = "Zlib"\n')
        spec = load_spec(d / "package.toml")
        sbom = make_sbom(spec)
        assert make_sbom(spec) == sbom, "the SBOM is not deterministic"
        unsigned = pack(ALG_NONE, b"", b"", make_meta(spec, sbom), spec["rows"], spec["images"][0][1])
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p = unpack(unsigned)
        signed = pack(ALG_ED25519, pub, priv.sign(message(ALG_ED25519, p["meta"], p["rows"])), p["meta"], p["rows"], p["images"])
        good = {key_id(ALG_ED25519, pub).hex()}
        check(signed, good, sbom)
        expect("unsigned", lambda: check(unsigned, good, sbom))
        expect("wrong signer", lambda: check(signed, {"00" * 32}, sbom))
        flipped = bytearray(signed)
        flipped[HEADER_LEN + 32 + 3] ^= 1
        expect("forged signature", lambda: check(bytes(flipped), good, sbom))
        bad_img = bytearray(signed)
        bad_img[-1] ^= 1
        expect("tampered image", lambda: check(bytes(bad_img), good, sbom))
        expect("other SBOM", lambda: check(signed, good, sbom + b" "))
        expect("trailing byte", lambda: check(signed + b"\0", good, sbom))
        expect("unknown algorithm", lambda: check(signed[:6] + b"\x02\x00" + signed[8:], good, sbom))
        expect("foreign section", lambda: rows_ok(b"[operator]\npubkey = \"00\"\n"))
        for what, expr in (("GPL-only package", "GPL-3.0-only"), ("licence ref", "LicenseRef-x"),
                           ("AND with one bad", "MIT AND GPL-3.0-only"), ("empty", ""), ("dangling", "MIT OR")):
            if licence_ok(expr, allowed):
                fails.append(what)
        for what, expr in (("OR with one good", "MIT OR GPL-3.0-only"), ("exception", "Apache-2.0 WITH LLVM-exception"),
                           ("parens", "(MIT OR BSD-2-Clause) AND Zlib")):
            if not licence_ok(expr, allowed):
                fails.append(what)
    for f in fails:
        print(f"selftest: {f}: NOT refused as it should be", file=sys.stderr)
    if not fails:
        print("selftest: every refusal fires")
    return 1 if fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("keygen"); s.add_argument("prefix"); s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("keyid"); s.add_argument("pub"); s.set_defaults(fn=cmd_keyid)
    s = sub.add_parser("lint"); s.add_argument("package", nargs="?"); s.add_argument("--sbom")
    s.add_argument("--allow", action="append", default=[], help="extra SPDX id to accept"); s.set_defaults(fn=cmd_lint)
    s = sub.add_parser("build"); s.add_argument("package"); s.add_argument("-o", "--out", required=True)
    s.add_argument("--sbom-out"); s.add_argument("--allow", action="append", default=[]); s.set_defaults(fn=cmd_build)
    s = sub.add_parser("sign"); s.add_argument("package"); s.add_argument("--key", required=True)
    s.add_argument("-o", "--out"); s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("verify"); s.add_argument("package"); s.add_argument("--signer", action="append")
    s.add_argument("--signers"); s.add_argument("--any-signer", action="store_true"); s.add_argument("--sbom")
    s.add_argument("--allow", action="append", default=[]); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("inspect"); s.add_argument("package"); s.set_defaults(fn=cmd_inspect)
    s = sub.add_parser("selftest"); s.set_defaults(fn=cmd_selftest)
    a = ap.parse_args(argv)
    if a.cmd == "lint" and not (a.package or a.sbom):
        ap.error("lint needs package.toml or --sbom")
    try:
        return a.fn(a)
    except Refused as e:
        print(f"azpkg: refused: {e}", file=sys.stderr)
        return 1
    except (OSError, tomllib.TOMLDecodeError, KeyError) as e:
        print(f"azpkg: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
