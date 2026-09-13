#!/usr/bin/env python3
"""Verify a release with a fixed trust root before extracting exact binaries.

Requires Python 3 and OpenSSL with Ed25519 support. Neither the release nor the
hub supplies the verification key. Run this from a trusted source checkout.
"""
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import re
import os

KEY = "LY7nOn0uWCqGfv6sBy3io9y0SLlW/NVqGg9TB8MWPPE="
MAX = 256 * 1024 * 1024

def main():
    release_dir, asset, output, *names = sys.argv[1:]
    root = pathlib.Path(release_dir)
    manifest_path = root / "sshhub-manifest.json"
    if manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("manifest too large")
    signed = json.loads(manifest_path.read_bytes())
    body = base64.b64decode(signed["manifest"], validate=True)
    signature = base64.b64decode(signed["signature"], validate=True)
    with tempfile.TemporaryDirectory() as temp:
        p = pathlib.Path(temp)
        # RFC 8410 Ed25519 SubjectPublicKeyInfo prefix.
        (p / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + base64.b64decode(KEY))
        (p / "body").write_bytes(body)
        (p / "sig").write_bytes(signature)
        subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                        "-inkey", str(p / "key.der"), "-rawin", "-in", str(p / "body"),
                        "-sigfile", str(p / "sig")], check=True, stdout=subprocess.DEVNULL)
    manifest = json.loads(body)
    if manifest["schema_version"] != 1 or not manifest.get("version"):
        raise ValueError("invalid manifest")
    version = manifest["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid signed version")
    if tuple(map(int, version.split("."))) < (0, 7, 0):
        raise ValueError("release predates forwarding-only architecture; need 0.7.0 or newer")
    expected = os.environ.get("SSHHUB_EXPECTED_VERSION")
    if expected and version != expected.removeprefix("v"):
        raise ValueError("signed version does not match selected release")
    archive = root / asset
    if archive.stat().st_size > MAX:
        raise ValueError("artifact too large")
    payload = archive.read_bytes()
    if hashlib.sha256(payload).hexdigest() != manifest["artifacts"][asset]:
        raise ValueError("artifact digest mismatch")
    import io
    found = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tf:
        for entry in tf:
            if entry.name not in names or not entry.isfile() or entry.size > MAX or entry.name in found:
                raise ValueError("unexpected, duplicate, or oversized archive entry")
            found[entry.name] = tf.extractfile(entry).read()
    if set(found) != set(names):
        raise ValueError("incomplete archive")
    for name, data in found.items():
        (pathlib.Path(output) / name).write_bytes(data)
    print("Verified release", manifest["version"])

if __name__ == "__main__":
    main()
