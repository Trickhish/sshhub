"""Isolated verifier integration tests using disposable signing keys."""
import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("verify", pathlib.Path(__file__).with_name("verify-release.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerifyReleaseTests(unittest.TestCase):
    def test_signature_digest_and_archive_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            out = p / "out"
            out.mkdir()
            key = p / "key.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)], check=True)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
            asset = "sshhub-agent-linux-amd64.tar.gz"

            def sign_archive(name):
                with tarfile.open(p / asset, "w:gz") as tf:
                    info = tarfile.TarInfo(name)
                    info.size = 4
                    tf.addfile(info, io.BytesIO(b"test"))
                body = json.dumps({"schema_version": 1, "version": "1.0.0", "artifacts": {
                    asset: hashlib.sha256((p / asset).read_bytes()).hexdigest()}}).encode()
                (p / "body").write_bytes(body)
                subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(p / "body"), "-out", str(p / "sig")], check=True)
                (p / "sshhub-manifest.json").write_text(json.dumps({
                    "manifest": base64.b64encode(body).decode(),
                    "signature": base64.b64encode((p / "sig").read_bytes()).decode()}))

            with patch.object(verify, "KEY", base64.b64encode(public[-32:]).decode()), patch.object(sys, "argv", ["verify", str(p), asset, str(out), "sshhub-agent"]):
                sign_archive("sshhub-agent")
                verify.main()
                self.assertEqual((out / "sshhub-agent").read_bytes(), b"test")
                (p / asset).write_bytes(b"tampered")
                with self.assertRaises(ValueError):
                    verify.main()
                sign_archive("../sshhub-agent")
                with self.assertRaises(ValueError):
                    verify.main()
                sign_archive("sshhub-agent")
                sm = json.loads((p / "sshhub-manifest.json").read_text())
                sm["signature"] = base64.b64encode(bytes(64)).decode()
                (p / "sshhub-manifest.json").write_text(json.dumps(sm))
                with self.assertRaises(subprocess.CalledProcessError):
                    verify.main()


if __name__ == "__main__":
    unittest.main()
