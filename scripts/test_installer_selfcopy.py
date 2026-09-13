"""Regression test for the installer's self-copy.

The updater re-runs the installer persisted at /usr/local/lib/sshhub. A previous
version fell back to copying the Python verifier there when BASH_SOURCE was not
a readable file (which is the case under `curl | bash`). Automatic updates then
failed with a confusing error, and nothing noticed until an update was actually
attempted. These tests assert the installer only ever persists a bash script.
"""
import pathlib
import re
import unittest

SCRIPT = pathlib.Path(__file__).with_name("install-agent.sh")


class InstallerSelfCopyTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text()

    def test_never_copies_verifier_as_installer(self):
        # The verifier is Python; copying it to the installer path breaks updates.
        self.assertNotRegex(
            self.text,
            r'install\s+-m\s+755\s+"\$\{BASH_SOURCE\[0\]:-\$VERIFIER\}"',
            "installer must not fall back to $VERIFIER as its own self-copy",
        )

    def test_validates_what_it_persists(self):
        # Whatever ends up at the installer path must be checked to be bash.
        body = self.text[self.text.index("INSTALLER_DST"):]
        self.assertIn("head -1", body)
        self.assertIn("grep -q bash", body)

    def test_fetches_installer_not_verifier_when_piped(self):
        # The curl fallback must target install-agent.sh.
        fallback = re.search(r"curl[^\n]*-o\s+\"\$INSTALLER_DST[^\n]*\n[^\n]*", self.text)
        self.assertIsNotNone(fallback, "expected a curl fallback for the installer")
        self.assertIn("install-agent.sh", fallback.group(0))
        self.assertNotIn("verify-release.py", fallback.group(0))

    def test_updater_invokes_installer_path(self):
        # The unit must point the updater at the persisted installer.
        self.assertIn("--installer /usr/local/lib/sshhub/install-agent.sh", self.text)


if __name__ == "__main__":
    unittest.main()
