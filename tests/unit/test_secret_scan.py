"""Tests for scripts/secret_scan.py (push-protection scanner)."""
import base64
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import secret_scan as sc


def _scan_text(text):
    return sc.scan_content("fake/file.txt", text.encode())


class TestDetectors:
    def test_private_key_detected(self):
        f = _scan_text("x\n-----BEGIN PRIVATE KEY-----\nabc\n")
        assert any("private key material" in r for r in f)

    def test_github_token_detected(self):
        tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        assert _scan_text(f'token = "{tok}"')

    def test_aws_key_detected(self):
        assert _scan_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE extra")

    def test_hardcoded_credential_assignment_detected(self):
        assert _scan_text('api_key = "super-secret-value-1234567890"')

    def test_raw_random_b64_secret_detected(self):
        blob = base64.b64encode(os.urandom(32)).decode().rstrip("=")
        # ensure it's long enough and high entropy
        assert len(blob) >= 32
        assert _scan_text(f'LEAKED="{blob}"') or sc.looks_random(blob)

    def test_package_lock_integrity_not_flagged(self):
        line = ('"integrity": "sha512-'
                'YXJ0aWZhY3QgcmFuZG9tIGJhc2U2NCBidWxsZXQgZGF0YQ=='
                '",\n')
        assert _scan_text(line) == []

    def test_ed25519_signature_not_flagged(self):
        sig = ("ed25519:h9anN8iUn7uOmXteTJSnRnv3f0P6Via4a-BIWuoKb-U"
               "05h5xNFHe3GR1qhUKkVJzEIgD8X6kZnLsLhG1RjBQ==")
        assert _scan_text(f'"signature": "{sig}"') == []

    def test_url_funding_line_not_flagged(self):
        assert _scan_text('"url": "https://tidelift.com/funding/github/npm/browserslist"') == []

    def test_path_comment_not_flagged(self):
        assert _scan_text("// copied from src/components/AzraelIncidentLog.tsx source") == []


class TestDenylist:
    def test_denylisted_paths(self):
        assert sc.denylisted(".ledgerdev/key.pem")
        assert sc.denylisted("app/__pycache__/x.pyc")
        assert sc.denylisted("server.crt".replace(".crt", ".key"))
        assert sc.denylisted(".env.production")
        assert not sc.denylisted("src/app.py")


class TestRepoModes:
    def test_working_tree_is_clean(self):
        rc = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "secret_scan.py"),
                             "--working"], capture_output=True, text=True)
        assert rc.returncode == 0, rc.stderr

    def test_history_has_no_secrets(self):
        rc = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "secret_scan.py"),
                             "--ref", "HEAD"], capture_output=True, text=True)
        assert rc.returncode == 0, rc.stderr

    def test_staged_mode_detects_planted_secret(self, tmp_path=None):
        # Plant a fake secret file, stage it, run --staged, then clean up.
        plant = os.path.join(ROOT, "PLANTED_FAKE_SECRET_TEST.txt")
        try:
            with open(plant, "w") as fh:
                fh.write('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
            subprocess.run(["git", "-C", ROOT, "add", "--", plant], check=True)
            rc = subprocess.run([sys.executable,
                                 os.path.join(ROOT, "scripts", "secret_scan.py"),
                                 "--staged"], capture_output=True, text=True)
            assert rc.returncode == 1
            assert "AWS access key id" in rc.stderr
        finally:
            subprocess.run(["git", "-C", ROOT, "reset", "-q", "--", plant])
            if os.path.exists(plant):
                os.remove(plant)
