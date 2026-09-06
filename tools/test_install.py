#!/usr/bin/env python3
"""Exercise the real installer offline, including failed downloads and partial archives."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallTest(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            mocks, install = root / 'mocks', root / 'install'
            mocks.mkdir()
            install.mkdir()
            for binary in ['bitwarden-use', 'bitwarden-use-agent']:
                (install / binary).write_text('existing binary')
            archive = root / 'fixture.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for binary in ['bitwarden-use', 'bitwarden-use-agent']:
                    if mode == 'missing_agent' and binary.endswith('-agent'):
                        continue
                    info = tarfile.TarInfo('bitwarden-use-aarch64-apple-darwin/' + binary)
                    payload = b'#!/bin/sh\necho "bitwarden-use 0.2.0"\n'
                    info.mode, info.size = 0o755, len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (root / 'fixture.sha256').write_text(('0' * 64 if mode == 'bad_checksum' else digest) + '  fixture.tar.gz\n')
            (mocks / 'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n')
            (mocks / 'curl').write_text('''#!/bin/sh
set -eu
url=""; dest=""
while [ "$#" -gt 0 ]; do
 case "$1" in -o) shift; dest="$1";; https:*) url="$1";; esac
 shift
done
case "$url" in
 *.sha256) [ "$TEST_MODE" != missing_checksum ] || exit 22; cp "$FIXTURES/fixture.sha256" "$dest";;
 *) cp "$FIXTURES/fixture.tar.gz" "$dest";;
esac
''')
            for path in mocks.iterdir():
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(mocks) + os.pathsep + os.environ['PATH'],
                       BITWARDEN_INSTALL_DIR=str(install), FIXTURES=str(root), TEST_MODE=mode)
            run = subprocess.run(['sh', str(ROOT / 'install.sh')], env=env, capture_output=True, text=True)
            if mode == 'ok':
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertTrue((install / 'bwu').is_symlink())
                self.assertIn('0.2.0', (install / 'bitwarden-use').read_text())
            else:
                self.assertNotEqual(run.returncode, 0)
                for binary in ['bitwarden-use', 'bitwarden-use-agent']:
                    self.assertEqual((install / binary).read_text(), 'existing binary')
            self.assertFalse(list(install.glob('.bwu-install.*')))

    def test_installer(self):
        for mode in ['ok', 'missing_checksum', 'bad_checksum', 'missing_agent']:
            with self.subTest(mode=mode):
                self.run_case(mode)


if __name__ == '__main__':
    unittest.main()
