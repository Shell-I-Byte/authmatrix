#!/usr/bin/env python3
"""Focused positive/negative tests for complete source ZIP preflight."""
import io
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
from verify_source_archive import verify

ROOT = Path(__file__).resolve().parents[1]

class ArchivePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='authmatrix-zip-preflight-')
        cls.archive = Path(cls.tmp.name) / 'valid.zip'
        subprocess.run([sys.executable, str(ROOT/'tools/seal_release_source.py'), str(cls.archive), '--source', str(ROOT)], check=True, capture_output=True)
        cls.entries = []
        with zipfile.ZipFile(cls.archive) as z:
            cls.entries = [(info, z.read(info)) for info in z.infolist()]
        cls.prefix = ROOT.name + '/'

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def mutated(self, alter=None, new=None):
        p = Path(self.tmp.name)/('probe-%d.zip' % (len(list(Path(self.tmp.name).glob('probe*.zip')))+1))
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as z:
            for info, data in self.entries:
                if alter and info.filename == alter[0]:
                    data = alter[1]
                z.writestr(info, data)
            if new:
                name, content, mode = new
                info = zipfile.ZipInfo(name)
                info.external_attr = (mode << 16)
                z.writestr(info, content)
        return p

    def rejected(self, **kwargs):
        with self.assertRaises((ValueError, KeyError)):
            verify(self.mutated(**kwargs), ROOT.name)

    def test_00_original_pass(self):
        self.assertGreater(verify(self.archive, ROOT.name), 20)

    def test_01_extra_outside(self):
        self.rejected(new=('other/synthetic.txt', b'x', stat.S_IFREG|0o644))

    def test_02_traversal(self):
        self.rejected(new=(self.prefix+'../traversal', b'x', stat.S_IFREG|0o644))

    def test_03_absolute(self):
        self.rejected(new=('/absolute.txt', b'x', stat.S_IFREG|0o644))

    def test_04_windows_backslash(self):
        self.rejected(new=(self.prefix+'evil\\file', b'x', stat.S_IFREG|0o644))

    def test_05_unmanifested_inside(self):
        self.rejected(new=(self.prefix+'synthetic-extra.txt', b'x', stat.S_IFREG|0o644))

    def test_06_duplicate_name(self):
        name,data = self.entries[0][0].filename,self.entries[0][1]
        self.rejected(new=(name, data, stat.S_IFREG|0o644))

    def test_07_case_collision(self):
        name,data = self.entries[0][0].filename,self.entries[0][1]
        folded = ROOT.name + '/' + name[len(self.prefix):].swapcase()
        self.rejected(new=(folded, data, stat.S_IFREG|0o644))

    def test_08_symlink(self):
        self.rejected(new=(self.prefix+'link', b'../../../outside', stat.S_IFLNK|0o777))

    def test_09_tampered_content(self):
        self.rejected(alter=(self.entries[0][0].filename,b'tamper'))

    def test_10_wrong_root(self):
        with self.assertRaises(ValueError):
            verify(self.archive,'unrelated-root')

    def test_11_directory_member(self):
        self.rejected(new=(self.prefix+'folder/', b'', stat.S_IFDIR|0o755))

    def manifested_member(self, filename):
        # Deliberately add a member AND its correct SHA-256 to the manifest.
        # The check must reject unsafe names, not merely notice a hash mismatch.
        payload = b'local-only portability probe'
        manifest_name = self.prefix+'SOURCE_MANIFEST_SHA256.json'
        original = next(data for info, data in self.entries if info.filename == manifest_name)
        manifest = json.loads(original)
        manifest['files'][filename] = hashlib.sha256(payload).hexdigest()
        updated = json.dumps(manifest,sort_keys=True).encode()
        p = Path(self.tmp.name)/('manifested-'+filename.replace('/','_')+'.zip')
        with zipfile.ZipFile(p,'w',zipfile.ZIP_DEFLATED) as z:
            for info, data in self.entries:
                z.writestr(info, updated if info.filename == manifest_name else data)
            info = zipfile.ZipInfo(self.prefix+filename)
            info.external_attr = ((stat.S_IFREG|0o644) << 16)
            z.writestr(info,payload)
        return p

    def test_12_windows_reserved_device_names_even_when_manifested(self):
        for filename in ('synthetic/NUL.txt', 'synthetic/CON', 'COM1.go', 'LPT9.log'):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    verify(self.manifested_member(filename), ROOT.name)

    def test_13_windows_trailing_period_even_when_manifested(self):
        for filename in ('synthetic/report.', 'synthetic/subdir./file.txt'):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    verify(self.manifested_member(filename), ROOT.name)

    def test_14_manifested_portable_name_still_passes(self):
        self.assertGreater(verify(self.manifested_member('synthetic/valid-report.txt'), ROOT.name), 20)

    def test_16_manifested_file_cannot_be_parent_directory(self):
        # LICENSE is a *file* in the genuine source. The forged child has
        # a correct manifest hash; the structural collision must still fail.
        with self.assertRaises(ValueError):
            verify(self.manifested_member('LICENSE/child.txt'), ROOT.name)

    def test_17_manifested_case_colliding_ancestor(self):
        # docs/ exists. DOCS/ with another basename merges on Windows/macOS.
        with self.assertRaises(ValueError):
            verify(self.manifested_member('DOCS/new.txt'), ROOT.name)

    def test_18_manifested_noncolliding_nested_control(self):
        self.assertGreater(verify(self.manifested_member('docs/new.txt'), ROOT.name), 20)

    def test_15_unsafe_root_rejected(self):
        for name in ('NUL.txt', 'COM1', 'portable.'):
            with self.subTest(root=name):
                with self.assertRaises(ValueError):
                    verify(self.archive,name)

if __name__=='__main__':
    unittest.main(verbosity=2)
