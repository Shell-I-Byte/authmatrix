"""Static CI completeness regression; NOT a substitute for hosted runs."""
from pathlib import Path
import re
import unittest

CI = Path(__file__).resolve().parents[1]/'.github/workflows/ci.yml'
class NativeMatrixTests193(unittest.TestCase):
    def test_required_native_runners_present(self):
        content = CI.read_text()
        for label, os_name, arch in (('ubuntu-24.04-arm','linux','arm64'),
                                     ('macos-15','darwin','arm64'),
                                     ('windows-2025','windows','amd64')):
            with self.subTest(label=label):
                self.assertIn('- os: '+label+'\n', content)
                self.assertRegex(content, '- os: '+re.escape(label)+r'\n\s+expected_os: '+os_name+r'\n\s+expected_arch: '+arch)

    def test_native_must_run_before_release_not_only_tags(self):
        text=CI.read_text()
        job=text.split('\n  native:\n',1)[1]
        self.assertNotIn("if: github.event_name",job)
        self.assertIn('go test -race -count=1 ./...',job)
        self.assertIn('go mod verify',job)
        self.assertIn('test "$(go env GOVERSION)" = "go1.27.2"',job)
        self.assertIn('tests/native_portable_smoke.py',job)
        self.assertIn('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',job)
