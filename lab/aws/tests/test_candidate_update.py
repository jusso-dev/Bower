import importlib.util
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
module = types.ModuleType('candidate_update')
source = (ROOT / 'monitoring/update-candidate-linux.sh').read_text().split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
exec(compile(source, 'update-candidate-linux.sh', 'exec'), module.__dict__)


class CandidateUpdateTests(unittest.TestCase):
    def create_archive(self, path, extra=None, mode=None):
        with zipfile.ZipFile(path, 'w') as archive:
            for name in module.FILES:
                entry = zipfile.ZipInfo('collector/' + name)
                entry.external_attr = (mode or (stat.S_IFREG | 0o644)) << 16
                archive.writestr(entry, b'candidate-' + name.encode())
            if extra is not None:
                archive.writestr(extra, b'bad')

    def test_exact_two_native_files_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'archive.zip'
            self.create_archive(path)
            module.archive_files(path, root)
            self.assertEqual(set(module.FILES), {p.name for p in root.iterdir()} - {'archive.zip'})
            self.assertTrue((root / 'Bower.Collector').stat().st_mode & stat.S_IXUSR)

    def test_traversal_extra_case_duplicate_and_symlink_rejected(self):
        for extra, mode in [('../escape', None), ('collector/settings.json', None), ('collector/bower.collector', None),
                            ('collector/Bower.Collector', None), (None, stat.S_IFLNK | 0o777)]:
            with self.subTest(extra=extra, mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / 'archive.zip'
                self.create_archive(path, extra, mode)
                with self.assertRaises(ValueError):
                    module.archive_files(path, root)
                self.assertFalse((root / 'Bower.Collector').exists())

    def fixture(self, directory):
        root = Path(directory)
        install, candidate, backup = (root / name for name in ('install', 'candidate', 'backup'))
        for path in (install, candidate, backup):
            path.mkdir()
        for name in module.FILES:
            (install / name).write_bytes(b'old-' + name.encode())
            (candidate / name).write_bytes(b'new-' + name.encode())
        (install / 'unrelated-config').write_bytes(b'unchanged')
        return install, candidate, backup

    def test_success_changes_only_two_files_and_keeps_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            install, candidate, backup = self.fixture(directory)
            calls = []
            result = module.swap_pair(install, candidate, backup, lambda: calls.append('stop'), lambda: calls.append('start'), lambda: True)
            self.assertTrue(result['updated'])
            self.assertEqual(['stop', 'start'], calls)
            for name in module.FILES:
                self.assertEqual(b'new-' + name.encode(), (install / name).read_bytes())
                self.assertEqual(b'old-' + name.encode(), (backup / name).read_bytes())
            self.assertEqual(b'unchanged', (install / 'unrelated-config').read_bytes())

    def test_failed_readiness_restores_both_files(self):
        with tempfile.TemporaryDirectory() as directory:
            install, candidate, backup = self.fixture(directory)
            result = module.swap_pair(install, candidate, backup, lambda: None, lambda: None, mock.Mock(side_effect=[False, True]))
            self.assertFalse(result['updated'])
            self.assertTrue(result['rollbackSucceeded'])
            for name in module.FILES:
                self.assertEqual(b'old-' + name.encode(), (install / name).read_bytes())

    def test_failure_after_first_replace_restores_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            install, candidate, backup = self.fixture(directory)
            original = module.os.replace
            def replace(src, dst):
                if src == candidate / 'libe_sqlite3.so':
                    raise OSError('injected replacement failure')
                return original(src, dst)
            with mock.patch.object(module.os, 'replace', side_effect=replace):
                result = module.swap_pair(install, candidate, backup, lambda: None, lambda: None, lambda: True)
            self.assertFalse(result['updated'])
            self.assertTrue(result['rollbackSucceeded'])
            self.assertEqual(['Bower.Collector'], result['filesChanged'])
            for name in module.FILES:
                self.assertEqual(b'old-' + name.encode(), (install / name).read_bytes())

    def test_failed_rollback_never_claims_success(self):
        with tempfile.TemporaryDirectory() as directory:
            install, candidate, backup = self.fixture(directory)
            result = module.swap_pair(install, candidate, backup, lambda: None, lambda: None, lambda: False)
            self.assertFalse(result['updated'])
            self.assertFalse(result['rollbackSucceeded'])


if __name__ == '__main__':
    unittest.main()
