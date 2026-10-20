import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('review_static_hash_cache', ROOT / 'scripts/review-static.py')
review_static = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review_static)


class CompilerHashCacheTests(unittest.TestCase):
    def setUp(self):
        review_static._VERIFIED_COMPILER_HASHES.clear()

    def test_same_unchanged_file_is_hashed_once(self):
        with tempfile.TemporaryDirectory() as folder:
            compiler = Path(folder) / 'soljson.cjs'
            compiler.write_bytes(b'verified compiler bytes')
            original_hash = review_static._sha256_file
            with patch.object(review_static, '_sha256_file', wraps=original_hash) as hash_file:
                first = review_static._verified_compiler_hash(compiler)
                for _ in range(10):
                    self.assertEqual(review_static._verified_compiler_hash(compiler), first)
            self.assertEqual(hash_file.call_count, 1)

    def test_changed_file_is_rehashed(self):
        with tempfile.TemporaryDirectory() as folder:
            compiler = Path(folder) / 'soljson.cjs'
            compiler.write_bytes(b'original compiler bytes')
            first = review_static._verified_compiler_hash(compiler)
            compiler.write_bytes(b'modified compiler bytes')
            second = review_static._verified_compiler_hash(compiler)
            self.assertNotEqual(first, second)
            self.assertEqual(review_static._verified_compiler_hash(compiler), second)

    def test_change_during_hashing_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            compiler = Path(folder) / 'soljson.cjs'
            compiler.write_bytes(b'original compiler bytes')
            original_hash = review_static._sha256_file

            def mutate_after_hash(path):
                digest = original_hash(path)
                path.write_bytes(b'changed during verification')
                return digest

            with patch.object(review_static, '_sha256_file', side_effect=mutate_after_hash):
                with self.assertRaisesRegex(ValueError, 'changed while verifying'):
                    review_static._verified_compiler_hash(compiler)
            self.assertFalse(review_static._VERIFIED_COMPILER_HASHES)


if __name__ == '__main__':
    unittest.main()
