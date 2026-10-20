import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("data_provenance", ROOT / "scripts/data_provenance.py")
data_provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data_provenance)


class DataProvenanceTests(unittest.TestCase):
    def kwargs(self):
        return {
            "kind": "rpc.response",
            "project_id": "project-1",
            "source_ref": {"method": "eth_getCode", "request_id": 7},
            "tool_version": "collector/1.0",
            "chain_id": 1,
            "block_number": 123,
            "block_hash": "a" * 64,
            "contract_address": "0x" + "b" * 40,
            "code_hash": "c" * 64,
            "provenance": {"rpc_url": "https://rpc.example", "attempt": 1},
        }

    def test_content_addressed_archive_is_deduplicated_and_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(data_provenance, "utc_now", return_value="2026-01-01T00:00:00.000Z"):
                first = data_provenance.archive_bytes(Path(directory), b"raw response", **self.kwargs())
                second = data_provenance.archive_bytes(Path(directory), b"raw response", **self.kwargs())
            self.assertEqual(first["content_hash"], second["content_hash"])
            self.assertEqual(first["metadata_hash"], second["metadata_hash"])
            self.assertTrue(data_provenance.verify_archive(first))
            self.assertTrue(data_provenance.verify_archive(second))
            self.assertEqual(len(list(Path(directory).rglob("payload.bin.gz"))), 1)
            self.assertEqual(len(list(Path(directory).rglob("*.metadata.json"))), 1)

    def test_same_payload_keeps_distinct_source_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            first = data_provenance.archive_bytes(Path(directory), b"same", **self.kwargs())
            other = self.kwargs()
            other["source_ref"] = {"method": "eth_getCode", "request_id": 8}
            second = data_provenance.archive_bytes(Path(directory), b"same", **other)
            self.assertEqual(first["content_hash"], second["content_hash"])
            self.assertNotEqual(first["metadata_hash"], second["metadata_hash"])
            self.assertTrue(data_provenance.verify_archive(first))
            self.assertTrue(data_provenance.verify_archive(second))
            self.assertEqual(len(list(Path(directory).rglob("payload.bin.gz"))), 1)
            self.assertEqual(len(list(Path(directory).rglob("*.metadata.json"))), 2)

    def test_parse_error_is_recorded_without_discarding_raw_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = data_provenance.archive_bytes(
                Path(directory), b"malformed rpc body", parse_error="invalid JSON", **self.kwargs()
            )
            metadata = json.loads(Path(reference["metadata_path"]).read_text())
            self.assertEqual(metadata["processing"], {"status": "failed", "error": "invalid JSON"})
            self.assertTrue(data_provenance.verify_archive(reference))

    def test_archive_json_is_deterministic_for_mapping_order(self):
        with tempfile.TemporaryDirectory() as directory:
            common = {
                "kind": "rpc.response",
                "project_id": "project-1",
                "source_ref": "rpc:json",
                "tool_version": "collector/1.0",
                "provenance": {},
            }
            first = data_provenance.archive_json(Path(directory), {"b": 2, "a": 1}, **common)
            second = data_provenance.archive_json(Path(directory), {"a": 1, "b": 2}, **common)
            self.assertEqual(first["content_hash"], second["content_hash"])
            self.assertTrue(data_provenance.verify_archive(first))
            self.assertTrue(data_provenance.verify_archive(second))

    def test_tampering_and_metadata_schema_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = data_provenance.archive_bytes(Path(directory), b"immutable", **self.kwargs())
            altered_reference = dict(reference, kind="other.kind")
            self.assertFalse(data_provenance.verify_archive(altered_reference))
            payload_path = Path(reference["payload_path"])
            payload_path.write_bytes(payload_path.read_bytes() + b"tamper")
            self.assertFalse(data_provenance.verify_archive(reference))
            with self.assertRaises(data_provenance.ArchiveError):
                data_provenance.archive_bytes(Path(directory), b"immutable", **self.kwargs(), parse_error=" ")

    def test_archive_rejects_symlinked_shard_directory(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            payload = b"chain response"
            shard = data_provenance.sha256_bytes(payload)[:2]
            (root / "raw").mkdir()
            (root / "raw" / shard).symlink_to(Path(outside), target_is_directory=True)
            with self.assertRaisesRegex(data_provenance.ArchiveError, "regular directory"):
                data_provenance.archive_bytes(root, payload, **self.kwargs())
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_verifier_rejects_symlinked_shard_directory(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            reference = data_provenance.archive_bytes(root, b"chain response", **self.kwargs())
            payload_path = Path(reference["payload_path"])
            shard_path = payload_path.parent.parent
            outside_path = Path(outside) / payload_path.parent.name
            outside_path.mkdir()
            for item in payload_path.parent.iterdir():
                item.rename(outside_path / item.name)
            payload_path.parent.rmdir()
            shard_path.rmdir()
            shard_path.symlink_to(Path(outside), target_is_directory=True)
            self.assertFalse(data_provenance.verify_archive(reference))

    def test_verifier_rejects_metadata_bytes_changed_without_semantic_change(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = data_provenance.archive_bytes(Path(directory), b"raw", **self.kwargs())
            metadata_path = Path(reference["metadata_path"])
            metadata = json.loads(metadata_path.read_text())
            metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
            self.assertFalse(data_provenance.verify_archive(reference))

    def test_provenance_rejects_unknown_fields_and_invalid_address(self):
        record = data_provenance.build_provenance(
            content_hash="a" * 64, project_id="p", source_ref="rpc:1", tool_version="t", provenance={}
        )
        self.assertTrue(data_provenance.validate_provenance(record))
        altered = dict(record)
        altered["extra"] = True
        self.assertFalse(data_provenance.validate_provenance(altered))
        with self.assertRaises(data_provenance.ArchiveError):
            data_provenance.build_provenance(
                content_hash="a" * 64, project_id="p", source_ref="rpc:1", tool_version="t",
                contract_address="0x123", provenance={}
            )


if __name__ == "__main__":
    unittest.main()
