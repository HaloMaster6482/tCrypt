from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from typer.testing import CliRunner

from tcrypt.cli import app
from tcrypt.crypto import (
    decrypt_bytes,
    decode_message_artifact,
    encode_message_artifact,
    encrypt_bytes,
    load_or_create_key_file,
)


class CryptoTests(unittest.TestCase):
    def test_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            key_file = temp_path / ".tcrypt.key"
            source = temp_path / "secret.txt"
            source.write_text("hello file", encoding="utf-8")

            key = load_or_create_key_file(key_file)
            blob = encrypt_bytes("file", source.name, source.read_bytes(), key)
            payload = decrypt_bytes(blob, key)

            self.assertEqual(payload.kind, "file")
            self.assertEqual(payload.name, source.name)
            self.assertEqual(payload.data.decode("utf-8"), "hello file")

    def test_message_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            key_file = temp_path / ".tcrypt.key"

            key = load_or_create_key_file(key_file)
            blob = encrypt_bytes("message", None, b"secret message", key)
            token = encode_message_artifact(blob)
            payload = decrypt_bytes(decode_message_artifact(token), key)

            self.assertEqual(payload.kind, "message")
            self.assertEqual(payload.data.decode("utf-8"), "secret message")

    def test_encrypt_file_prompts_and_replaces_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            key_file = temp_path / ".tcrypt.key"
            source = temp_path / "secret.txt"
            output = temp_path / "locked.tcrypt"

            source.write_text("hello file", encoding="utf-8")
            output.write_bytes(b"old data")

            runner = CliRunner()
            result = runner.invoke(
                app,
                ["encrypt-file", str(source), "--output", str(output), "--key-file", str(key_file)],
                input="y\n",
            )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Replace file?", result.output)

            key = load_or_create_key_file(key_file)
            payload = decrypt_bytes(output.read_bytes(), key)

            self.assertEqual(payload.kind, "file")
            self.assertEqual(payload.name, source.name)
            self.assertEqual(payload.data.decode("utf-8"), "hello file")


if __name__ == "__main__":
    unittest.main()
