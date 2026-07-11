from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcryption.crypto import (
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


if __name__ == "__main__":
    unittest.main()
