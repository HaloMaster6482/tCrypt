from __future__ import annotations

import base64
import ctypes
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"TCRT"
VERSION = 1
KEY_SIZE = 32
NONCE_SIZE = 12
DEFAULT_KEY_FILE = Path.home() / ".tcrypt.key"
WINDOWS_HIDDEN_ATTRIBUTE = 0x02


class TcryptionError(RuntimeError):
    """Raised when tCrypt cannot continue."""


@dataclass(frozen=True)
class DecryptedPayload:
    kind: str
    name: str | None
    data: bytes


def _set_hidden_file_attribute(path: Path) -> None:
    if os.name != "nt":
        return

    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), WINDOWS_HIDDEN_ATTRIBUTE)
    except Exception:
        return


def load_or_create_key_file(key_file: Path = DEFAULT_KEY_FILE) -> bytes:
    key_file = Path(key_file).expanduser()
    if key_file.exists():
        try:
            raw = base64.urlsafe_b64decode(key_file.read_text(encoding="utf-8").strip())
        except Exception as exc:
            raise TcryptionError(f"Key file is broken: {key_file}") from exc
        if len(raw) != KEY_SIZE:
            raise TcryptionError(f"Key file has the wrong size: {key_file}")
        return raw

    key_file.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(KEY_SIZE)
    key_file.write_text(base64.urlsafe_b64encode(key).decode("ascii"), encoding="utf-8")
    _set_hidden_file_attribute(key_file)
    return key


def key_file_path(key_file: Path = DEFAULT_KEY_FILE) -> Path:
    return Path(key_file).expanduser()


def _build_plaintext(kind: str, name: str | None, data: bytes) -> bytes:
    header = {"kind": kind, "name": name}
    return json.dumps(header, separators=(",", ":")).encode("utf-8") + b"\n" + data


def _split_plaintext(plaintext: bytes) -> DecryptedPayload:
    header_text, data = plaintext.split(b"\n", 1)
    header = json.loads(header_text.decode("utf-8"))
    return DecryptedPayload(
        kind=str(header.get("kind", "message")),
        name=header.get("name"),
        data=data,
    )


def encrypt_bytes(kind: str, name: str | None, data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, _build_plaintext(kind, name, data), MAGIC)
    return MAGIC + bytes([VERSION]) + nonce + ciphertext


def decrypt_bytes(blob: bytes, key: bytes) -> DecryptedPayload:
    minimum_size = len(MAGIC) + 1 + NONCE_SIZE + 16
    if len(blob) < minimum_size or not blob.startswith(MAGIC):
        raise TcryptionError("This does not look like a tCrypt file.")

    version = blob[len(MAGIC)]
    if version != VERSION:
        raise TcryptionError(f"Unsupported tCrypt version: {version}")

    nonce_start = len(MAGIC) + 1
    nonce_end = nonce_start + NONCE_SIZE
    nonce = blob[nonce_start:nonce_end]
    ciphertext = blob[nonce_end:]

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise TcryptionError("The key file does not match this encrypted data.") from exc

    return _split_plaintext(plaintext)


def encode_message_artifact(blob: bytes) -> str:
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decode_message_artifact(token: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(token.encode("utf-8"))
    except Exception as exc:
        raise TcryptionError("That encrypted message is not valid.") from exc
