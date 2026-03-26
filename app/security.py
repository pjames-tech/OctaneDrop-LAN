from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Deque, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer



def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = os.urandom(16)
    n = 2**14
    r = 8
    p = 1
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return "$".join(
        [
            "scrypt",
            str(n),
            str(r),
            str(p),
            base64.urlsafe_b64encode(salt).decode("utf-8"),
            base64.urlsafe_b64encode(derived).decode("utf-8"),
        ]
    )



def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, n_text, r_text, p_text, salt_text, digest_text = stored_hash.split("$")
        if algorithm != "scrypt":
            return False
        n = int(n_text)
        r = int(r_text)
        p = int(p_text)
        salt = base64.urlsafe_b64decode(salt_text.encode("utf-8"))
        expected = base64.urlsafe_b64decode(digest_text.encode("utf-8"))
    except (ValueError, TypeError, base64.binascii.Error):
        return False

    try:
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)



def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


@dataclass(slots=True)
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int = 0


class FixedWindowRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str, *, max_events: int, window_seconds: int) -> RateLimitResult:
        now = time.time()
        bucket = self._buckets[key]

        while bucket and bucket[0] <= now - window_seconds:
            bucket.popleft()

        if len(bucket) >= max_events:
            retry_after = int(window_seconds - (now - bucket[0])) + 1
            return RateLimitResult(False, max(retry_after, 1))

        bucket.append(now)
        return RateLimitResult(True, 0)


class ShareTokenManager:
    def __init__(self, secret_key: str) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key=secret_key, salt="download-link")

    def create(self, file_id: str) -> str:
        return self._serializer.dumps({"file_id": file_id})

    def verify(self, token: str, *, max_age: int) -> str | None:
        try:
            payload = self._serializer.loads(token, max_age=max_age)
        except (BadSignature, SignatureExpired):
            return None
        if not isinstance(payload, dict):
            return None
        file_id = payload.get("file_id")
        return file_id if isinstance(file_id, str) else None


class FileTooLargeError(ValueError):
    pass


class StreamingDecryptError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class StreamHeader:
    chunk_size: int
    plaintext_size: int
    nonce_prefix: bytes


class FileCipher:
    STREAM_MAGIC = b"ODS2"
    STREAM_HEADER = struct.Struct(">4sIQ8s")
    STREAM_CHUNK_LENGTH = struct.Struct(">I")
    NONCE_PREFIX_SIZE = 8
    NONCE_COUNTER_BYTES = 4
    NONCE_SIZE = NONCE_PREFIX_SIZE + NONCE_COUNTER_BYTES
    TAG_SIZE = 16
    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
    MAX_CHUNKS = 2**32

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("Encryption key must be 16, 24, or 32 bytes.")
        self._cipher = AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < 13:
            raise ValueError("Encrypted blob is too short.")
        nonce, ciphertext = blob[:12], blob[12:]
        return self._cipher.decrypt(nonce, ciphertext, associated_data=None)

    def _stream_aad(self, *, chunk_size: int, nonce_prefix: bytes, chunk_index: int) -> bytes:
        return self.STREAM_MAGIC + struct.pack(
            ">I8sI",
            chunk_size,
            nonce_prefix,
            chunk_index,
        )

    def _stream_nonce(self, nonce_prefix: bytes, chunk_index: int) -> bytes:
        if len(nonce_prefix) != self.NONCE_PREFIX_SIZE:
            raise ValueError("Invalid nonce prefix size.")
        if not 0 <= chunk_index < self.MAX_CHUNKS:
            raise ValueError("Chunk index is out of range.")
        return nonce_prefix + chunk_index.to_bytes(self.NONCE_COUNTER_BYTES, "big")

    def pack_stream_header(self, *, chunk_size: int, plaintext_size: int, nonce_prefix: bytes) -> bytes:
        if not 0 < chunk_size <= 2**32 - 1:
            raise ValueError("Chunk size must fit in 32 bits.")
        if plaintext_size < 0:
            raise ValueError("Plaintext size cannot be negative.")
        if len(nonce_prefix) != self.NONCE_PREFIX_SIZE:
            raise ValueError("Invalid nonce prefix size.")
        return self.STREAM_HEADER.pack(self.STREAM_MAGIC, chunk_size, plaintext_size, nonce_prefix)

    def read_stream_header(self, source: BinaryIO) -> StreamHeader:
        header_bytes = source.read(self.STREAM_HEADER.size)
        if len(header_bytes) != self.STREAM_HEADER.size:
            raise StreamingDecryptError("Encrypted file header is incomplete.")

        magic, chunk_size, plaintext_size, nonce_prefix = self.STREAM_HEADER.unpack(header_bytes)
        if magic != self.STREAM_MAGIC:
            raise StreamingDecryptError("Encrypted file header is invalid.")
        if chunk_size <= 0:
            raise StreamingDecryptError("Encrypted file chunk size is invalid.")
        return StreamHeader(
            chunk_size=chunk_size,
            plaintext_size=plaintext_size,
            nonce_prefix=nonce_prefix,
        )

    def encrypt_fileobj_to_path(
        self,
        source: BinaryIO,
        destination: Path,
        *,
        max_plaintext_bytes: int,
        chunk_size: int | None = None,
    ) -> tuple[int, str]:
        chosen_chunk_size = chunk_size or self.DEFAULT_CHUNK_SIZE
        nonce_prefix = os.urandom(self.NONCE_PREFIX_SIZE)
        digest = hashlib.sha256()
        plaintext_size = 0
        chunk_index = 0

        try:
            source.seek(0)
        except (AttributeError, OSError):
            pass

        with destination.open("wb+") as target:
            target.write(
                self.pack_stream_header(
                    chunk_size=chosen_chunk_size,
                    plaintext_size=0,
                    nonce_prefix=nonce_prefix,
                )
            )

            while True:
                chunk = source.read(chosen_chunk_size)
                if not chunk:
                    break

                plaintext_size += len(chunk)
                if plaintext_size > max_plaintext_bytes:
                    raise FileTooLargeError("Upload exceeds the configured size limit.")

                if chunk_index >= self.MAX_CHUNKS:
                    raise FileTooLargeError("File uses too many encrypted chunks for this format.")

                digest.update(chunk)
                ciphertext = self._cipher.encrypt(
                    self._stream_nonce(nonce_prefix, chunk_index),
                    chunk,
                    self._stream_aad(
                        chunk_size=chosen_chunk_size,
                        nonce_prefix=nonce_prefix,
                        chunk_index=chunk_index,
                    ),
                )
                target.write(self.STREAM_CHUNK_LENGTH.pack(len(ciphertext)))
                target.write(ciphertext)
                chunk_index += 1

            target.seek(0)
            target.write(
                self.pack_stream_header(
                    chunk_size=chosen_chunk_size,
                    plaintext_size=plaintext_size,
                    nonce_prefix=nonce_prefix,
                )
            )
            target.flush()
            os.fsync(target.fileno())

        return plaintext_size, digest.hexdigest()

    def iter_decrypt_path(
        self,
        path: Path,
        *,
        expected_plaintext_size: int | None = None,
    ) -> Iterator[bytes]:
        with path.open("rb") as source:
            prefix = source.read(len(self.STREAM_MAGIC))
            source.seek(0)
            if prefix != self.STREAM_MAGIC:
                blob = source.read()
                plaintext = self.decrypt(blob)
                if expected_plaintext_size is not None and len(plaintext) != expected_plaintext_size:
                    raise StreamingDecryptError("Stored file metadata does not match the decrypted file size.")
                if plaintext:
                    yield plaintext
                return

            header = self.read_stream_header(source)
            if expected_plaintext_size is not None and header.plaintext_size != expected_plaintext_size:
                raise StreamingDecryptError("Stored file metadata does not match the encrypted file header.")

            produced = 0
            chunk_index = 0
            while produced < header.plaintext_size:
                length_bytes = source.read(self.STREAM_CHUNK_LENGTH.size)
                if len(length_bytes) != self.STREAM_CHUNK_LENGTH.size:
                    raise StreamingDecryptError("Encrypted file ended unexpectedly.")

                (ciphertext_length,) = self.STREAM_CHUNK_LENGTH.unpack(length_bytes)
                max_ciphertext_length = header.chunk_size + self.TAG_SIZE
                if not self.TAG_SIZE <= ciphertext_length <= max_ciphertext_length:
                    raise StreamingDecryptError("Encrypted chunk length is invalid.")

                ciphertext = source.read(ciphertext_length)
                if len(ciphertext) != ciphertext_length:
                    raise StreamingDecryptError("Encrypted chunk is incomplete.")

                plaintext = self._cipher.decrypt(
                    self._stream_nonce(header.nonce_prefix, chunk_index),
                    ciphertext,
                    self._stream_aad(
                        chunk_size=header.chunk_size,
                        nonce_prefix=header.nonce_prefix,
                        chunk_index=chunk_index,
                    ),
                )
                produced += len(plaintext)
                if produced > header.plaintext_size:
                    raise StreamingDecryptError("Encrypted file expands beyond its declared size.")
                if plaintext:
                    yield plaintext
                chunk_index += 1

            if source.read(1):
                raise StreamingDecryptError("Encrypted file has unexpected trailing data.")
