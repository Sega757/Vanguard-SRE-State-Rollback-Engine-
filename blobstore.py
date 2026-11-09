"""blobstore.py: content-addressable хранилище (sha256). Запись: tmp -> fsync -> rename -> fsync(dir)."""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class BlobIntegrityError(RuntimeError):
    """Блоб отсутствует или его содержимое не совпадает с хешем."""


class BlobStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self._tmp = self.root / "_tmp"
        self._tmp.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise ValueError(f"bad digest: {digest!r}")
        return self.root / digest[:2] / digest

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def put(self, data: bytes | str) -> str:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        digest = hashlib.sha256(raw).hexdigest()
        target = self._path(digest)
        if target.is_file():
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._tmp / f"{digest}.{uuid.uuid4().hex[:10]}"
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            tmp.unlink(missing_ok=True)
            raise
        os.close(fd)
        os.replace(str(tmp), str(target))
        self._fsync_dir(target.parent)
        return digest

    def exists(self, digest: str) -> bool:
        try:
            return self._path(digest).is_file()
        except ValueError:
            return False

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        if not path.is_file():
            raise BlobIntegrityError(f"blob not found: {digest}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise BlobIntegrityError(f"blob corrupted: {digest}")
        return data
