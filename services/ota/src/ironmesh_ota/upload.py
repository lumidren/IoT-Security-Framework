"""Streaming ``multipart/form-data`` parsing for firmware uploads.

The request body is consumed chunk by chunk: the ``image`` part is hashed (SHA-256) and spooled
to a private temporary file as it arrives, the size limit is enforced on the running byte count
(the upload is aborted with 413 as soon as it is exceeded, without buffering the rest), and the
``metadata`` part is capped separately. No part is ever held in memory as a whole.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header

from .problems import Problem


@dataclass
class ParsedUpload:
    image_path: Path
    image_sha256: bytes
    image_size: int
    metadata: bytes
    filename: str | None = None
    _dir: tempfile.TemporaryDirectory[str] | None = field(default=None, repr=False)

    def cleanup(self) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.cleanup()


class _State:
    def __init__(self, workdir: Path, max_image: int, max_metadata: int) -> None:
        self.workdir = workdir
        self.max_image = max_image
        self.max_metadata = max_metadata
        self.header_field = bytearray()
        self.header_value = bytearray()
        self.headers: dict[str, bytes] = {}
        self.current: str | None = None
        self.filename: str | None = None
        self.image_fh: Any = None
        self.image_path: Path | None = None
        self.image_hash = hashlib.sha256()
        self.image_size = 0
        self.metadata = bytearray()
        self.seen: set[str] = set()
        self.error: Problem | None = None

    def fail(self, problem: Problem) -> None:
        if self.error is None:
            self.error = problem

    def failed(self) -> bool:
        return self.error is not None

    # --- callbacks ------------------------------------------------------------------------
    def on_part_begin(self) -> None:
        self.headers = {}
        self.current = None

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self.header_field += data[start:end]

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self.header_value += data[start:end]

    def on_header_end(self) -> None:
        self.headers[self.header_field.decode("latin-1").lower()] = bytes(self.header_value)
        self.header_field.clear()
        self.header_value.clear()

    def on_headers_finished(self) -> None:
        _, params = parse_options_header(self.headers.get("content-disposition", b""))
        name = params.get(b"name", b"").decode("utf-8", "replace")
        if name in self.seen:
            self.fail(Problem(422, errors=[{"field": name, "message": "duplicate form part"}]))
            self.current = None
            return
        self.seen.add(name)
        self.current = name
        if name == "image":
            raw = params.get(b"filename")
            self.filename = raw.decode("utf-8", "replace") if raw else None
            self.image_path = self.workdir / "image.bin"
            self.image_fh = self.image_path.open("xb")

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        if self.current == "image":
            self.image_size += len(chunk)
            if self.image_size > self.max_image:
                self.fail(Problem(413, f"image exceeds the {self.max_image}-byte limit"))
                return
            self.image_hash.update(chunk)
            self.image_fh.write(chunk)
        elif self.current == "metadata":
            self.metadata += chunk
            if len(self.metadata) > self.max_metadata:
                self.fail(Problem(413, f"metadata exceeds the {self.max_metadata}-byte limit"))

    def on_part_end(self) -> None:
        if self.current == "image" and self.image_fh is not None:
            self.image_fh.close()
            self.image_fh = None
        self.current = None


async def parse_firmware_upload(
    content_type: str | None,
    content_length: str | None,
    stream: AsyncIterator[bytes],
    *,
    max_image: int,
    max_metadata: int,
) -> ParsedUpload:
    ctype, params = parse_options_header(content_type)
    if ctype != b"multipart/form-data" or b"boundary" not in params:
        raise Problem(415, "expected multipart/form-data with image and metadata parts")
    limit = max_image + max_metadata + 64 * 1024
    if content_length is not None and content_length.isdigit() and int(content_length) > limit:
        raise Problem(413, f"request body exceeds the {limit}-byte limit")
    tmp = tempfile.TemporaryDirectory(prefix="ota-upload-")
    os.chmod(tmp.name, 0o700)
    state = _State(Path(tmp.name), max_image, max_metadata)
    parser = MultipartParser(
        params[b"boundary"],
        {
            "on_part_begin": state.on_part_begin,
            "on_part_data": state.on_part_data,
            "on_part_end": state.on_part_end,
            "on_header_field": state.on_header_field,
            "on_header_value": state.on_header_value,
            "on_header_end": state.on_header_end,
            "on_headers_finished": state.on_headers_finished,
        },
    )
    try:
        received = 0
        async for chunk in stream:
            received += len(chunk)
            if received > limit:
                state.fail(Problem(413, f"request body exceeds the {limit}-byte limit"))
            if state.failed():
                break
            parser.write(chunk)
            if state.failed():
                break
        if not state.failed():
            parser.finalize()
    except MultipartParseError as exc:
        state.fail(Problem(400, f"malformed multipart body: {exc}"))
    finally:
        if state.image_fh is not None:
            state.image_fh.close()
    try:
        if state.error is not None:
            raise state.error
        missing = [p for p in ("image", "metadata") if p not in state.seen]
        if missing or state.image_path is None:
            raise Problem(
                422,
                errors=[{"field": p, "message": f"{p} part is required"} for p in missing],
                detail="image (binary) and metadata (JSON) parts are required",
            )
    except Problem:
        tmp.cleanup()
        raise
    return ParsedUpload(
        image_path=state.image_path,
        image_sha256=state.image_hash.digest(),
        image_size=state.image_size,
        metadata=bytes(state.metadata),
        filename=state.filename,
        _dir=tmp,
    )
