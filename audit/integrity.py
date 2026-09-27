import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(
    file_path: str | Path
) -> str:

    path = Path(file_path)

    digest = hashlib.sha256()

    with path.open("rb") as file:

        for chunk in iter(
            lambda: file.read(65536),
            b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_text(
    content: str
) -> str:

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def sha256_json(
    data: Any
) -> str:

    serialized = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return sha256_text(
        serialized
    )