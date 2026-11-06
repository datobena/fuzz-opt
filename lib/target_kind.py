"""Target kinds in the benchmark manifest.

arvo      - ARVO/OSS-Fuzz historical bug reproductions (default; has a PoC).
fuzzbench - FuzzBench benchmark targets (entry["kind"] == "fuzzbench").
upstream  - current upstream OSS-Fuzz projects (entry["kind"] == "upstream").
"""
from typing import Optional

ARVO = "arvo"
FUZZBENCH = "fuzzbench"
UPSTREAM = "upstream"
UPSTREAM_IMAGE_PREFIX = "bench-upstream/"


def kind_of(entry: Optional[dict]) -> str:
    kind = (entry or {}).get("kind")
    if kind in (FUZZBENCH, UPSTREAM):
        return kind
    return ARVO


def is_upstream(entry: Optional[dict]) -> bool:
    return kind_of(entry) == UPSTREAM


def has_poc(entry: Optional[dict]) -> bool:
    return kind_of(entry) == ARVO


def is_upstream_image(image: str) -> bool:
    return image.startswith(UPSTREAM_IMAGE_PREFIX)


def sanitizer_of(entry: Optional[dict]) -> str:
    return (entry or {}).get("sanitizer") or "address"


def language_of(entry: Optional[dict]) -> str:
    return (entry or {}).get("language") or "c++"
