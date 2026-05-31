"""Seed corpus download and management."""

import io
import logging
import os
import zipfile
from urllib.request import urlopen, Request
from urllib.error import HTTPError

import config

logger = logging.getLogger(__name__)


def download_corpus(
    project: str,
    fuzz_target: str,
    output_dir: str,
) -> bool:
    """Download public seed corpus from GCS.

    Args:
        project: OSS-Fuzz project name.
        fuzz_target: Fuzz target name.
        output_dir: Directory to extract corpus into.

    Returns:
        True if corpus was downloaded successfully.
    """
    url = config.CORPUS_URL_TEMPLATE.format(
        project=project, fuzz_target=fuzz_target
    )
    logger.info("Downloading corpus from %s", url)

    os.makedirs(output_dir, exist_ok=True)

    try:
        req = Request(url)
        with urlopen(req, timeout=300) as response:
            data = response.read()

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(output_dir)

        count = len(os.listdir(output_dir))
        logger.info("Downloaded %d corpus files to %s", count, output_dir)
        return True

    except HTTPError as e:
        logger.warning("Failed to download corpus: %s (HTTP %d)", url, e.code)
        return False
    except Exception as e:
        logger.error("Error downloading corpus: %s", e)
        return False


def collect_build_corpus(project: str, fuzz_target: str, output_dir: str) -> int:
    """Collect seed corpus from project build artifacts.

    Looks for <fuzz_target>_seed_corpus.zip in the build output directory.

    Returns:
        Number of corpus files collected.
    """
    os.makedirs(output_dir, exist_ok=True)

    build_out = os.path.join(config.OSS_FUZZ_DIR, "build", "out", project)
    seed_zip = os.path.join(build_out, f"{fuzz_target}_seed_corpus.zip")

    if not os.path.exists(seed_zip):
        logger.info("No build seed corpus found at %s", seed_zip)
        return 0

    try:
        with zipfile.ZipFile(seed_zip) as zf:
            zf.extractall(output_dir)
        count = len(os.listdir(output_dir))
        logger.info("Collected %d seed corpus files from build", count)
        return count
    except Exception as e:
        logger.error("Error extracting build corpus: %s", e)
        return 0


def merge_corpus_dirs(src_dirs: list[str], dst_dir: str) -> int:
    """Merge multiple corpus directories into one, deduplicating by content.

    Returns:
        Total number of unique files in merged corpus.
    """
    os.makedirs(dst_dir, exist_ok=True)
    seen_hashes = set()
    count = 0

    for src_dir in src_dirs:
        if not os.path.isdir(src_dir):
            continue
        for fname in os.listdir(src_dir):
            src_path = os.path.join(src_dir, fname)
            if not os.path.isfile(src_path):
                continue
            with open(src_path, "rb") as f:
                content = f.read()
            content_hash = hash(content)
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)
            dst_path = os.path.join(dst_dir, f"corpus_{count:06d}")
            with open(dst_path, "wb") as f:
                f.write(content)
            count += 1

    logger.info("Merged %d unique corpus files into %s", count, dst_dir)
    return count


def ensure_fallback_seed(corpus_dir: str) -> None:
    """Ensure corpus_dir has at least one seed file.

    Creates a 1-byte fallback seed if the directory is empty.
    """
    os.makedirs(corpus_dir, exist_ok=True)
    if any(
        os.path.isfile(os.path.join(corpus_dir, f))
        for f in os.listdir(corpus_dir)
    ):
        return  # already has seeds
    fallback_path = os.path.join(corpus_dir, "seed_fallback_00")
    with open(fallback_path, "wb") as f:
        f.write(b"\x00")
    logger.info("Created 1-byte fallback seed at %s", fallback_path)
