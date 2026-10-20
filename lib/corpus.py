"""Seed corpus download and management."""

import hashlib
import io
import logging
import os
import shutil
import tempfile
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

    OSS-Fuzz keys its public ClusterFuzz corpora by the full fuzzer name
    ``{project}_{fuzz_target}`` (e.g. ``selinux_secilc-fuzzer``), so try that
    path first and fall back to the bare ``{fuzz_target}``. Using only the bare
    target name returns HTTP 403 (AccessDenied) for projects whose corpus lives
    under the prefixed name.

    Args:
        project: OSS-Fuzz project name.
        fuzz_target: Fuzz target name.
        output_dir: Directory to extract corpus into.

    Returns:
        True if corpus was downloaded successfully.
    """
    # Policy: corpus downloads are DISABLED. Phase-2/3 use ONLY the project's
    # bundled <target>_seed_corpus.zip, never a downloaded (GCS/ClusterFuzz)
    # corpus. This function is intentionally a no-op regardless of callers.
    logger.info("Corpus download disabled by policy (bundled-only); skipping %s/%s",
                project, fuzz_target)
    return False

    os.makedirs(output_dir, exist_ok=True)  # noqa: unreachable -- disabled above

    candidates = [f"{project}_{fuzz_target}"]
    if fuzz_target not in candidates:
        candidates.append(fuzz_target)

    for name in candidates:
        url = config.CORPUS_URL_TEMPLATE.format(project=project, fuzz_target=name)
        logger.info("Downloading corpus from %s", url)
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
            continue
        except Exception as e:
            logger.error("Error downloading corpus: %s", e)
            continue

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
        # Recursive: an OSS-Fuzz <target>_seed_corpus.zip commonly unpacks into a
        # subdirectory (wolfssl's is corp-rsa/, selinux's is secilc/test/), and a
        # flat listdir merged ZERO of those 1380 files while reporting success.
        # Sorted so the merge is deterministic across runs.
        for src_path in sorted(
            os.path.join(root, f)
            for root, _dirs, files in os.walk(src_dir) for f in files
        ):
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


# --------------------------------------------------------------------------- #
# FuzzBench seed staging (manifest entries with "kind": "fuzzbench")
# --------------------------------------------------------------------------- #
def _sha1_file(path: str) -> str:
    """FuzzBench common/utils.py file_hash: SHA-1 of the file's contents."""
    digest = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(51200), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage_fuzzbench_seed_corpus(bin_dir: str, fuzz_target: str, dst_dir: str) -> dict:
    """Build the seed corpus exactly as FuzzBench's runner does, into dst_dir.

    FuzzBench experiment/runner.py (3234e151) set_up_corpus_directories, with
    SEED_CORPUS_DIR=/out/seeds and no MICRO_EXPERIMENT/CUSTOM_SEED_CORPUS_DIR/
    OSS_FUZZ_CORPUS/NO_SEEDS:
      1. start from whatever the build left in /out/seeds (some build.sh files
         and Dockerfiles populate it);
      2. _unpack_clusterfuzz_seed_corpus: members of /out/<t>_seed_corpus.zip
         ONLY (no other name -- a misnamed zip means FuzzBench fuzzes unseeded),
         skipping directory entries and members over 1 MiB, each extracted under
         <seeds>/<idx:016d>/;
      3. _clean_seed_corpus: walk recursively, delete files over 1 MiB, move
         every file to <seeds>/<sha1 of content> (duplicates collapse);
      4. afl prepare_fuzz_environment -> create_seed_file_for_empty_corpus:
         an empty dir gets one file `default_seed` containing "hi".
    One deliberate difference: FuzzBench leaves the emptied subdirectories of
    step 3 behind (which also stops step 4 from firing when every file was
    oversize); they are dropped here, so such a corpus gets default_seed
    instead of an AFL start-up failure.

    dst_dir is wiped first. Returns counts for logging/provenance.
    """
    limit = int(getattr(config, "FUZZBENCH_SEED_BYTES_LIMIT", 1024 * 1024))
    if os.path.isdir(dst_dir):
        shutil.rmtree(dst_dir)
    os.makedirs(dst_dir, exist_ok=True)

    stats = {"from_out_seeds": 0, "from_zip": 0, "zip_skipped_oversize": 0,
             "removed_oversize": 0, "staged": 0, "default_seed": False,
             "zip": None}
    work = tempfile.mkdtemp(prefix=".fbseeds-", dir=os.path.dirname(
        os.path.abspath(dst_dir)))
    try:
        # 1. /out/seeds from the build.
        out_seeds = os.path.join(bin_dir, "seeds")
        if os.path.isdir(out_seeds):
            shutil.copytree(out_seeds, os.path.join(work, "out_seeds"))
            stats["from_out_seeds"] = sum(
                len(fs) for _r, _d, fs in os.walk(os.path.join(work, "out_seeds")))

        # 2. <t>_seed_corpus.zip (runner: splitext(/out/<t>)[0] + suffix).
        seed_zip = os.path.join(
            bin_dir, os.path.splitext(fuzz_target)[0] + "_seed_corpus.zip")
        if os.path.isfile(seed_zip):
            stats["zip"] = os.path.basename(seed_zip)
            try:
                with zipfile.ZipFile(seed_zip) as zf:
                    idx = 0
                    for member in zf.infolist():
                        if member.filename.endswith("/"):
                            continue
                        if member.file_size > limit:
                            stats["zip_skipped_oversize"] += 1
                            continue
                        zf.extract(member, os.path.join(work, f"{idx:016d}"))
                        idx += 1
                    stats["from_zip"] = idx
            except (zipfile.BadZipFile, OSError) as e:
                logger.warning("fuzzbench seeds: could not unpack %s: %s", seed_zip, e)

        # 3. size filter + sha1 naming, flattened into dst_dir.
        for root, _dirs, files in os.walk(work):
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                if os.path.getsize(path) > limit:
                    stats["removed_oversize"] += 1
                    continue
                os.replace(path, os.path.join(dst_dir, _sha1_file(path)))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    stats["staged"] = sum(1 for f in os.listdir(dst_dir)
                          if os.path.isfile(os.path.join(dst_dir, f)))
    # 4. empty -> default_seed "hi" (no trailing newline).
    if stats["staged"] == 0:
        name = getattr(config, "FUZZBENCH_DEFAULT_SEED_NAME", "default_seed")
        with open(os.path.join(dst_dir, name), "wb") as fh:
            fh.write(getattr(config, "FUZZBENCH_DEFAULT_SEED_CONTENT", b"hi"))
        stats["default_seed"] = True
    logger.info("fuzzbench seeds for %s: %s", fuzz_target, stats)
    return stats
