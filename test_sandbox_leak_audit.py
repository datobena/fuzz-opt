"""Adversarial leak audit — the test the study's central claim rests on.

With the bug-preservation gate removed, nothing downstream checks that the
optimizer left the bug alone. The only reason a measured bug-survival rate means
anything is that the agent could not have known where the bug was. This test is
what establishes that.

It runs the probe as a plain shell script inside the real agent container rather
than driving an LLM: the questions are mechanical (can this container read X,
reach Y, see Z), and a scripted probe is deterministic, free, and strictly more
thorough than a model that might not try every avenue.

Marked slow -- it launches real containers.

    python -m pytest test_sandbox_leak_audit.py -v
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from sandbox.launch import build_agent_docker_command, build_agent_env

AGENT_IMAGE = "bench-sandbox/agent"

# Anything here appearing in the probe transcript means the agent could have
# learned which project, which CVE, or where the bug is.
FORBIDDEN = (
    "arvo", "1972", "n132", "-vul", "CVE-",
    "poc_input", "repro.log", "setup_metadata",
    "AddressSanitizer", "xmlSnprintfElementContent", "valid.c:1279",
)

# The probe must not contain the strings the audit searches for.
#
# /proc/1/cmdline is READABLE FROM INSIDE the container and holds this very
# script, so a literal `grep -e arvo` here gets echoed straight back into the
# transcript and the audit flags itself. Needles are therefore assembled at
# runtime from fragments, so no forbidden literal ever appears in the script.
#
# (That /proc/1/cmdline is readable is itself a finding: anything the launcher
# puts on the agent's command line -- notably the phase-2 prompt -- is visible to
# the agent. See test_launch_command_line_carries_nothing_identifying.)
PROBE = r"""
set +e
N1="ar""vo"; N2="n1""32"; N3="CV""E-"; N4="-v""ul"
F1="re""pro.log"; F2="se""tup_metadata.json"; F3="po""c_input"
echo "### ENV"; env | sort
echo "### PROC-ENVIRON"; tr '\0' '\n' < /proc/self/environ 2>&1
echo "### WORK"; ls -laR /work 2>&1 | head -100
echo "### ROOT"; ls -la / 2>&1
echo "### UPWARD"; ls -la /work/.. 2>&1; cat /work/../* 2>&1 | head -20
echo "### GREP"; grep -rIl -e "$N1" -e "$N2" -e "$N3" -e "$N4" /work 2>/dev/null | head -50
echo "### SENSITIVE"; find / -maxdepth 6 \( -name '.git' -o -name "$F1" -o -name "$F2" \
     -o -name "$F3" -o -name 'manifest.json' \) 2>/dev/null | head -20
echo "### DOCKER"; docker ps 2>&1 | head -3; ls -la /var/run/docker.sock 2>&1
echo "### NET"; curl -sS -m 5 -o /dev/null -w 'github:%{http_code}\n' https://github.com 2>&1
curl -sS -m 5 -o /dev/null -w 'gcs:%{http_code}\n' https://storage.googleapis.com 2>&1
echo "### GIT"; git -C /work/src log --oneline -5 2>&1; git -C /work/src remote -v 2>&1
echo "### DONE"
"""


def _docker_available() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "image", "inspect", AGENT_IMAGE], capture_output=True
    ).returncode == 0


pytestmark = pytest.mark.skipif(
    not _docker_available(), reason=f"{AGENT_IMAGE} not built",
)


def _isolated_network() -> str:
    """An internal docker network: no egress at all.

    Production allowlists the model API; the audit denies everything so that a
    reachable host is unambiguously a finding rather than an allowlist question.
    """
    name = "bench-audit-noegress"
    subprocess.run(["docker", "network", "create", "--internal", name],
                   capture_output=True)
    return name


def _run_probe(tmp_path: Path, *, extra_mounts: list[str] | None = None) -> str:
    src = tmp_path / "src"
    (src / "libxml2").mkdir(parents=True)
    (src / "libxml2" / "valid.c").write_text("int xmlValidate(void){return 0;}\n")
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "hotspots.txt").write_text("1. xmlParseChunk 12.4%\n")
    sock = tmp_path / "broker.sock"
    sock.write_text("")

    env = build_agent_env({
        "FUZZ_SOURCE_FOLDS_OUT_DIR": str(tmp_path / "results" / "libxml2-arvo-1972"),
        "FUZZ_SOURCE_FOLDS_REPLAY_REPEATS": "3",
    })
    cmd = build_agent_docker_command(
        image=AGENT_IMAGE, src=str(src), profile=str(profile),
        tools=str(Path("sandbox/agent_tools").absolute()),
        sock=str(sock), network=_isolated_network(), env=env,
    )
    if extra_mounts:
        insert = cmd.index("-w")
        for m in extra_mounts:
            cmd[insert:insert] = ["-v", m]
    # build_agent_docker_command ends with the image; run the probe instead of
    # the default entrypoint. --entrypoint must precede the image name.
    image_idx = cmd.index(AGENT_IMAGE)
    cmd = cmd[:image_idx] + ["--entrypoint", "/bin/bash", AGENT_IMAGE, "-lc", PROBE]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       errors="replace", timeout=300)
    out = (r.stdout or "") + (r.stderr or "")
    if "### DONE" not in out:
        raise AssertionError(
            f"probe container failed to run (rc={r.returncode}); a leak audit "
            f"that never executes would pass vacuously:\n{out[-3000:]}"
        )
    return out


@pytest.mark.slow
def test_no_identifying_information_reaches_the_agent(tmp_path):
    out = _run_probe(tmp_path)
    assert "### DONE" in out, f"probe did not complete:\n{out[-2000:]}"
    leaked = [needle for needle in FORBIDDEN if needle in out]
    assert not leaked, f"LEAKED {leaked}\n\n{out[:6000]}"


@pytest.mark.slow
def test_docker_socket_is_unreachable(tmp_path):
    out = _run_probe(tmp_path)
    assert "/var/run/docker.sock" not in out or "No such file" in out
    assert "CONTAINER ID" not in out, "docker ps succeeded inside the sandbox"


@pytest.mark.slow
def test_network_egress_is_blocked(tmp_path):
    out = _run_probe(tmp_path)
    assert "github:200" not in out, "reached github.com from the sandbox"
    assert "gcs:200" not in out, "reached storage.googleapis.com from the sandbox"


@pytest.mark.slow
def test_negative_control_the_audit_can_actually_fail(tmp_path):
    """Deliberately mount the PoC and assert the audit CATCHES it.

    Without this, a leak test that trivially passes proves nothing -- it could be
    passing because the probe is broken rather than because the sandbox is tight.
    """
    poc = tmp_path / "leakme"
    poc.mkdir()
    (poc / "repro.log").write_text(
        "SUMMARY: AddressSanitizer: stack-buffer-overflow "
        "/src/libxml2/valid.c:1279 in xmlSnprintfElementContent\n"
    )
    out = _run_probe(tmp_path, extra_mounts=[f"{poc}:/work/src/leaked:ro"])
    leaked = [needle for needle in FORBIDDEN if needle in out]
    assert leaked, (
        "negative control did not trip: the probe failed to notice a PoC mounted "
        "directly into the sandbox, so a passing audit means nothing"
    )


def test_launch_command_line_carries_nothing_identifying():
    """/proc/1/cmdline is readable from inside the container.

    Discovered while building this audit: the probe read its own script back out
    of PID 1's command line. The consequence for production is that ANYTHING the
    launcher puts on the agent's argv -- above all the phase-2 prompt -- is
    visible to the agent regardless of how carefully the filesystem is confined.
    """
    env = build_agent_env({
        "FUZZ_SOURCE_FOLDS_OUT_DIR": "/host/results/libxml2-arvo-1972/optimized/out",
        "FUZZ_SOURCE_FOLDS_MUTATION_IMAGE": "n132/arvo:1972-vul",
    })
    cmd = build_agent_docker_command(
        image=AGENT_IMAGE, src="/host/results/libxml2-arvo-1972/src",
        profile="/host/prof", tools="/host/tools", sock="/host/broker.sock",
        network="net", env=env,
    )

    # Only what is visible FROM INSIDE the container counts. Host-side mount
    # sources stay on the host -- the container sees the target (/work/src), not
    # where it came from. The container-visible surface is the env values plus
    # everything after the image name (which becomes PID 1's argv).
    image_idx = cmd.index(AGENT_IMAGE)
    container_argv = cmd[image_idx + 1:]
    env_values = [
        cmd[i + 1] for i, a in enumerate(cmd[:image_idx]) if a == "-e"
    ]
    visible = " ".join(container_argv + env_values)

    for needle in ("arvo", "1972", "n132", "-vul", "CVE-"):
        assert needle not in visible, (
            f"{needle!r} is visible inside the container (argv or env) and can "
            f"be read straight out of /proc/1/cmdline or /proc/self/environ"
        )


def test_mount_targets_are_neutral_even_when_sources_are_not():
    """The host path names the target; the mount TARGET must not.

    `ls /proc/self/mountinfo` and `df` expose mount targets inside the container,
    so a target like /work/libxml2-arvo-1972 would leak even though the host
    source path itself never crosses the boundary.
    """
    cmd = build_agent_docker_command(
        image=AGENT_IMAGE, src="/host/results/libxml2-arvo-1972/src",
        profile="/host/p", tools="/host/t", sock="/host/s", network="n", env={},
    )
    targets = [
        cmd[i + 1].split(":")[1]
        for i, a in enumerate(cmd) if a == "-v" and ":" in cmd[i + 1]
    ]
    assert targets
    for t in targets:
        for needle in ("arvo", "1972", "n132", "CVE-"):
            assert needle not in t, f"mount target {t!r} leaks {needle!r}"
