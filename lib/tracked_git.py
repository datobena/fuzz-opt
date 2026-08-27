"""Version-track the optimizer's edits WITHOUT putting a .git in the source tree.

Two separate problems make an in-tree .git wrong here, and both are silent.

1. It leaks the answer. The extracted ARVO tree ships the project's real
   repository -- for libxml2 that is 6788 commits including
   ``refs/remotes/origin/master``, 2308 commits AHEAD of the vulnerable revision
   (so it contains the fix), plus CVE-named tags; for wolfssl it is 619 MB and
   22364 commits. That directory is bind-mounted writable into the agent as
   /work/src. The egress proxy exists to stop the agent looking the bug up
   online, and this hands it `git diff HEAD origin/master -- <file>` instead.

2. It changes how projects build. wolfssl's autogen.sh:

       # If this is a source checkout then call autoreconf with error as well
       if test -e .git; then WARNINGS="all,error"; else WARNINGS="all"; fi

   so a .git anywhere in that tree turns on -Werror, and clang 18 emits warnings
   clang 12 did not (-Wbitwise-instead-of-logical, -Wunused-but-set-variable).
   Every rebuild fails. Deleting the extracted .git is not enough on its own,
   because the benchmark then creates its own to track rounds -- which is exactly
   what this module moves out of the way.

The git directory becomes a SIBLING of the work tree, so it is outside the
`-v <project_src>:/src/<project>` bind mount and invisible to both the compiler
and the agent.
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# Anything a build script might sniff for to decide it is in a checkout.
VCS_DIRS = (".git", ".svn", ".hg", ".bzr")


def git_dir_for(work_tree: str | Path) -> Path:
    """Where this work tree's benchmark-owned git metadata lives."""
    wt = Path(work_tree).resolve()
    return wt.parent / f".bench-git-{wt.name}"


def git_cmd(work_tree: str | Path) -> list[str]:
    """``git`` argv pinned to an out-of-tree git dir for this work tree.

    Use INSTEAD of a bare ["git", ...] with cwd=<tree> for every command that
    tracks optimizer edits. Callers may still pass cwd=<tree>; the explicit
    --work-tree is what makes pathspecs resolve the same either way.
    """
    wt = Path(work_tree).resolve()
    return ["git", f"--git-dir={git_dir_for(wt)}", f"--work-tree={wt}"]


def strip_vcs_metadata(tree: str | Path) -> list[str]:
    """Remove any VCS directory the extracted tree shipped. Returns what it removed.

    Called on the source root, so it also catches sibling checkouts: wolfssl's
    tree carries six of them (wolfssl, wolfssh, wolf-ssl-ssh-fuzzers,
    fuzzing-headers, fuzz-targets, afl), and the build copies siblings in.
    """
    removed: list[str] = []
    root = Path(tree)
    if not root.is_dir():
        return removed
    for path in sorted(root.rglob("*")):
        if path.name in VCS_DIRS and path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
            removed.append(str(path.relative_to(root)))
    if removed:
        logger.info("stripped %d VCS director%s from %s: %s",
                    len(removed), "y" if len(removed) == 1 else "ies",
                    root, ", ".join(removed[:8]))
    return removed
