"""Tests for out-of-tree source tracking.

Both properties here were live defects: the agent could read the upstream fix out
of /work/src, and wolfssl's build flipped to -Werror because a .git existed.
"""
from __future__ import annotations

import subprocess

from lib import tracked_git

_ID = ["-c", "user.email=b@t", "-c", "user.name=b"]


def _tree(tmp_path):
    t = tmp_path / "src" / "proj"
    t.mkdir(parents=True)
    (t / "a.c").write_text("int main(void){return 0;}\n")
    return t


# --- the work tree never gains a .git --------------------------------------
def test_tracking_leaves_no_vcs_dir_in_the_work_tree(tmp_path):
    """wolfssl's autogen.sh: `if test -e .git; then WARNINGS="all,error"`. A .git
    the benchmark created is indistinguishable from a real checkout to that
    script, and turns every rebuild into a -Werror failure under clang 18."""
    t = _tree(tmp_path)
    g = tracked_git.git_cmd(t)
    subprocess.run(g + ["init", "-q"], cwd=t, check=True)
    subprocess.run(g + ["add", "-A"], cwd=t, check=True)
    subprocess.run(g + _ID + ["commit", "-q", "-m", "base"], cwd=t, check=True)

    assert not (t / ".git").exists()
    assert tracked_git.git_dir_for(t).is_dir()
    # ...and it is outside the tree, so outside the -v <tree>:/src/<proj> mount.
    assert tracked_git.git_dir_for(t).parent == t.parent


def test_commit_tag_diff_and_revert_all_work_out_of_tree(tmp_path):
    """The round lifecycle: tag iter_00, edit, diff, then revert on rejection."""
    t = _tree(tmp_path)
    g = tracked_git.git_cmd(t)
    subprocess.run(g + ["init", "-q"], cwd=t, check=True)
    subprocess.run(g + ["add", "-A"], cwd=t, check=True)
    subprocess.run(g + _ID + ["commit", "-q", "-m", "base"], cwd=t, check=True)
    subprocess.run(g + ["tag", "-f", "iter_00"], cwd=t, capture_output=True)

    (t / "a.c").write_text("int main(void){return 1;}\n")
    (t / "junk.o").write_text("artifact")
    diff = subprocess.run(g + ["diff", "HEAD"], cwd=t,
                          capture_output=True, text=True).stdout
    assert "return 1" in diff

    subprocess.run(g + ["reset", "--hard", "iter_00"], cwd=t, capture_output=True)
    subprocess.run(g + ["clean", "-fd"], cwd=t, capture_output=True)
    assert (t / "a.c").read_text() == "int main(void){return 0;}\n"
    assert not (t / "junk.o").exists()   # a rejected round leaves nothing behind


# --- shipped repositories are removed --------------------------------------
def test_strip_removes_nested_and_sibling_checkouts(tmp_path):
    """wolfssl ships six checkouts under the source root and its build copies the
    siblings in, so stripping only the project dir would not be enough."""
    root = tmp_path / "src"
    for name in ("wolfssl", "wolfssh", "wolf-ssl-ssh-fuzzers"):
        (root / name / ".git" / "refs").mkdir(parents=True)
        (root / name / "file.c").write_text("x")
    (root / "wolfssl" / ".svn").mkdir()

    removed = tracked_git.strip_vcs_metadata(root)

    assert not list(root.rglob(".git"))
    assert not list(root.rglob(".svn"))
    assert len(removed) == 4
    assert (root / "wolfssl" / "file.c").exists()   # sources untouched


def test_strip_is_a_noop_on_a_clean_tree(tmp_path):
    root = tmp_path / "src"
    (root / "proj").mkdir(parents=True)
    (root / "proj" / "a.c").write_text("x")
    assert tracked_git.strip_vcs_metadata(root) == []


def test_strip_tolerates_a_missing_tree(tmp_path):
    assert tracked_git.strip_vcs_metadata(tmp_path / "nope") == []
