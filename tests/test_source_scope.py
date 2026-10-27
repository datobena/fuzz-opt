"""The host edit boundary must survive bypass attempts, not just normal diffs."""
import json
import os
from pathlib import Path
import shutil

import pytest

from lib.source_scope import SourceScopeGuard, SourceScopeViolation, SourceScopeRecoveryRequired


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'library.c').write_text('int library(void) { return 1; }\n')
    (root / 'build.sh').write_text('build\n')
    (root / '.gitignore').write_text('ignored/\n')
    (root / 'fuzz').mkdir()
    (root / 'fuzz' / 'target.c').write_text('int LLVMFuzzerTestOneInput(void) { return 0; }\n')
    (root / 'fuzz-common.c').write_text('int support;\n')
    (root / 'odd_helper.c').write_text('int helper;\n')
    return root


@pytest.fixture
def guard(tree):
    g = SourceScopeGuard(tree, harness='fuzz/target.c', exclude_globs=('odd_helper.c',))
    try:
        yield g
    finally:
        g.close()


def test_allowed_library_content_and_immutable_build_copy(tree, guard):
    (tree / 'library.c').write_text('int library(void) { return 2; }\n')
    os.utime(tree / 'library.c', ns=(123456789000, 123456789000))
    with guard.snapshot() as candidate:
        assert candidate.name == tree.name
        assert candidate.parent.parent != tree.parent
        assert (candidate / 'library.c').stat().st_mtime_ns == 123456789000
        # A writer races the build after validation. Only the safe copy builds.
        (tree / 'fuzz/target.c').write_text('int main(void) { return 0; }')
        assert 'LLVMFuzzerTestOneInput' in (candidate / 'fuzz/target.c').read_text()
    with pytest.raises(SourceScopeViolation, match='protected file'):
        guard.validate()


@pytest.mark.parametrize('name', ['build.sh', '.gitignore', 'fuzz/target.c', 'fuzz-common.c', 'odd_helper.c'])
def test_protected_files_rejected_and_full_baseline_restored(tree, guard, name):
    original = (tree / name).read_bytes()
    (tree / name).write_text('tampered')
    with pytest.raises(SourceScopeViolation):
        guard.validate()
    guard.restore()
    assert (tree / name).read_bytes() == original
    # A repaired agent cannot erase a violation observed by the broker.
    with pytest.raises(SourceScopeViolation):
        guard.validate()


@pytest.mark.parametrize('attack', ['added_source', 'ignored_file', 'deleted', 'rename',
                                    'symlink_file', 'symlink_directory', 'hardlink', 'mode'])
def test_actual_tree_not_git_or_backup_directory_is_authoritative(tree, guard, tmp_path, attack):
    if attack == 'added_source': (tree / 'new.c').write_text('int new;')
    elif attack == 'ignored_file':
        (tree / 'ignored').mkdir(); (tree / 'ignored/evil.sh').write_text('evil')
    elif attack == 'deleted': (tree / 'library.c').unlink()
    elif attack == 'rename': (tree / 'library.c').rename(tree / 'renamed.c')
    elif attack == 'symlink_file':
        (tree / 'library.c').unlink(); (tree / 'library.c').symlink_to(tmp_path / 'external')
    elif attack == 'symlink_directory':
        shutil.rmtree(tree / 'fuzz'); (tree / 'fuzz').symlink_to(tmp_path)
    elif attack == 'hardlink':
        outside = tmp_path / 'outside'; outside.write_text('int external;')
        (tree / 'library.c').unlink(); os.link(outside, tree / 'library.c')
    elif attack == 'mode': (tree / 'library.c').chmod(0o755)
    with pytest.raises(SourceScopeViolation): guard.validate()
    guard.restore()
    assert (tree / 'library.c').is_file() and not (tree / 'library.c').is_symlink()
    assert (tree / 'fuzz').is_dir() and not (tree / 'fuzz').is_symlink()
    assert not (tree / 'new.c').exists() and not (tree / 'ignored').exists()


def test_unchanged_project_symlink_is_permitted(tree):
    (tree / 'alias.h').symlink_to('library.c')
    g = SourceScopeGuard(tree, harness='fuzz/target.c')
    try:
        g.validate()
        with g.snapshot() as p: assert (p / 'alias.h').is_symlink()
    finally: g.close()


def test_unknown_named_harness_and_entrypoint_files_are_protected(tree):
    (tree / 'main.c').write_text('int LLVMFuzzerInitialize(void) { return 0; }')
    g = SourceScopeGuard(tree, harness='fuzz/../fuzz/target.c')
    try:
        assert 'main.c' not in g.allowed and 'fuzz/target.c' not in g.allowed
    finally: g.close()


def test_unresolved_harness_fails_closed(tree):
    with pytest.raises(SourceScopeViolation):
        SourceScopeGuard(tree, harness='unknown')


def test_baseline_hardlinks_fail_closed(tree, tmp_path):
    os.link(tree / 'library.c', tmp_path / 'alias')
    with pytest.raises(SourceScopeViolation, match='baseline contains hardlinked'):
        SourceScopeGuard(tree, harness='fuzz/target.c')


def test_replaced_source_root_never_follows_outside_symlink(tree, guard, tmp_path):
    outside = tmp_path / 'outside'; outside.mkdir(); (outside / 'keep').write_text('safe')
    shutil.rmtree(tree); tree.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SourceScopeViolation): guard.validate()
    guard.restore()
    assert not tree.is_symlink() and (outside / 'keep').read_text() == 'safe'


def test_restore_repairs_permissions_and_removes_ignored_additions(tree, guard):
    (tree / 'fuzz').chmod(0)
    with pytest.raises(SourceScopeViolation): guard.validate()
    guard.restore()
    assert (tree / 'fuzz/target.c').read_text().startswith('int LLVMFuzzerTestOneInput')


def test_leftover_writer_preserves_backup_and_blocks_rebaseline(tree, guard):
    baseline = guard.baseline
    guard.defer_recovery(); guard.close()
    assert baseline.exists() and guard.pending.exists()
    with pytest.raises(SourceScopeRecoveryRequired, match='pending recovery'):
        SourceScopeGuard(tree, harness='fuzz/target.c')
    # Test cleanup stands in for an operator-confirmed recovery.
    guard.pending.unlink(); guard.keep = False


def test_broker_rejects_protected_edit_without_invoking_docker(tree, guard, monkeypatch):
    from sandbox import broker
    ctx = broker.BrokerContext(image='img', source_dir=str(tree), out_dir='/out',
        corpus_dir='/corpus', fuzz_target='target', project='project', cpu=0, source_guard=guard)
    (tree / 'fuzz/target.c').write_text('changed')
    monkeypatch.setattr(broker, '_run_build_snapshot', lambda c: pytest.fail('must not build'))
    ok, message = broker._run_build(ctx)
    assert not ok and 'fuzz/target.c' in message


def test_broker_builds_private_snapshot_not_live_source(tree, guard, monkeypatch):
    from sandbox import broker
    ctx = broker.BrokerContext(image='fb-aflpp/project', source_dir=str(tree), out_dir='/out',
        corpus_dir='/corpus', fuzz_target='target', project='project', cpu=0, source_guard=guard)
    def build(c):
        assert c.build_source_dir != str(tree)
        command = broker._build_command(c)
        assert f'{c.build_source_dir}:/fold/src:ro' in command
        (tree / 'fuzz/target.c').write_text('evil')
        assert 'LLVMFuzzerTestOneInput' in (Path(c.build_source_dir) / 'fuzz/target.c').read_text()
        return True, 'built from frozen source'
    monkeypatch.setattr(broker, '_run_build_snapshot', build)
    assert broker._run_build(ctx)[0]
    with pytest.raises(SourceScopeViolation): guard.validate()


def test_broker_without_host_policy_cannot_build(tree):
    from sandbox import broker
    ctx = broker.BrokerContext(image='img', source_dir=str(tree), out_dir='/out',
        corpus_dir='/corpus', fuzz_target='target', project='project', cpu=0)
    assert broker._run_build(ctx)[0] is False


def _optimize(monkeypatch, tree, tmp_path, agent, build):
    import phase2_setup as p
    monkeypatch.setenv('FUZZ_TARGET', os.environ.get('FUZZ_TARGET', ''))
    monkeypatch.setattr(p, '_stage_project_fuzz_support', lambda *a: None)
    monkeypatch.setattr(p, '_prebuild_phase2_corpus_and_profile', lambda *a: True)
    monkeypatch.setattr(p, '_find_harness_source', lambda *a: 'fuzz/target.c')
    monkeypatch.setattr(p, '_invoke_agent_capture', agent)
    return p.optimize_and_build(str(tree), 'target', str(tmp_path / 'diff'),
        project='project', build_fn=build, max_attempts=1, codex_extra_env={'dummy':'yes'})


def test_post_agent_rejection_precedes_build_and_restores_every_path(tree, tmp_path, monkeypatch):
    def agent(*a, **k):
        (tree / 'fuzz/target.c').write_text('evil')
        return {'ok':False, 'timed_out':True, 'stdout':'', 'stderr':''}
    assert not _optimize(monkeypatch, tree, tmp_path, agent, lambda: pytest.fail('must not build'))
    assert 'LLVMFuzzerTestOneInput' in (tree / 'fuzz/target.c').read_text()
    report = json.loads((tmp_path / 'diff/source_scope_violation.json').read_text())
    assert any('fuzz/target.c' in s for s in report['violations'])


def test_authoritative_build_retains_source_edits_but_not_generated_files(tree, tmp_path, monkeypatch):
    def agent(*a, **k):
        (tree / 'library.c').write_text('int faster;')
        return {'ok':True, 'timed_out':False, 'stdout':'done', 'stderr':''}
    def build():
        (tree / 'generated.o').write_text('object')
        return True, 'built'
    assert _optimize(monkeypatch, tree, tmp_path, agent, build)
    assert (tree / 'library.c').read_text() == 'int faster;'
    assert not (tree / 'generated.o').exists()


def test_protected_symlink_alias_protects_its_library_named_target(tree):
    (tree / 'fuzz-common.c').unlink()
    (tree / 'fuzz-common.c').symlink_to('odd_helper.c')
    g = SourceScopeGuard(tree, harness='fuzz/target.c')
    try:
        assert 'odd_helper.c' not in g.allowed
        (tree / 'odd_helper.c').write_text('changed support')
        with pytest.raises(SourceScopeViolation): g.validate()
    finally: g.close()


def test_touching_protected_file_rejected_but_source_timestamp_allowed(tree, guard):
    os.utime(tree / 'library.c', ns=(1, 1))
    guard.validate()
    os.utime(tree / 'build.sh', ns=(1, 1))
    with pytest.raises(SourceScopeViolation): guard.validate()


def test_pending_recovery_is_checked_before_any_host_tree_activity(tree, guard, tmp_path, monkeypatch):
    import phase2_setup as p
    guard.defer_recovery(['agent-old'])
    monkeypatch.setattr(p, '_optimize_and_build', lambda *a, **k: pytest.fail('must not stage/profile/Git'))
    with pytest.raises(SourceScopeRecoveryRequired):
        p.optimize_and_build(str(tree), 'target', str(tmp_path / 'd'), project='p', build_fn=lambda: None)
    guard.pending.unlink(); guard.keep = False


def test_confirmed_orphan_recovery_restores_ignored_paths(tree, guard):
    from lib.source_scope import recover_pending
    guard.defer_recovery(['agent-old'])
    (tree / 'ignored').mkdir(); (tree / 'ignored/evil').write_text('untracked')
    with pytest.raises(SourceScopeRecoveryRequired): recover_pending(tree)
    assert recover_pending(tree, writers_stopped=True)
    assert not (tree / 'ignored').exists() and not guard.pending.exists()
    guard.keep = False


def test_protected_directory_alias_protects_all_descendants(tree):
    shutil.rmtree(tree / 'fuzz')
    (tree / 'helpers').mkdir()
    (tree / 'helpers/target.c').write_text('int entry;')
    (tree / 'helpers/support.c').write_text('int support;')
    (tree / 'fuzz').symlink_to('helpers', target_is_directory=True)
    g = SourceScopeGuard(tree, harness='fuzz/target.c')
    try:
        assert 'helpers/support.c' not in g.allowed
        (tree / 'helpers/support.c').write_text('changed support')
        with pytest.raises(SourceScopeViolation): g.validate()
    finally: g.close()


def test_directory_exclusion_glob_follows_trusted_alias_to_protected_files(tree):
    (tree / 'libsupport').mkdir()
    (tree / 'libsupport/helper.c').write_text('int shared;')
    (tree / 'support').symlink_to('libsupport', target_is_directory=True)
    g = SourceScopeGuard(tree, harness='fuzz/target.c', exclude_globs=('support/**',))
    try:
        assert 'libsupport/helper.c' not in g.allowed
        (tree / 'libsupport/helper.c').write_text('changed')
        with pytest.raises(SourceScopeViolation): g.validate()
    finally: g.close()


def test_protected_alias_of_source_root_fails_closed_for_every_source(tree):
    shutil.rmtree(tree / 'fuzz')
    (tree / 'entry.c').write_text('int entry;')
    (tree / 'fuzz').symlink_to('.', target_is_directory=True)
    g = SourceScopeGuard(tree, harness='entry.c')
    try:
        assert not g.allowed
    finally: g.close()


@pytest.mark.parametrize('name', ['config.h', 'config.hh', 'config.hpp', 'config.hxx'])
def test_conventional_configuration_headers_are_protected(tree, name):
    (tree / name).write_text('#define PARSE_ENABLED 1')
    g = SourceScopeGuard(tree, harness='fuzz/target.c')
    try:
        assert name not in g.allowed
        (tree / name).write_text('#define PARSE_ENABLED 0')
        with pytest.raises(SourceScopeViolation): g.validate()
    finally: g.close()


def test_protected_alias_closure_reaches_transitive_library_named_target(tree):
    shutil.rmtree(tree / 'fuzz')
    (tree / 'entry.c').write_text('int entry;')
    (tree / 'helpers').mkdir()
    (tree / 'helpers/support.c').symlink_to('../odd_helper.c')
    (tree / 'fuzz').symlink_to('helpers', target_is_directory=True)
    g = SourceScopeGuard(tree, harness='entry.c')
    try:
        assert 'odd_helper.c' not in g.allowed
        (tree / 'odd_helper.c').write_text('changed shared helper')
        with pytest.raises(SourceScopeViolation): g.validate()
    finally: g.close()


def test_protected_script_alias_target_cannot_be_edited_as_source(tree):
    (tree / 'build.sh').unlink(); (tree / 'build.sh').symlink_to('odd_helper.c')
    g = SourceScopeGuard(tree, harness='fuzz/target.c')
    try:
        assert 'odd_helper.c' not in g.allowed
    finally: g.close()


def test_ordinary_include_alias_does_not_block_library_headers(tree):
    (tree / 'headers').mkdir()
    (tree / 'headers/library.h').write_text('int library(void);')
    (tree / 'include').symlink_to('headers', target_is_directory=True)
    g = SourceScopeGuard(tree, harness='fuzz/target.c')
    try:
        assert 'headers/library.h' in g.allowed
        (tree / 'headers/library.h').write_text('int library(int arg);')
        g.validate()
    finally: g.close()


@pytest.mark.parametrize('pattern', ['support/inc/foo.c', 'sup*/inc/*.c'])
def test_explicit_exclusion_through_composed_directory_aliases(tree, pattern):
    (tree / 'helpers').mkdir(); (tree / 'real').mkdir()
    (tree / 'real/foo.c').write_text('int protected;')
    (tree / 'helpers/inc').symlink_to('../real', target_is_directory=True)
    (tree / 'support').symlink_to('helpers', target_is_directory=True)
    g = SourceScopeGuard(tree, harness='fuzz/target.c', exclude_globs=(pattern,))
    try:
        assert 'real/foo.c' not in g.allowed
        (tree / 'real/foo.c').write_text('changed')
        with pytest.raises(SourceScopeViolation): g.validate()
    finally: g.close()


def test_resuming_same_output_directory_archives_stale_violation(tree, tmp_path, monkeypatch):
    def bad_agent(*a, **k):
        (tree / 'fuzz/target.c').write_text('bad')
        return {'ok':False, 'timed_out':False, 'stdout':'', 'stderr':''}
    assert not _optimize(monkeypatch, tree, tmp_path, bad_agent, lambda: pytest.fail('forbidden build'))
    def good_agent(*a, **k):
        (tree / 'library.c').write_text('int valid_change;')
        return {'ok':True, 'timed_out':False, 'stdout':'done', 'stderr':''}
    assert _optimize(monkeypatch, tree, tmp_path, good_agent, lambda: (True, 'built'))
    assert not (tmp_path / 'diff/source_scope_violation.json').exists()
    assert list((tmp_path / 'diff').glob('source_scope_violation.previous-*.json'))
