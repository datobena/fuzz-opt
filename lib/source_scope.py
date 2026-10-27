"""Host-owned edit policy; agent-visible Git state is never an authority.

Only contents of pre-existing library C/C++ files may change. Build from a
validated private copy while an agent is live: validating a writable mount and
then compiling that mount leaves a check/use race.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

SOURCE_SUFFIXES = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx'}
FUZZ_DIRS = {'fuzz', 'fuzzer', 'fuzzers', 'fuzzing', 'oss-fuzz', 'oss_fuzz',
             'fuzz-targets', 'fuzz_targets', 'fuzzing-headers'}
CONFIG_HEADERS = {'config.h', 'config.hh', 'config.hpp', 'config.hxx'}
FUZZ_ENTRY = re.compile(rb'\b(?:LLVMFuzzerTestOneInput|LLVMFuzzerInitialize|'
                        rb'__AFL_LOOP|__AFL_INIT|__AFL_FUZZ_INIT)\b')
_current: ContextVar = ContextVar('source_scope_guard', default=None)


class SourceScopeRecoveryRequired(RuntimeError):
    """A prior writer's absence/restoration has not been established."""


def recovery_marker(source_dir):
    p = Path(source_dir).absolute()
    return p.parent / ('.source-scope-recovery-' + p.name + '.json')


def require_recovered(source_dir):
    marker = recovery_marker(source_dir)
    if marker.exists():
        raise SourceScopeRecoveryRequired(
            'source has pending recovery; stop all previous writers and restore '
            'the trusted backup before retrying')


class SourceScopeViolation(RuntimeError):
    def __init__(self, violations):
        self.violations = list(violations)
        super().__init__('Source edit scope rejected: ' + '; '.join(self.violations[:25]))


def _copy_and_inventory(root: Path, destination: Path | None = None):
    """Walk through directory FDs, never following an untrusted symlink.

    No glob/rglob/copytree follows a raced parent directory. Files are opened
    O_NOFOLLOW and copied through their FD; changes during a read fail closed.
    """
    entries = {}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        def walk(dfd, rel):
            ds = os.fstat(dfd)
            entries[rel] = {'kind': 'dir', 'mode': stat.S_IMODE(ds.st_mode)}
            if destination is not None:
                (destination / rel).mkdir(parents=True, exist_ok=True)
            for name in sorted(os.listdir(dfd)):
                path = f'{rel}/{name}' if rel else name
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                mode = stat.S_IMODE(st.st_mode)
                if stat.S_ISDIR(st.st_mode):
                    child = os.open(name, flags, dir_fd=dfd)
                    try:
                        if (st.st_dev, st.st_ino) != (os.fstat(child).st_dev, os.fstat(child).st_ino):
                            raise SourceScopeViolation([f'{path}: directory changed during capture'])
                        walk(child, path)
                    finally:
                        os.close(child)
                elif stat.S_ISLNK(st.st_mode):
                    target = os.readlink(name, dir_fd=dfd)
                    entries[path] = {'kind': 'symlink', 'mode': mode, 'target': target}
                    if destination is not None:
                        (destination / path).symlink_to(target)
                        os.utime(destination / path, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
                elif stat.S_ISREG(st.st_mode):
                    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                    try:
                        before = os.fstat(f)
                        if not stat.S_ISREG(before.st_mode) or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
                            raise SourceScopeViolation([f'{path}: file changed during capture'])
                        h = hashlib.sha256()
                        output = (destination / path).open('wb') if destination is not None else None
                        try:
                            while True:
                                data = os.read(f, 1024 * 1024)
                                if not data:
                                    break
                                h.update(data)
                                if output is not None:
                                    output.write(data)
                        finally:
                            if output is not None:
                                output.close()
                        after = os.fstat(f)
                        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
                        if any(getattr(before, k) != getattr(after, k) for k in fields):
                            raise SourceScopeViolation([f'{path}: file changed during capture'])
                    finally:
                        os.close(f)
                    entries[path] = {'kind': 'file', 'mode': mode, 'sha256': h.hexdigest(),
                                     'nlink': before.st_nlink, 'mtime_ns': before.st_mtime_ns}
                    if destination is not None:
                        target = destination / path
                        target.chmod(mode)
                        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                else:
                    raise SourceScopeViolation([f'{path}: unsupported filesystem object'])
            if destination is not None:
                (destination / rel).chmod(stat.S_IMODE(ds.st_mode))
                os.utime(destination / rel, ns=(ds.st_atime_ns, ds.st_mtime_ns))
        walk(fd, '')
    finally:
        os.close(fd)
    return entries


class SourceScopeGuard:
    def __init__(self, source_dir, *, harness='', exclude_globs=(), report_path=None):
        self.source = Path(source_dir).absolute()
        if self.source.is_symlink():
            raise SourceScopeViolation(['source root is a symlink'])
        # Resolve trusted ancestor symlinks once; the original root identity is
        # pinned below, and all subsequent traversal is no-follow.
        self.source = self.source.resolve(strict=True)
        self._identity = self._root_identity()
        self.pending = self.source.parent / ('.source-scope-recovery-' + self.source.name + '.json')
        if self.pending.exists():
            raise SourceScopeRecoveryRequired('source has pending recovery; refusing to establish a new baseline')
        self.keep = False
        self._private = Path(tempfile.mkdtemp(prefix='fuzz-source-scope-'))
        self.baseline = self._private / 'baseline' / self.source.name
        self.report_path = Path(report_path) if report_path else None
        self.violations = []
        try:
            self.entries = _copy_and_inventory(self.source, self.baseline)
            if any(e.get('nlink', 1) != 1 for e in self.entries.values()):
                raise SourceScopeViolation(['baseline contains hardlinked files; refusing an ambiguous edit boundary'])
            hp = Path(harness)
            if not hp.is_absolute():
                hp = self.source / hp
            try:
                hp = hp.resolve(strict=True)
            except (OSError, RuntimeError):
                raise SourceScopeViolation(['harness path did not resolve; refusing to guess edit scope']) from None
            try:
                harness_relative = str(hp.relative_to(self.source))
            except ValueError:
                harness_relative = None
            if not harness or not hp.is_file():
                raise SourceScopeViolation(['harness path did not resolve; refusing to guess edit scope'])
            def protected_name(name):
                p = Path(name)
                return (p.name.lower() in CONFIG_HEADERS
                        or any(part.lower() in FUZZ_DIRS for part in p.parts)
                        or 'fuzz' in p.stem.lower()
                        or any(fnmatch.fnmatchcase(name, pattern) for pattern in exclude_globs))

            aliases = []
            for name, entry in self.entries.items():
                if entry['kind'] != 'symlink':
                    continue
                try:
                    resolved = (self.source / name).resolve(strict=True)
                    target = resolved.relative_to(self.source)
                except (OSError, ValueError, RuntimeError):
                    continue
                aliases.append((name, str(target), resolved.is_dir()))

            def under(name, target):
                return target == '.' or name == target or name.startswith(target + '/')

            # Closure is needed for fuzz -> helpers -> real.c, and for globs
            # designating logical descendants behind an otherwise ordinary
            # directory alias. Non-source file aliases (build.sh -> helper.c)
            # protect their targets too; ordinary include-directory aliases do
            # not blanket-disable library edits.
            protected_alias_targets = {harness_relative} if harness_relative else set()
            changed = True
            while changed:
                previous = set(protected_alias_targets)
                for name, target, is_dir in aliases:
                    if (protected_name(name)
                            or (not is_dir and Path(name).suffix.lower() not in SOURCE_SUFFIXES)
                            or any(under(name, item) for item in protected_alias_targets)):
                        protected_alias_targets.add(target)
                    if is_dir:
                        # A pattern can continue through another alias not
                        # enumerated under this directory. Conservatively
                        # protect the target subtree when this alias matches a
                        # directory prefix of an explicit exclusion.
                        if any(fnmatch.fnmatchcase(name, '/'.join(pattern.split('/')[:depth]))
                               for pattern in exclude_globs
                               for depth in range(1, len(pattern.split('/')))):
                            protected_alias_targets.add(target)
                        prefix = '' if target == '.' else target + '/'
                        for actual in self.entries:
                            if actual.startswith(prefix):
                                logical = name + '/' + actual[len(prefix):]
                                if any(fnmatch.fnmatchcase(logical, pattern) for pattern in exclude_globs):
                                    protected_alias_targets.add(actual)
                changed = previous != protected_alias_targets
            self.allowed = set()
            for name, entry in self.entries.items():
                p = Path(name)
                if entry['kind'] != 'file' or entry['nlink'] != 1 or p.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                if name == harness_relative or protected_name(name) or any(target == '.' or name == target or name.startswith(target + '/') for target in protected_alias_targets):
                    continue
                if any(fnmatch.fnmatchcase(name, pattern) for pattern in exclude_globs):
                    continue
                # Protect harnesses with unconventional names, and headers that
                # implement fuzz-only entry points, independently of filenames.
                if FUZZ_ENTRY.search((self.baseline / name).read_bytes()):
                    continue
                self.allowed.add(name)
            (self._private / 'policy.json').write_text(json.dumps({
                'source': str(self.source), 'allowed': sorted(self.allowed),
                'protected': sorted(set(self.entries) - self.allowed),
                'entries': self.entries}, indent=2))
        except BaseException:
            self.close()
            raise

    def _root_identity(self):
        st = self.source.lstat()
        if not stat.S_ISDIR(st.st_mode):
            raise SourceScopeViolation(['source root is not a directory'])
        return st.st_dev, st.st_ino

    def _check(self, entries):
        problems = []
        for name in sorted(set(self.entries) | set(entries)):
            before, after = self.entries.get(name), entries.get(name)
            label = name or '.'
            if before is None:
                problems.append(f'{label}: added path')
            elif after is None:
                problems.append(f'{label}: deleted path')
            elif before['kind'] != after['kind'] or before['mode'] != after['mode']:
                problems.append(f'{label}: file type or mode changed')
            elif before['kind'] == 'file':
                if before['nlink'] != after['nlink']:
                    problems.append(f'{label}: hardlink count changed')
                elif name not in self.allowed and (before['sha256'] != after['sha256'] or before['mtime_ns'] != after['mtime_ns']):
                    problems.append(f'{label}: protected file modified')
            elif before != after:
                problems.append(f'{label}: protected path modified')
        if problems:
            self._reject(problems)

    def _reject(self, problems):
        self.violations.extend(x for x in problems if x not in self.violations)
        if self.report_path:
            self.report_path.parent.mkdir(parents=True, exist_ok=True)
            self.report_path.write_text(json.dumps({'ok': False, 'violations': self.violations}, indent=2))
        raise SourceScopeViolation(problems)

    def validate(self):
        if self.violations:
            self._reject(self.violations)
        try:
            if self._root_identity() != self._identity:
                self._reject(['source root was replaced'])
            self._check(_copy_and_inventory(self.source))
        except SourceScopeViolation as exc:
            self._reject(exc.violations)
        except OSError as exc:
            self._reject([f'cannot safely inspect source ({type(exc).__name__})'])

    @contextmanager
    def snapshot(self):
        """Validated, private build input. Agent writes cannot race the build."""
        if self.violations:
            self._reject(self.violations)
        work = Path(tempfile.mkdtemp(prefix='candidate-', dir=self._private))
        candidate = work / self.source.name
        try:
            if self._root_identity() != self._identity:
                self._reject(['source root was replaced'])
            entries = _copy_and_inventory(self.source, candidate)
            self._check(entries)
            yield candidate
        except SourceScopeViolation as exc:
            self._reject(exc.violations)
        except OSError as exc:
            self._reject([f'cannot safely snapshot source ({type(exc).__name__})'])
        finally:
            # Kept until the complete optimizer session is confirmed stopped:
            # a failed docker client can leave a builder using this snapshot.
            pass

    def restore(self, snapshot=None):
        """Restore ignored/untracked paths too, only after all writers stopped."""
        _remove_tree(self.source)
        shutil.copytree(snapshot or self.baseline, self.source, symlinks=True)
        self._identity = self._root_identity()

    def defer_recovery(self, containers=()):
        self.keep = True
        self.pending.write_text(json.dumps({'source': str(self.source),
                                            'baseline': str(self.baseline),
                                            'policy': str(self._private / 'policy.json'),
                                            'containers': list(containers)}, indent=2))
        self.pending.chmod(0o600)

    def close(self):
        if not self.keep:
            _remove_tree(self._private)


def _remove_tree(path):
    """Repair directory permissions without following symlinks before removal.

    Called on private snapshots or an agent tree AFTER writers are stopped.
    """
    path = Path(path)
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        path.unlink()
        return
    if stat.S_IMODE(st.st_mode) & 0o700 != 0o700:
        path.chmod(stat.S_IMODE(st.st_mode) | 0o700)
    for child in path.iterdir():
        _remove_tree(child)
    path.rmdir()


def current_guard():
    return _current.get()


def start_guard(*args, **kwargs):
    guard = SourceScopeGuard(*args, **kwargs)
    _current.set(guard)
    return guard


@contextmanager
def scope_session():
    token = _current.set(None)
    try:
        yield
    finally:
        guard = _current.get()
        if guard is not None:
            guard.close()
        _current.reset(token)


def recover_pending(source_dir, *, writers_stopped=False):
    """Host recovery, only AFTER all old agent/build containers are gone."""
    marker = recovery_marker(source_dir)
    if not marker.exists():
        return False
    if not writers_stopped:
        raise SourceScopeRecoveryRequired('refusing recovery while writers may be live')
    record = json.loads(marker.read_text())
    source = Path(source_dir).absolute()
    baseline = Path(record['baseline'])
    if str(source.resolve(strict=False)) != record['source'] and not source.is_symlink():
        raise SourceScopeRecoveryRequired('pending recovery source does not match')
    _remove_tree(source)
    shutil.copytree(baseline, source, symlinks=True)
    _remove_tree(baseline.parent.parent)
    marker.unlink()
    return True
