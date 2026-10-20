"""Run a local EVM decompiler and retain its output as heuristic evidence."""
import codecs
import hashlib
from io import StringIO
import math
import os
from pathlib import Path
import re
import stat
try:
    import resource
except ImportError:  # pragma: no cover - Windows has no resource module.
    resource = None
import shutil
import signal
import subprocess
import sys
import tempfile
import time


MAX_BYTECODE_BYTES = 131_072
MAX_ARTIFACTS = 256
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_TREE_ENTRIES = 512
MAX_PSEUDOCODE_BUFFER_PARTS = 1024
MAX_PSEUDOCODE_BUFFER_CHARS = 64 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_DECOMPILER_OPEN_FILES = 1024
MAX_PROCESS_TREE_RSS_BYTES = 8 * 1024 * 1024 * 1024
PROCESS_TREE_RSS_POLL_INTERVAL_SECONDS = 0.25
ARTIFACT_USAGE_POLL_INTERVAL_SECONDS = 0.1
_PSEUDOCODE_SPECIAL_TOKEN = re.compile(r'//|/\*|["\']')


class ArtifactBudgetExceeded(RuntimeError):
    pass


class ProcessTreeCleanupIncomplete(ArtifactBudgetExceeded):
    def __init__(self, message, *, timed_out=False, output=None, stderr=None):
        super().__init__(message)
        self.timed_out = timed_out
        self.output = output
        self.stderr = stderr


_RESOURCE_LIMIT_EXEC = (
    'import os, resource, sys\n'
    'file_limit = int(sys.argv[1])\n'
    'cpu_limit = int(sys.argv[2])\n'
    'nofile_limit = int(sys.argv[3])\n'
    'def apply_limit(kind, requested):\n'
    '    soft, hard = resource.getrlimit(kind)\n'
    '    hard = requested if hard == resource.RLIM_INFINITY else min(hard, requested)\n'
    '    soft = hard if soft == resource.RLIM_INFINITY else min(soft, hard)\n'
    '    resource.setrlimit(kind, (soft, hard))\n'
    'apply_limit(resource.RLIMIT_FSIZE, file_limit)\n'
    'apply_limit(resource.RLIMIT_CPU, cpu_limit)\n'
    'apply_limit(resource.RLIMIT_NOFILE, nofile_limit)\n'
    'command = sys.argv[4:]\n'
    'os.execvpe(command[0], command, os.environ)\n'
)


def _validate_bytecode(bytecode):
    if not isinstance(bytecode, str):
        raise ValueError('runtime bytecode must be non-empty, even-length 0x hex')
    if len(bytecode) > 2 + MAX_BYTECODE_BYTES * 2:
        raise ValueError(f'runtime bytecode exceeds {MAX_BYTECODE_BYTES} byte limit')
    if not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', bytecode):
        raise ValueError('runtime bytecode must be non-empty, even-length 0x hex')
    raw = bytes.fromhex(bytecode[2:])
    if len(raw) > MAX_BYTECODE_BYTES:
        raise ValueError(f'runtime bytecode exceeds {MAX_BYTECODE_BYTES} byte limit')
    return raw


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(HASH_CHUNK_BYTES), b''):
            digest.update(block)
    return digest.hexdigest()


def _sha256_and_text(path):
    """Hash and decode a bounded text artifact from the same file pass."""
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder('utf-8')('replace')
    text_parts = []
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(HASH_CHUNK_BYTES), b''):
            digest.update(block)
            text_parts.append(decoder.decode(block))
    text_parts.append(decoder.decode(b'', final=True))
    return digest.hexdigest(), ''.join(text_parts)


def _write_process_output(path, value):
    if isinstance(value, bytes):
        Path(path).write_bytes(value)
    else:
        Path(path).write_text(value or '', encoding='utf-8')


def _read_process_table(*, timeout=2):
    ps_binary = shutil.which('ps')
    if not ps_binary:
        raise ArtifactBudgetExceeded('process_memory_monitor_unavailable')
    try:
        result = subprocess.run(
            [ps_binary, '-axo', 'pid=,ppid=,rss=,uid=,stat=,lstart='], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        if timeout < 2:
            raise
        raise ArtifactBudgetExceeded('process_memory_monitor_unavailable') from error
    except OSError as error:
        raise ArtifactBudgetExceeded('process_memory_monitor_unavailable') from error
    if result.returncode != 0:
        raise ArtifactBudgetExceeded('process_memory_monitor_unavailable')

    rows = {}
    children_by_parent = {}
    try:
        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            if len(fields) != 10:
                raise ValueError('unexpected ps output')
            pid, parent, rss_kib, uid = (int(field) for field in fields[:4])
            state = fields[4]
            if pid <= 0 or parent < 0 or rss_kib < 0 or uid < 0 or not state:
                raise ValueError('invalid ps process row')
            if pid in rows:
                raise ValueError('duplicate ps process id')
            rows[pid] = {
                'parent': parent,
                'rss': rss_kib * 1024,
                'uid': uid,
                'state': state,
                'start': tuple(fields[5:]),
            }
            children_by_parent.setdefault(parent, []).append(pid)
    except ValueError as error:
        raise ArtifactBudgetExceeded('process_memory_monitor_invalid_output') from error
    if not rows:
        raise ArtifactBudgetExceeded('process_memory_monitor_invalid_output')
    return rows, children_by_parent


def _kill_observed_descendants(observed_processes):
    if not observed_processes:
        return False, True
    if os.name == 'nt':
        return False, False
    try:
        rows, _ = _read_process_table()
    except ArtifactBudgetExceeded:
        return True, False

    live = []
    for pid, identity in observed_processes.items():
        row = rows.get(pid)
        if row and row['state'].upper().startswith('Z'):
            continue
        if row and (row['uid'], row['start']) == identity:
            live.append(pid)

    cleanup_incomplete = False
    for pid in live:
        pidfd = None
        try:
            pidfd_open = getattr(os, 'pidfd_open', None)
            pidfd_send_signal = getattr(signal, 'pidfd_send_signal', None)
            if callable(pidfd_open) and callable(pidfd_send_signal):
                pidfd = pidfd_open(pid, 0)
            # Revalidate after opening a stable Linux process handle and as
            # close as possible to a numeric-PID signal on other POSIX hosts.
            current_rows, _ = _read_process_table()
            row = current_rows.get(pid)
            if not row or row['state'].upper().startswith('Z'):
                continue
            if (row['uid'], row['start']) != observed_processes[pid]:
                continue
            if pidfd is not None:
                pidfd_send_signal(pidfd, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            cleanup_incomplete = True
        except ArtifactBudgetExceeded:
            cleanup_incomplete = True
        finally:
            if pidfd is not None:
                try:
                    os.close(pidfd)
                except OSError:
                    pass

    if not live:
        return False, True
    time.sleep(0.05)
    try:
        rows, _ = _read_process_table()
    except ArtifactBudgetExceeded:
        return True, False
    remains = any(
        (row := rows.get(pid)) is not None and not row['state'].upper().startswith('Z')
        and (row['uid'], row['start']) == observed_processes[pid]
        for pid in live
    )
    return True, not remains and not cleanup_incomplete


def _kill_process_group(process, observed_processes=None):
    if os.name == 'nt':
        try:
            result = subprocess.run(
                ['taskkill', '/PID', str(process.pid), '/T', '/F'],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=1,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
        except OSError:
            pass
        return False
    group_terminated = True
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.kill()
        except OSError:
            pass
        group_terminated = False
    else:
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                process.kill()
            except OSError:
                pass
            group_terminated = False
    if _process_group_exists(process.pid) is True:
        group_terminated = False
    if observed_processes:
        _, observed_terminated = _kill_observed_descendants(observed_processes)
        group_terminated = group_terminated and observed_terminated
    return group_terminated


def _process_group_exists(process_id):
    if os.name == 'nt':
        return None
    try:
        os.killpg(process_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _process_tree_cleanup_disclosure():
    if os.name == 'nt':
        return {
            'mechanism': 'taskkill_parent_tree_best_effort',
            'trackedScope': 'unverified',
            'detachedDescendants': 'not_verified',
            'escapeCondition': 'descendant_detaches_from_parent_process_tree',
        }
    return {
        'mechanism': 'posix_process_group_plus_observed_descendant_pids',
        'trackedScope': 'initial_process_group_and_descendants_seen_in_periodic_process_snapshots',
        'detachedDescendants': 'observed_descendants_terminated_on_exit_or_cleanup; unobserved_descendants_may_escape',
        'escapeCondition': 'descendant_detaches_or_is_reparented_before_its_first_process_snapshot',
        'pidIdentityPrecision': 'uid_and_ps_lstart_seconds_with_immediate_pre_signal_revalidation; same_second_pid_reuse_remains_possible_without_pidfd',
    }


def _terminate_and_reap(process, *, timed_out=False, observed_processes=None):
    tree_terminated = _kill_process_group(process, observed_processes)
    try:
        output = process.communicate(timeout=1)
    except subprocess.TimeoutExpired as first_timeout:
        try:
            process.kill()
        except OSError:
            pass
        try:
            output = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            output = (first_timeout.output, first_timeout.stderr)
    if os.name != 'nt':
        deadline = time.monotonic() + 0.5
        group_exists = _process_group_exists(process.pid)
        descendants_alive = False
        descendant_state_verified = True
        while time.monotonic() < deadline:
            if observed_processes:
                try:
                    rows, _ = _read_process_table()
                except ArtifactBudgetExceeded:
                    descendant_state_verified = False
                    break
                descendants_alive = any(
                    (row := rows.get(pid)) is not None
                    and not row['state'].upper().startswith('Z')
                    and (row['uid'], row['start']) == identity
                    for pid, identity in observed_processes.items()
                )
            if group_exists is False and not descendants_alive:
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            group_exists = _process_group_exists(process.pid)
        if group_exists is not False or descendants_alive or not descendant_state_verified:
            tree_terminated = False
        else:
            tree_terminated = True
    if not tree_terminated:
        stdout_output, stderr_output = output
        raise ProcessTreeCleanupIncomplete(
            'decompiler_process_tree_cleanup_incomplete', timed_out=timed_out,
            output=stdout_output, stderr=stderr_output,
        )
    return output


def _scan_artifact_usage(output_dir):
    pending = [Path(output_dir)]
    total_bytes = 0
    artifact_count = 0
    entry_count = 0
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as error:
            raise ArtifactBudgetExceeded('artifact_inventory_unavailable') from error
        with entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_ARTIFACT_TREE_ENTRIES:
                    raise ArtifactBudgetExceeded('artifact_tree_entry_limit_exceeded')
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise ArtifactBudgetExceeded('artifact_inventory_unavailable') from error
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(Path(entry.path))
                    continue
                artifact_count += 1
                if artifact_count > MAX_ARTIFACTS:
                    raise ArtifactBudgetExceeded('artifact_count_limit_exceeded')
                total_bytes += metadata.st_size
                if metadata.st_size >= MAX_ARTIFACT_BYTES:
                    raise ArtifactBudgetExceeded('artifact_file_size_limit_exceeded')
                if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                    raise ArtifactBudgetExceeded('artifact_total_bytes_limit_exceeded')
    return total_bytes, artifact_count, entry_count


def _process_tree_rss_bytes(process_id, observed_processes=None, *, timeout=2):
    ps_binary = shutil.which('ps')
    if not ps_binary:
        raise ArtifactBudgetExceeded('process_memory_monitor_unavailable')
    rows, children_by_parent = _read_process_table(timeout=timeout)

    if process_id not in rows:
        raise ArtifactBudgetExceeded('process_memory_monitor_target_missing')

    total = 0
    pending = [process_id]
    visited = set()
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        row = rows.get(pid)
        if row:
            total += row['rss']
            if pid != process_id and observed_processes is not None:
                # A PID can be recycled while this process tree is still alive.
                # Refresh its generation only while it is reachable from root.
                observed_processes[pid] = (row['uid'], row['start'])
        pending.extend(children_by_parent.get(pid, ()))

    # A sampled descendant may have been reparented after its parent exited.
    # Keep counting it while its process identity still matches the sample.
    if observed_processes is not None:
        pending = [
            pid for pid, identity in observed_processes.items()
            if pid not in visited
            and (row := rows.get(pid)) is not None
            and not row['state'].upper().startswith('Z')
            and (row['uid'], row['start']) == identity
        ]
        while pending:
            pid = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            row = rows.get(pid)
            if row is None or row['state'].upper().startswith('Z'):
                continue
            total += row['rss']
            pending.extend(children_by_parent.get(pid, ()))
    return total


def _preflight_process_tree_rss_monitor():
    if os.name == 'nt':
        raise ArtifactBudgetExceeded('decompiler_process_tree_status_unverifiable')
    # Validate the monitor before starting the external binary; a missing or
    # unusable ps command must never turn into an unmonitored decompile run.
    _process_tree_rss_bytes(os.getpid())


def _run_process(command, *, timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 text=False, artifact_dir=None):
    """Run a bounded tool and clean its process group and observed descendants."""
    if artifact_dir is not None:
        _preflight_process_tree_rss_monitor()
    popen_command = command
    if artifact_dir is not None and os.name != 'nt' and resource is not None:
        cpu_limit = max(1, math.ceil(float(timeout)) + 1)
        popen_command = [
            sys.executable, '-c', _RESOURCE_LIMIT_EXEC,
            str(MAX_ARTIFACT_BYTES), str(cpu_limit), str(MAX_DECOMPILER_OPEN_FILES), *command,
        ]
    process = subprocess.Popen(
        popen_command, stdout=stdout, stderr=stderr, text=text, start_new_session=os.name != 'nt',
        creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0) if os.name == 'nt' else 0,
    )
    cleaned = False
    observed_processes = {}

    def terminate_process(*, timed_out=False):
        options = {}
        if timed_out:
            options['timed_out'] = True
        if observed_processes:
            options['observed_processes'] = observed_processes
        return _terminate_and_reap(process, **options)

    try:
        if artifact_dir is None:
            output, error = process.communicate(timeout=timeout)
        else:
            deadline = time.monotonic() + timeout
            next_artifact_check = 0
            next_memory_check = 0
            while process.poll() is None:
                now = time.monotonic()
                if now >= next_artifact_check:
                    _scan_artifact_usage(artifact_dir)
                    next_artifact_check = (
                        time.monotonic() + ARTIFACT_USAGE_POLL_INTERVAL_SECONDS
                    )
                now = time.monotonic()
                if now >= next_memory_check:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        process_tree_rss = _process_tree_rss_bytes(
                            process.pid, observed_processes, timeout=min(2, remaining),
                        )
                    except ArtifactBudgetExceeded as error:
                        if str(error) == 'process_memory_monitor_target_missing' and process.poll() is not None:
                            break
                        raise
                    if process_tree_rss > MAX_PROCESS_TREE_RSS_BYTES:
                        raise ArtifactBudgetExceeded('process_tree_memory_limit_exceeded')
                    next_memory_check = now + PROCESS_TREE_RSS_POLL_INTERVAL_SECONDS
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(min(0.05, remaining))
            # The parent may have exited while a descendant still owns the
            # stdout/stderr pipe. Keep the final drain bounded so the process
            # group liveness check below can run and report the orphan.
            try:
                output, error = process.communicate(timeout=0.25)
            except subprocess.TimeoutExpired:
                terminate_process()
                cleaned = True
                raise ArtifactBudgetExceeded('decompiler_child_process_outlived_parent')
        process_group_exists = _process_group_exists(process.pid)
        if process_group_exists is True:
            terminate_process()
            cleaned = True
            raise ArtifactBudgetExceeded('decompiler_child_process_outlived_parent')
        if process_group_exists is None and artifact_dir is not None:
            terminate_process()
            cleaned = True
            raise ArtifactBudgetExceeded('decompiler_process_tree_status_unverifiable')
        if artifact_dir is not None:
            escaped_descendant, tree_terminated = _kill_observed_descendants(observed_processes)
            if escaped_descendant:
                cleaned = True
                if not tree_terminated:
                    raise ProcessTreeCleanupIncomplete(
                        'decompiler_process_tree_cleanup_incomplete', output=output, stderr=error,
                    )
                raise ArtifactBudgetExceeded('decompiler_child_process_outlived_parent')
        if artifact_dir is not None:
            _scan_artifact_usage(artifact_dir)
    except ProcessTreeCleanupIncomplete:
        raise
    except ArtifactBudgetExceeded:
        if not cleaned:
            terminate_process()
        raise
    except subprocess.TimeoutExpired:
        output, error = terminate_process(timed_out=True)
        raise subprocess.TimeoutExpired(command, timeout, output=output, stderr=error)
    except BaseException as interrupted:
        try:
            terminate_process()
        except BaseException as cleanup_error:
            raise interrupted from cleanup_error
        raise
    return subprocess.CompletedProcess(command, process.returncode, output, error)


def _artifact_inventory(output_dir, *, pseudocode_paths=None):
    artifacts = []
    overflow = 0
    omitted = 0
    total_bytes = 0
    entry_count = 0
    pending = [Path(output_dir)]
    while pending and not overflow:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError:
            omitted += 1
            continue
        with entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_ARTIFACT_TREE_ENTRIES:
                    overflow = 1
                    break
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError:
                    if len(artifacts) >= MAX_ARTIFACTS:
                        overflow = 1
                        break
                    artifacts.append({
                        'path': Path(entry.path).relative_to(output_dir).as_posix(),
                        'size': 0,
                        'omittedReason': 'artifact_unreadable',
                    })
                    omitted += 1
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(Path(entry.path))
                    continue
                if len(artifacts) >= MAX_ARTIFACTS:
                    overflow = 1
                    break
                path = Path(entry.path)
                item = {
                    'path': path.relative_to(output_dir).as_posix(),
                    'size': metadata.st_size,
                }
                total_bytes += item['size']
                if stat.S_ISLNK(metadata.st_mode):
                    item['omittedReason'] = 'symlink_artifact_omitted'
                elif not stat.S_ISREG(metadata.st_mode):
                    item['omittedReason'] = 'non_regular_artifact_omitted'
                elif item['size'] >= MAX_ARTIFACT_BYTES:
                    item['omittedReason'] = 'file_at_or_exceeds_per_file_limit'
                elif total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                    item['omittedReason'] = 'total_artifact_bytes_limit_exceeded'
                else:
                    try:
                        if (pseudocode_paths is not None and
                                path.suffix.lower() in ('.sol', '.yul')):
                            item['sha256'], text = _sha256_and_text(path)
                            if _has_pseudocode_text(path.suffix, text):
                                pseudocode_paths.add(item['path'])
                        else:
                            item['sha256'] = _sha256(path)
                    except OSError:
                        item['omittedReason'] = 'artifact_unreadable'
                if 'omittedReason' in item:
                    omitted += 1
                artifacts.append(item)
    artifacts.sort(key=lambda item: item['path'])
    return artifacts, overflow, omitted, total_bytes


def _pseudocode_code(text):
    """Mask comments and literal bodies in one pass, preserving quoted Yul names."""
    if _PSEUDOCODE_SPECIAL_TOKEN.search(text) is None:
        return text
    pieces = []
    buffered_chars = 0
    output = StringIO()

    def append(piece):
        nonlocal buffered_chars
        if not piece:
            return
        pieces.append(piece)
        buffered_chars += len(piece)
        # Dense short comments must not retain one list entry per comment.
        if (len(pieces) >= MAX_PSEUDOCODE_BUFFER_PARTS or
                buffered_chars >= MAX_PSEUDOCODE_BUFFER_CHARS):
            output.write(''.join(pieces))
            pieces.clear()
            buffered_chars = 0

    index = 0
    code_start = 0
    while index < len(text):
        if text.startswith('//', index):
            append(text[code_start:index])
            index += 2
            while index < len(text) and text[index] not in '\r\n':
                index += 1
            append(' ')
            code_start = index
        elif text.startswith('/*', index):
            append(text[code_start:index])
            # Search once from this opener. An unclosed block consumes the
            # remainder, rather than retrying every nested-looking opener.
            end = text.find('*/', index + 2)
            append(' ')
            if end == -1:
                code_start = len(text)
                break
            index = end + 2
            code_start = index
        elif text[index] in ('"', "'"):
            append(text[code_start:index])
            quote = text[index]
            literal_start = index
            closed = False
            index += 1
            while index < len(text):
                if text[index] == '\\':
                    index = min(index + 2, len(text))
                elif text[index] == quote:
                    index += 1
                    closed = True
                    break
                else:
                    index += 1
            # Keep quote boundaries/newlines for object "name" hints, but
            # never interpret declaration-looking text inside a literal.
            body_end = index - 1 if closed else index
            append(quote)
            # Bound join's temporary sequence as well as the outer buffer.
            for start in range(literal_start + 1, body_end, MAX_PSEUDOCODE_BUFFER_CHARS):
                chunk = text[start:min(start + MAX_PSEUDOCODE_BUFFER_CHARS, body_end)]
                append(''.join(char if char in '\r\n' else ' ' for char in chunk))
            if closed:
                append(quote)
            code_start = index
        else:
            index += 1
    append(text[code_start:])
    output.write(''.join(pieces))
    return output.getvalue()


def _has_pseudocode_artifact(path):
    suffix = Path(path).suffix.lower()
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return False
    return _has_pseudocode_text(suffix, text)


def _has_pseudocode_text(suffix, text):
    suffix = suffix.lower()
    code = _pseudocode_code(text)
    if suffix == '.sol':
        return re.search(
            r'\b(?:abstract\s+)?(?:contract|interface|library)\s+'
            r'[A-Za-z_$][A-Za-z0-9_$]*[^{};]{0,512}\{', code,
        ) is not None
    if suffix == '.yul':
        return re.search(
            r'\b(?:object\s+(?:"[^"\r\n]+"|[A-Za-z_$][A-Za-z0-9_$]*)\s*\{'
            r'|function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\()', code,
        ) is not None
    return False


def _resolve_binary(binary):
    if not isinstance(binary, (str, os.PathLike)) or not os.fspath(binary):
        return None
    candidate = os.fspath(binary)
    resolved = shutil.which(candidate)
    if resolved:
        return str(Path(resolved).resolve())
    path = Path(candidate).expanduser()
    if path.is_file() and os.access(path, os.X_OK):
        return str(path.resolve())
    return None


def _base_result(raw, output_dir, *, tool_version=None, state='failed', error=None,
                 exit_code=None, timed_out=False, command=None, binary_sha256=None,
                 hardfork=None, artifact_inventory=None,
                 process_tree_rss_monitor_available=None):
    artifacts, overflow, omitted, total_bytes = artifact_inventory or _artifact_inventory(output_dir)
    has_process_tree_rss_monitor = (
        os.name != 'nt' and bool(shutil.which('ps'))
        if process_tree_rss_monitor_available is None
        else bool(process_tree_rss_monitor_available)
    )
    resource_enforcement = 'subprocess RLIMIT_FSIZE/RLIMIT_CPU/RLIMIT_NOFILE'
    if has_process_tree_rss_monitor:
        resource_enforcement += '; sampled process-tree RSS monitor (250ms), not an OS hard quota'
    elif os.name == 'nt' or resource is None:
        resource_enforcement = 'wall timeout and inventory checks only on this platform'
    else:
        resource_enforcement += '; process-tree memory monitor unavailable'
    return {
        'state': state,
        'engine': 'heimdall-rs',
        'toolVersion': tool_version,
        'binarySha256': binary_sha256,
        'inputSha256': hashlib.sha256(raw).hexdigest(),
        'inputBytecodeBytes': len(raw),
        'hardfork': hardfork,
        'processTreeRssLimitBytes': MAX_PROCESS_TREE_RSS_BYTES if has_process_tree_rss_monitor else None,
        'processTreeRssSampleIntervalMs': round(PROCESS_TREE_RSS_POLL_INTERVAL_SECONDS * 1000) if has_process_tree_rss_monitor else None,
        'memoryLimitEnforcement': 'periodic_process_tree_rss_monitor' if has_process_tree_rss_monitor else 'unavailable',
        'processTreeRssCoverage': 'sampled_parent_child_lineage_and_identity_matched_observed_descendants; unsampled fast descendants may escape' if has_process_tree_rss_monitor else 'unavailable',
        'cpuLimitScope': 'per_process_not_aggregate_across_descendants' if os.name != 'nt' and resource is not None else 'wall_timeout_only',
        'processTreeCleanup': _process_tree_cleanup_disclosure(),
        'confidence': 'heuristic',
        'sourceVerified': False,
        'highLevelSemanticsRecovered': False,
        'outputKind': 'inferred_pseudocode_not_verified_source',
        'command': command or [],
        'exitCode': exit_code,
        'timedOut': timed_out,
        'artifacts': artifacts,
        'artifactOverflowCount': overflow,
        'artifactOmittedCount': omitted,
        # Once the inventory cap is hit this is only a prefix sum; do not
        # present it as the total size of an unbounded artifact tree.
        'artifactTotalBytes': total_bytes if overflow == 0 else None,
        'artifactFileLimitBytes': MAX_ARTIFACT_BYTES,
        'artifactAggregateBudgetBytes': MAX_TOTAL_ARTIFACT_BYTES,
        'artifactUsageSampleIntervalMs': round(ARTIFACT_USAGE_POLL_INTERVAL_SECONDS * 1000),
        'artifactAggregateBudgetEnforcement': (
            f'periodic_monitor_{round(ARTIFACT_USAGE_POLL_INTERVAL_SECONDS * 1000)}ms_and_post_run_inventory; '
            f'{resource_enforcement}; no filesystem quota'
        ),
        'artifactInventoryComplete': overflow == 0 and omitted == 0 and total_bytes <= MAX_TOTAL_ARTIFACT_BYTES,
        # Keep the distinction between "the output exists" and "another
        # engine independently agreed with it" explicit.  Artifact references
        # are content-bound when inventory succeeded, and omitted artifacts
        # retain their reason without being presented as validated output.
        'crossValidation': {
            'state': 'not_performed',
            'reason': 'single_decompiler_engine_configured',
            'enginesConfigured': ['heimdall-rs'],
            'enginesCompleted': [],
            'comparedEngineCount': 0,
            'artifactRefs': [
                {
                    'path': artifact.get('path'),
                    'sha256': artifact.get('sha256'),
                    'size': artifact.get('size'),
                    'omittedReason': artifact.get('omittedReason'),
                }
                for artifact in artifacts
                if isinstance(artifact, dict) and isinstance(artifact.get('path'), str)
            ],
            'artifactReferenceState': 'available' if artifacts else 'not_available',
        },
        'error': str(error)[:500] if error else None,
    }


def run_heimdall(bytecode, *, binary, output_dir, timeout_seconds=120, hardfork='latest'):
    """Decompile runtime bytecode without RPC or LLM post-processing.

    `output_dir` must be new. The returned Solidity/Yul files are heuristic
    pseudocode, never verified source.
    """
    raw = _validate_bytecode(bytecode)
    if (isinstance(timeout_seconds, bool) or
            not isinstance(timeout_seconds, (int, float)) or
            not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
        raise ValueError('timeout_seconds must be a positive finite number')
    if not isinstance(hardfork, str) or not hardfork.strip():
        raise ValueError('hardfork must be a non-empty string')

    output_path = Path(output_dir).expanduser().absolute()
    if os.path.lexists(output_path):
        raise ValueError('output_dir must not already exist')
    output_path.mkdir(parents=True)
    stdout_path = output_path / 'stdout.log'
    stderr_path = output_path / 'stderr.log'

    resolved_binary = _resolve_binary(binary)
    binary_sha256 = None
    if resolved_binary:
        try:
            binary_sha256 = _sha256(resolved_binary)
        except OSError as error:
            stderr_path.write_text(
                f'{type(error).__name__}: {error}\n', encoding='utf-8',
            )
            return _base_result(
                raw, output_path, state='unavailable',
                error='heimdall_binary_unreadable', hardfork=hardfork,
            )
    command = []
    if resolved_binary:
        command = [
            resolved_binary, 'decompile', '<runtime-bytecode-file>',
            '--skip-resolving', '--include-sol', '--output', str(output_path),
            '--name', 'decompiled', '--hardfork', hardfork,
            '--timeout', str(max(1, int(timeout_seconds * 1000))), '--quiet',
        ]
    if not resolved_binary:
        stderr_path.write_text(f'Heimdall binary unavailable: {binary}\n', encoding='utf-8')
        return _base_result(raw, output_path, state='unavailable', error='heimdall_binary_unavailable',
                            binary_sha256=binary_sha256, hardfork=hardfork)

    try:
        # Keep version output out of PIPE-backed memory capture. A broken or
        # replaced executable can emit without bound before the wall timeout;
        # file-backed logs are covered by the same artifact and RLIMIT checks
        # as the decompilation process.
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            version_result = _run_process(
                [resolved_binary, '--version'], timeout=5,
                stdout=stdout, stderr=stderr, artifact_dir=output_path,
            )
    except subprocess.TimeoutExpired as error:
        if error.stdout is not None:
            _write_process_output(stdout_path, error.stdout)
        if error.stderr is not None:
            _write_process_output(stderr_path, error.stderr)
        with stderr_path.open('ab') as stderr:
            stderr.write(b'\nHeimdall version check timed out\n')
        return _base_result(raw, output_path, state='timeout', timed_out=True,
                            error='heimdall_version_check_timeout', command=command,
                            binary_sha256=binary_sha256, hardfork=hardfork)
    except ArtifactBudgetExceeded as error:
        if getattr(error, 'output', None) is not None:
            _write_process_output(stdout_path, error.output)
        if getattr(error, 'stderr', None) is not None:
            _write_process_output(stderr_path, error.stderr)
        with stderr_path.open('a', encoding='utf-8') as stderr:
            stderr.write(f'\n{error}\n')
        timed_out = bool(getattr(error, 'timed_out', False))
        monitor_available = None
        if str(error).startswith(('process_memory_monitor_', 'decompiler_process_tree_status_unverifiable')):
            monitor_available = False
        return _base_result(raw, output_path, state='timeout' if timed_out else 'partial',
                            timed_out=timed_out, error=error, command=command,
                            binary_sha256=binary_sha256, hardfork=hardfork,
                            process_tree_rss_monitor_available=monitor_available)
    except OSError as error:
        stderr_path.write_text(f'{type(error).__name__}: {error}\n', encoding='utf-8')
        return _base_result(raw, output_path, state='unavailable', error=error,
                            command=command, binary_sha256=binary_sha256, hardfork=hardfork)

    version_stdout = version_result.stdout
    version_stderr = version_result.stderr
    if version_stdout is None:
        with stdout_path.open('rb') as stdout:
            version_stdout = stdout.read(4096).decode('utf-8', errors='replace')
    if version_stderr is None:
        with stderr_path.open('rb') as stderr:
            version_stderr = stderr.read(4096).decode('utf-8', errors='replace')
    version_text = (version_stdout or version_stderr or '').strip()
    tool_version = version_text.splitlines()[0][:300] if version_text else None
    if (version_result.returncode != 0 or not tool_version or
            not tool_version.lower().startswith('heimdall')):
        if version_result.stdout is not None:
            _write_process_output(stdout_path, version_result.stdout)
        if version_result.stderr is not None:
            _write_process_output(stderr_path, version_result.stderr)
        with stderr_path.open('a', encoding='utf-8') as stderr:
            stderr.write('\nBinary did not report a valid Heimdall version\n')
        return _base_result(raw, output_path, tool_version=tool_version, state='unavailable',
                            error='heimdall_version_unverified', command=command,
                            binary_sha256=binary_sha256, hardfork=hardfork)

    if _sha256(resolved_binary) != binary_sha256:
        return _base_result(raw, output_path, tool_version=tool_version, state='unavailable',
                            error='heimdall_binary_changed_during_startup', command=command,
                            binary_sha256=binary_sha256, hardfork=hardfork)

    arguments = [
        resolved_binary, 'decompile', None, '--skip-resolving', '--include-sol',
        '--output', str(output_path), '--name', 'decompiled', '--hardfork', hardfork,
        '--timeout', str(max(1, int(timeout_seconds * 1000))), '--quiet',
    ]
    state = 'failed'
    error = None
    exit_code = None
    timed_out = False
    artifact_inventory = None
    monitor_available = None
    try:
        with tempfile.TemporaryDirectory(prefix='heimdall-bytecode-') as temporary:
            input_path = Path(temporary) / 'runtime.hex'
            input_path.write_text('0x' + raw.hex(), encoding='ascii')
            arguments[2] = str(input_path)
            with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
                result = _run_process(
                    arguments, stdout=stdout, stderr=stderr,
                    timeout=timeout_seconds, artifact_dir=output_path,
                )
        exit_code = result.returncode
        try:
            final_binary_sha256 = _sha256(resolved_binary)
        except OSError:
            state = 'unavailable'
            error = 'heimdall_binary_unreadable_after_execution'
        else:
            if final_binary_sha256 != binary_sha256:
                state = 'unavailable'
                error = 'heimdall_binary_changed_during_execution'
            elif exit_code != 0:
                state = 'failed'
                error = f'heimdall_exit_code_{exit_code}'
            else:
                pseudocode_paths = set()
                artifact_inventory = _artifact_inventory(
                    output_path, pseudocode_paths=pseudocode_paths,
                )
                artifacts, overflow, omitted, artifact_total_bytes = artifact_inventory
                has_pseudocode = bool(pseudocode_paths)
                if overflow:
                    state = 'partial'
                    error = 'artifact_inventory_truncated'
                elif artifact_total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                    state = 'partial'
                    error = 'artifact_total_bytes_limit_exceeded'
                elif omitted:
                    state = 'partial'
                    error = 'artifact_inventory_incomplete'
                else:
                    state = 'completed' if has_pseudocode else 'partial'
                    if not has_pseudocode:
                        error = 'heimdall_completed_without_pseudocode_artifact'
    except ArtifactBudgetExceeded as exception:
        timed_out = bool(getattr(exception, 'timed_out', False))
        state = 'timeout' if timed_out else 'partial'
        error = str(exception)
        if error.startswith(('process_memory_monitor_', 'decompiler_process_tree_status_unverifiable')):
            monitor_available = False
    except subprocess.TimeoutExpired:
        state = 'timeout'
        timed_out = True
        error = f'heimdall_timeout_after_{timeout_seconds}_seconds'
    except OSError as exception:
        state = 'failed'
        error = f'{type(exception).__name__}: {exception}'

    return _base_result(raw, output_path, tool_version=tool_version, state=state,
                        error=error, exit_code=exit_code, timed_out=timed_out,
                        command=command, binary_sha256=binary_sha256, hardfork=hardfork,
                        artifact_inventory=artifact_inventory,
                        process_tree_rss_monitor_available=monitor_available)
