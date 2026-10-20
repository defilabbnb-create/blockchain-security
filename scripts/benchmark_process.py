"""Bounded benchmark children; sampled group RSS is not total unified memory."""
import os
import signal
import subprocess
import time


def sample_group_rss_kib(pgid):
    try:
        out = subprocess.run(
            ['ps', '-Ao', 'pid=,ppid=,rss=,pgid='], capture_output=True,
            text=True, timeout=2, check=True,
        )
    except (subprocess.SubprocessError, OSError) as error:
        return {'samplingError': type(error).__name__}
    rows = []
    for line in out.stdout.splitlines():
        try:
            _, _, rss, group = map(int, line.split())
        except ValueError:
            continue
        if group == pgid:
            rows.append(rss)
    return {'rssKiB': sum(rows), 'maxProcessRssKiB': max(rows, default=0),
            'processCount': len(rows)}


def run_analyzer(command, cwd, env, folder, timeout, sampler=sample_group_rss_kib):
    started = time.monotonic()
    process = None
    metrics = {'exitCode': None, 'rssSamples': 0, 'rssSampleErrors': 0,
               'rssEmptySamples': 0, 'peakGroupRssMiB': None,
               'peakProcessRssMiB': None}
    try:
        with (folder / 'stdout.json').open('w', encoding='utf-8') as stdout, \
                (folder / 'stderr.log').open('w', encoding='utf-8') as stderr:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            while process.poll() is None:
                if time.monotonic() - started >= timeout:
                    metrics['error'] = 'analyzer_timeout'
                    break
                sample = sampler(process.pid)
                metrics['rssSamples'] += 1
                if 'samplingError' in sample:
                    metrics['rssSampleErrors'] += 1
                elif sample.get('processCount', 0) > 0:
                    for field, key in (('peakGroupRssMiB', 'rssKiB'),
                                       ('peakProcessRssMiB', 'maxProcessRssKiB')):
                        peak = metrics[field]
                        value = sample[key] / 1024
                        metrics[field] = value if peak is None else max(peak, value)
                else:
                    metrics['rssEmptySamples'] += 1
                time.sleep(.1)
    except Exception as error:
        metrics['error'] = f'{type(error).__name__}: {str(error)[:500]}'
    finally:
        if process is not None:
            try:
                # The leader may have exited while descendants are still alive.
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                process.wait()
                metrics['exitCode'] = process.returncode
        metrics['wallSeconds'] = time.monotonic() - started
    return metrics
