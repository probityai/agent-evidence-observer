"""Observe the entire selected native child and enforce its external wall guard.

No inference is executed in this observer. Actual native child originals and
its terminal remain unchanged; external terminal/timing/pins are separately
retained and bound by the final manifest. Reconstruction follows child reap.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Any

ROOT = Path(__file__).parent
selection_spec = importlib.util.spec_from_file_location("selected_tool_argument_entry", ROOT / "task_matrix.py")
if selection_spec is None or selection_spec.loader is None:
    raise ValueError("selected entry cannot load")
selection = importlib.util.module_from_spec(selection_spec)
exec(compile((ROOT / "task_matrix.py").read_bytes(), str(ROOT / "task_matrix.py"), "exec"), selection.__dict__)
PROTOCOL_COMMIT, PROTOCOL_SHA256 = selection.PROTOCOL_COMMIT, selection.PROTOCOL_SHA256
active_protocol = selection.active_protocol
active_protocol()
from evidence_io import digest, now, read_regular, require, strict_json, write
from native_runner import finish, verify_runtime_site
from reusable_runtime import sanitized_environment


def cpu_preflight() -> None:
    """Refuse unsupported retained native CPU instructions before a call."""
    rows = Path('/proc/cpuinfo').read_text().splitlines()
    flagsets = [set(row.partition(':')[2].split()) for row in rows if row.startswith('flags')]
    required = {'avx','avx2','fma','f16c','sse3','ssse3'}
    # Linux spells SSE3 as pni on supported x86 kernels.
    require(bool(flagsets) and all(required <= (flags | ({'sse3'} if 'pni' in flags else set())) for flags in flagsets), 'selected retained runtime CPU instructions unavailable')


def reap(process: subprocess.Popen, started: float) -> tuple[int, Any, bool]:
    """Wait once for exact child resources with595sTERM and600sKILL boundary."""
    terminated = False
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return process.returncode, usage, terminated
        elapsed = time.monotonic() - started
        if elapsed >= 595 and not terminated:
            signal_group(process.pid, signal.SIGTERM)
            terminated = True
        if elapsed >= 600:
            signal_group(process.pid, signal.SIGKILL)
        time.sleep(0.01)


def signal_group(pid: int, selected_signal: int) -> None:
    """Allow an exited child to be reaped after a signal delivery race."""
    try:
        os.killpg(pid, selected_signal)
    except ProcessLookupError:
        pass


def observe(packet: Path, prepared: Path, repository: Path, output: Path, protocol: dict, runtime_python: Path) -> dict:
    """Retain original process streams and wait4 totals, then reconstruct evidence."""
    cpu_preflight()
    installation = strict_json(read_regular(prepared/'installation.json'))
    require(Path(installation['interpreter']).resolve() == runtime_python.resolve(), 'prepared interpreter differs from externally selected runtime Python')
    site = runtime_python.absolute().parent.parent / 'lib' / ('python' + protocol['runtimeReuse']['abi']['python']) / 'site-packages'
    require(Path(installation['sitePackages']).resolve() == site.resolve(), 'prepared site differs from externally selected virtual environment')
    verify_runtime_site(prepared, protocol, installation, site)
    output.mkdir(parents=True, exist_ok=False)
    command = [str(runtime_python.absolute()),'-I','-B',str(ROOT/'task_matrix.py'),str(packet),'--prepared',str(prepared),'--repository',str(repository),'--protocol-commit',PROTOCOL_COMMIT]
    started = time.monotonic()
    with (output/'native-stdout.json').open('xb') as stdout, (output/'native-stderr.txt').open('xb') as stderr:
        process = subprocess.Popen(command, env=sanitized_environment(), stdout=stdout, stderr=stderr, start_new_session=True)
        code, usage, terminated = reap(process, started)
    elapsed_ns = int((time.monotonic()-started)*1000000000)
    original = strict_json(read_regular(packet/'inference-terminal.json')) if (packet/'inference-terminal.json').exists() else {'status':'error'}
    terminal = {'status':'complete' if code==0 and original['status']=='complete' and not terminated else 'error','finishedAt':now(),'elapsed_ns':elapsed_ns,'process_cpu_ns':int((usage.ru_utime+usage.ru_stime)*1000000000),'process_maxrss_kib':usage.ru_maxrss,'returnCode':code,'wallGuardTerminated':terminated,'measurement':'external Linux wait4 selected native child; inference-terminal remains original'}
    write(output/'host-process.json',dict(terminal,command=command))
    try:
        result = finish(packet,protocol,PROTOCOL_COMMIT,PROTOCOL_SHA256,terminal)
    except (ValueError, KeyError, OSError) as error:
        write(output/'reconstruction-refusal.json',{'publicationDecision':'hold-incomplete-or-resource-evidence','planned':128,'returnedPopulationEstablished':False,'error':str(error),'modelCallsRetried':0})
        raise
    write(output/'reconstructed-report.json',result)
    return result


def verify_execution_selection(repository: Path, selected_file: Path, selected_hash: str) -> None:
    """Bind the commit-bearing entry to an externally selected reviewed source."""
    raw = read_regular(selected_file)
    require(digest(raw) == selected_hash, 'externally selected execution contract changed')
    contract = strict_json(raw)
    require(contract['protocolCommit'] == PROTOCOL_COMMIT and contract['protocolSHA256'] == PROTOCOL_SHA256, 'execution contract differs from prospective registration')
    entry = read_regular(ROOT/'task_matrix.py')
    require(digest(entry) == contract['taskMatrixSHA256'], 'execution entry differs from separately selected source')
    registered = subprocess.run(['git','show',contract['sourceCommit']+':'+contract['profilePath']+'/task_matrix.py'],cwd=repository,capture_output=True,check=True,timeout=10).stdout
    require(registered == entry, 'execution entry differs from reviewed Git object')


def main() -> None:
    """Launch only the published prospective source with selected preparation."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packet',type=Path);parser.add_argument('prepared',type=Path);parser.add_argument('repository',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--runtime-python',type=Path,required=True)
    parser.add_argument('--execution-selection',type=Path,required=True)
    parser.add_argument('--execution-selection-sha256',required=True)
    args=parser.parse_args()
    protocol=active_protocol()
    require(len(PROTOCOL_COMMIT)==40,'inference requires published prospective registration')
    verify_execution_selection(args.repository.resolve(),args.execution_selection,args.execution_selection_sha256)
    result=observe(args.packet.resolve(),args.prepared.resolve(),args.repository.resolve(),args.output.resolve(),protocol,args.runtime_python)
    raise SystemExit(0 if result['publicationDecision']=='publish-scoped-report' else 1)


if __name__=='__main__':
    main()
