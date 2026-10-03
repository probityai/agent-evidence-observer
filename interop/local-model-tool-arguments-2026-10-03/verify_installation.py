"""Build and actually install the selected reader with disclosed synthetic controls.

All new calls/resources in these packets are simulated. The clean installed
consumer runs no model code, accesses no model provider, and installs no
framework dependencies. Source selection is a same-operator build receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).parent
spec=importlib.util.spec_from_file_location('selected_tool_entry',ROOT/'task_matrix.py')
if spec is None or spec.loader is None:raise ValueError('selected entry cannot load')
selection=importlib.util.module_from_spec(spec);exec(compile((ROOT / "task_matrix.py").read_bytes(), str(ROOT / "task_matrix.py"), "exec"), selection.__dict__)
protocol=selection.active_protocol()
from build_installed_reader import build, WHEEL
from evidence_io import digest, encode, require, write
from reusable_runtime import sanitized_environment
from synthetic_packet import build as synthetic


def run(command: list[str], directory: Path, env: dict[str,str]) -> dict:
    """Retain literal streams and exit for one bounded installed invocation."""
    start=time.monotonic_ns()
    value=subprocess.run(command,env=env,cwd=directory,capture_output=True,timeout=180,check=False)
    return {'code':value.returncode,'stdout':value.stdout,'stderr':value.stderr,'elapsed_ns':time.monotonic_ns()-start}


def selected_contract(repository: Path) -> dict:
    """Select exact current Git blobs for an explicitly same-operator build."""
    commit=subprocess.run(['git','rev-parse','HEAD'],cwd=repository,check=True,capture_output=True,text=True).stdout.strip()
    names=list(protocol['sourceClosure'])+['task_matrix.py','protocol.json','LICENSE',protocol['compiler']['path'],protocol['compiler']['licensePath']]+['grammars/'+mode+'.gbnf' for mode in protocol['modes']]
    return {'sourceCommit':commit,'profilePath':ROOT.relative_to(repository).as_posix(),'files':{name:digest((ROOT/name).read_bytes()) for name in names},'scope':'sameoperator Git/source selection; no independent witness or adoption'}


def retain_result(output: Path, name: str, value: dict) -> None:
    """Save untouched stdout/stderr and a compact bounded process receipt."""
    write(output/(name+'.stdout'),value['stdout']);write(output/(name+'.stderr'),value['stderr'])
    write(output/(name+'.json'),{'code':value['code'],'elapsed_ns':value['elapsed_ns'],'stdoutSHA256':digest(value['stdout']),'stderrSHA256':digest(value['stderr'])})


def consume(repository: Path, output: Path) -> dict:
    """Run clean install, literal repeats, quality holds and actual hostile launch."""
    output.mkdir(parents=True,exist_ok=False)
    contract=selected_contract(repository);write(output/'source-contract.json',contract)
    build_receipt=build(repository,output/'wheel',contract)
    environment=output/'environment';base=sanitized_environment()
    subprocess.run([sys.executable,'-I','-B','-m','venv',str(environment)],check=True,env=base,timeout=180)
    python=environment/'bin/python';console=environment/'lib/python3.12/site-packages/probity_tool_arguments_reader/task_matrix.py'
    install=run([str(python),'-I','-B','-m','pip','install','--no-index','--no-deps','--no-cache-dir','--no-compile',str(output/'wheel'/WHEEL)],output,base)
    retain_result(output,'installation',install);require(install['code']==0,'clean reader installation failed')
    packages=run([str(python),'-I','-c','import importlib.metadata,json; print(json.dumps(sorted((d.metadata["Name"],d.version) for d in importlib.metadata.distributions())))'],output,base)
    retain_result(output,'installed-packages',packages)
    require(json.loads(packages['stdout'])==[['pip',json.loads(packages['stdout'])[0][1]],['probity-tool-arguments-reader','0.1.0']],'model-free reader installed population differs')
    archive=repository/'interop/local-model-vocabulary-2026-10-02/retained/native-37094901561.zip'
    expected=synthetic(output/'correct',archive,protocol,selection.PROTOCOL_COMMIT,selection.PROTOCOL_SHA256)
    incorrect=synthetic(output/'incorrect',archive,protocol,selection.PROTOCOL_COMMIT,selection.PROTOCOL_SHA256,incorrect=True)
    stopped=synthetic(output/'stopped',archive,protocol,selection.PROTOCOL_COMMIT,selection.PROTOCOL_SHA256,stop_after=1)
    command=[str(python),'-I','-B',str(console),str(output/'correct'),'--verify','--pins-file',str(output/'correct/consumer-pins.json')]
    first=run(command,output,base);repeat=run(command,output,base)
    retain_result(output,'correct',first);retain_result(output,'repeat',repeat)
    require(first['code']==repeat['code']==0 and first['stdout']==repeat['stdout'] and first['stderr']==repeat['stderr'],'installed reader literal repeat differs')
    require(json.loads(first['stdout'])==expected,'installed reader differs from selected synthetic reconstruction')
    for name,code in [('incorrect',1),('stopped',1)]:
        value=run([str(python),'-I','-B',str(console),str(output/name),'--verify','--pins-file',str(output/name/'consumer-pins.json')],output,base);retain_result(output,name,value);require(value['code']==code,'installed strict hold differs')
    forged=output/'changed-original';shutil.copytree(output/'correct',forged)
    returned=next((forged/'calls').glob('*-returned.json'));returned.write_bytes(b'{}')
    mutation=run([str(python),'-I','-B',str(console),str(forged),'--verify','--pins-file',str(output/'correct/consumer-pins.json')],output,base);retain_result(output,'changed-original',mutation)
    require(mutation['code']==2 and b'original retained bytes changed' in mutation['stderr'],'installed changed-original refusal differs')
    hostile=output/'hostile';hostile.mkdir();marker=output/'hostile-marker'
    hook='from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\nraise RuntimeError("hostile injected code")\n'
    (hostile/'sitecustomize.py').write_text(hook);(hostile/'probity_tool_arguments_reader.py').write_text(hook)
    polluted=dict(base,PYTHONPATH=str(hostile),PYTHONHOME=str(hostile),PYTHONUSERBASE=str(hostile),HOME=str(hostile))
    hostile_result=run(command,hostile,polluted);retain_result(output,'hostile-launch',hostile_result)
    require(not marker.exists() and hostile_result['code']==0 and hostile_result['stdout']==first['stdout'] and hostile_result['stderr']==first['stderr'],'actual hostile installed launch differs')
    boundary=run([str(python),'-I','-B',str(console),str(output/'correct'),'--protocol-commit',selection.PROTOCOL_COMMIT,'--prepared','unused','--repository',str(repository)],output,base)
    retain_result(output,'installed-native-denial',boundary)
    require(boundary['code']==2 and b'installed reader does not dispatch model inference' in boundary['stderr'],'installed direct source allowed native dispatch')
    verify_installed_native_boundaries(python, environment, output, repository, base)
    cache_control=installed_cache_control(python,console,command,output,base)
    receipt={'sourceContractSHA256':digest(encode(contract)),'wheel':build_receipt,'cleanInstalled':True,'literalRepeat':True,'strictIncorrectExit':1,'stopped':stopped['population'],'changedOriginalRefused':True,'hostileLaunchRefusedInjection':True,'installedDirectNativeDenied':True,'installedSourceCacheRefused':cache_control,'mode':'synthetic-control','newModelCalls':0,'newProviderCalls':0,'dependencyTransfers':0,'sameOperator':True,'scope':'actual clean model-free installed replay of disclosed synthetic controls using selected prior native custody bytes; no new model score/acceptance/adoption/independent inference custody'}
    write(output/'receipt.json',receipt);return receipt


def verify_installed_native_boundaries(python: Path, environment: Path, output: Path, repository: Path, env: dict[str,str]) -> None:
    """Preserve explicit native denials through normal console and module routes."""
    suffix=[str(output/'correct'),'--protocol-commit',selection.PROTOCOL_COMMIT,'--prepared','unused','--repository',str(repository)]
    routes={'console':[str(environment/'bin/probity-tool-arguments-reader')], 'module':['-m','probity_tool_arguments_reader.task_matrix']}
    for name, route in routes.items():
        value=run([str(python),'-I','-B']+route+suffix,output,env)
        retain_result(output,'installed-'+name+'-native-denial',value)
        require(value['code']==2 and b'installed reader does not dispatch model inference' in value['stderr'],'installed '+name+' allowed native dispatch')


def installed_cache_control(python: Path, console: Path, command: list[str], output: Path, env: dict[str,str]) -> dict:
    """Refuse timestamp-valid stale bytecode while selected source stays exact."""
    import os
    import py_compile
    source=console.with_name('schema_contract.py');original=source.read_bytes();metadata=source.stat()
    stale=b'raise RuntimeError("stale compiled helper executed")\n'
    source.write_bytes(stale+b' '*(len(original)-len(stale)));os.utime(source,ns=(metadata.st_atime_ns,metadata.st_mtime_ns))
    cache=Path(py_compile.compile(str(source),doraise=True))
    source.write_bytes(original);os.utime(source,ns=(metadata.st_atime_ns,metadata.st_mtime_ns))
    require(source.read_bytes()==original,'cache control changed selected source')
    value=run(command,output,env);retain_result(output,'installed-cache-refusal',value)
    require(value['code']==2 and b'selected source cache population must be empty' in value['stderr'] and b'stale compiled helper executed' not in value['stderr'],'installed cached helper selected executable code')
    return {'sourceSHA256':digest(original),'cachedBytes':cache.stat().st_size,'cacheSHA256':digest(cache.read_bytes()),'refusedBeforeHelperImport':True,'selectedSourceUnchanged':True,'modelCalls':0}


def main() -> None:
    """Run the bounded offline installed controls against this exact Git checkout."""
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('repository',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
    print(json.dumps(consume(args.repository.resolve(),args.output.resolve()),sort_keys=True))


if __name__=='__main__':main()
