"""Actually install a frozen reader and preserve actual native quality decisions.

The caller separately selects source-contract and artifact pins. Producer
self-selection in the workflow is explicitly same-operator. No model framework
or inference executes in this consumer. Interpreter and host ancestors trusted.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('selected_tool_entry',ROOT/'task_matrix.py')
if spec is None or spec.loader is None:raise ValueError('selected entry cannot load')
selection=importlib.util.module_from_spec(spec);exec(compile((ROOT / "task_matrix.py").read_bytes(), str(ROOT / "task_matrix.py"), "exec"), selection.__dict__)
selection.active_protocol()
from build_installed_reader import build,WHEEL
from evidence_io import digest,read_regular,require,strict_json,write
from reusable_runtime import sanitized_environment
from verify_installation import retain_result,run


def consume(repository: Path, packet: Path, pins: Path, output: Path, contract: dict) -> dict:
    """Install once, preserve both gates and prove raw-repeat/original refusal."""
    output.mkdir(parents=True,exist_ok=False)
    wheel=build(repository,output/'wheel',contract)
    selected_pins=read_regular(pins);write(output/'selected-pins.json',selected_pins)
    environment=output/'environment';base=sanitized_environment()
    subprocess.run([sys.executable,'-I','-B','-m','venv',str(environment)],check=True,env=base,timeout=180)
    python=environment/'bin/python';console=environment/'lib/python3.12/site-packages/probity_tool_arguments_reader/task_matrix.py'
    install=run([str(python),'-I','-B','-m','pip','install','--no-index','--no-deps','--no-cache-dir','--no-compile',str(output/'wheel'/WHEEL)],output,base)
    retain_result(output,'installation',install);require(install['code']==0,'actual installed reader installation failed')
    command=[str(python),'-I','-B',str(console),str(packet),'--verify','--pins-file',str(output/'selected-pins.json')]
    strict=run(command,output,base);repeat=run(command,output,base);evidence=run(command+['--evidence-only'],output,base)
    for name,result in [('strict',strict),('repeat',repeat),('evidence-only',evidence)]:retain_result(output,name,result)
    require(strict['code'] in {0,1} and strict['code']==repeat['code'] and strict['stdout']==repeat['stdout'] and strict['stderr']==repeat['stderr'],'actual installed literal repeat differs')
    report=strict_json(strict['stdout']);require(strict_json(evidence['stdout'])==report,'actual installed evidence/quality report differs')
    require(evidence['code']==(0 if report['publicationDecision']=='publish-scoped-report' else 1),'actual installed evidence exit differs')
    require(strict['code']==(0 if report['qualityDecision']=='admit-scoped-quality' else 1),'actual installed strict exit differs')
    forged=output/'changed-original';shutil.copytree(packet,forged)
    returned=next((forged/'calls').glob('*-returned.json'),None)
    require(returned is not None,'actual mutation control requires a retained response')
    returned.write_bytes(b'{}')
    corruption=run([str(python),'-I','-B',str(console),str(forged),'--verify','--pins-file',str(output/'selected-pins.json')],output,base);retain_result(output,'changed-original',corruption)
    require(corruption['code']==2 and b'original retained bytes changed' in corruption['stderr'],'actual installed changed-original refusal differs')
    receipt={'wheel':wheel,'strictExit':strict['code'],'evidenceExit':evidence['code'],'literalRepeat':True,'selectedPinsSHA256':digest(selected_pins),'changedOriginalRefused':True,'population':report['population'],'qualityDecision':report['qualityDecision'],'executionMode':report['executionMode'],'modelCalls':0,'providerCalls':0,'sameOperatorWorkflowPins':True,'scope':'clean installed model-free actual byte replay; producer pins inworkflow are sameoperator; no outside acceptance/adoption/independent inference or effect custody'}
    write(output/'receipt.json',receipt);return receipt


def main() -> None:
    """Require an external source-contract digest and separate artifact pins."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository',type=Path);parser.add_argument('packet',type=Path);parser.add_argument('pins',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--reader-contract',type=Path,required=True);parser.add_argument('--reader-contract-sha256',required=True)
    args=parser.parse_args();raw=read_regular(args.reader_contract)
    require(digest(raw)==args.reader_contract_sha256,'externally selected reader contract changed')
    print(json.dumps(consume(args.repository.resolve(),args.packet.resolve(),args.pins.resolve(),args.output.resolve(),strict_json(raw)),sort_keys=True))


if __name__=='__main__':main()
