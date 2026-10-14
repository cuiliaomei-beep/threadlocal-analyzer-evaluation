#!/usr/bin/env python3
"""Fetch pinned case sources, compile unchanged target classes, and analyze both revisions."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiment/gt'))
import _runtime as runtime

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def fetch(url, target, expected):
    request = urllib.request.Request(url, headers={'User-Agent':'threadlocal-reproduction/1.0'})
    with urllib.request.urlopen(request, timeout=60) as stream:
        data=stream.read()
    actual=hashlib.sha256(data).hexdigest()
    if actual!=expected:
        raise ValueError(f'Download hash mismatch for {url}: {actual}')
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(data)
    return {'url':url,'path':str(target.relative_to(ROOT)).replace('\\','/'),'sha256':actual,'bytes':len(data)}

def command(text, log, timeout):
    result=runtime.run_bash(runtime.shell_environment()+'; '+text,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,check=False)
    log.write_bytes(result.stdout)
    return {'exit_code':result.returncode,'log':str(log.relative_to(ROOT)).replace('\\','/')}

def one(case, side, output, dependency, args):
    folder=output/case['id']/side
    folder.mkdir(parents=True)
    revision=case['revisions'][side]
    record={'case':case['id'],'repository':case['repository'],'issue_number':case['issue_number'],'side':side,'revision':revision['commit'],'scope':case['scope']}
    try:
        source=folder/'source'/Path(case['source_path']).name
        record['source']=fetch(revision['source_url'],source,revision['source_sha256'])
        classes=folder/'classes'
        classes.mkdir()
        cp=' -classpath '+shlex.quote(runtime.bash_path(dependency)) if dependency else ''
        javac='"$JAVA_HOME/bin/javac" --release 17 -proc:none -g'+cp+' -d '+shlex.quote(runtime.bash_path(classes))+' '+shlex.quote(runtime.bash_path(source))
        record['compile']=command(javac,folder/'compile.log',120)
        if record['compile']['exit_code']:
            raise RuntimeError('Target compilation failed; inspect compile.log')
        jar=folder/'input.jar'
        package='"$JAVA_HOME/bin/jar" --create --file '+shlex.quote(runtime.bash_path(jar))+' -C '+shlex.quote(runtime.bash_path(classes))+' .'
        record['package']=command(package,folder/'package.log',30)
        if record['package']['exit_code']:
            raise RuntimeError('Target packaging failed; inspect package.log')
        with zipfile.ZipFile(jar) as archive:
            classnames=[n for n in archive.namelist() if n.endswith('.class')]
        record['input_jar']={'sha256':sha(jar),'classes':classnames}
        report=folder/'lifetl.json'
        analyze='"$JAVA_HOME/bin/java" -Xmx'+shlex.quote(args.heap)+' -jar '+shlex.quote(runtime.bash_path(args.tool))+' --jar '+shlex.quote(runtime.bash_path(jar))+' --out '+shlex.quote(runtime.bash_path(report))+' --timeout '+str(args.timeout)
        if dependency:
            analyze+=' --cp '+shlex.quote(runtime.bash_path(dependency))
        record['analysis']=command(analyze,folder/'analysis.log',args.timeout+30)
        if report.exists():
            data=json.loads(report.read_text(encoding='utf-8'))
            record['status']=data.get('status','ERROR')
            record['output_sha256']=sha(report)
            record['coverage']={k:data.get(k) for k in ('classes','methodsWithBody','bodyErrors','graphErrors','unresolvedInvokes','tlCount')}
            record['diagnostics']=data.get('warnings',[])
        else:
            record['status']='NO_OUTPUT'
    except Exception as exc:
        record['status']='ERROR'
        record['error']=str(exc)
    (folder/'record.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    return record

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',choices=['all','quickfix','redis','influx'],default='all')
    parser.add_argument('--jobs',type=int,default=2,choices=[1,2,3])
    parser.add_argument('--timeout',type=int,default=180)
    parser.add_argument('--heap',default='3g')
    parser.add_argument('--tool',type=Path,default=ROOT/'experiment/tldoctor2/target/tldoctor2.jar')
    parser.add_argument('--list',action='store_true',help='Print pinned inputs without downloading or running tools.')
    parser.add_argument('--check-reference',action='store_true',help='Compare stable diagnostic identities with results/case_diagnostics.json.')
    args=parser.parse_args()
    if args.timeout < 1 or not re.fullmatch(r'[1-9][0-9]*[mMgG]',args.heap):
        parser.error('Use a positive timeout and a heap such as 3g')
    inputs=ROOT/'manifests/case_studies.json'
    cases=json.loads(inputs.read_text(encoding='utf-8'))['cases']
    cases=[c for c in cases if args.case=='all' or c['id']==args.case]
    if args.list:
        print(json.dumps(cases,indent=2))
        return
    if not args.tool.is_file():
        parser.error('Build experiment/tldoctor2 with Maven first')
    output=ROOT/'experiment/out/case-audit'/datetime.now(timezone.utc).strftime('run-%Y%m%dT%H%M%S%fZ')
    output.mkdir(parents=True,exist_ok=False)
    dependencies={}
    for case in cases:
        if case['dependency']:
            dep=case['dependency']
            path=output/'dependencies'/dep['url'].rsplit('/',1)[1]
            fetch(dep['url'],path,dep['sha256'])
            dependencies[case['id']]=path
    records=[]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        tasks=[pool.submit(one,c,s,output,dependencies.get(c['id']),args) for c in cases for s in ('pre','post')]
        for future in as_completed(tasks):
            record=future.result()
            records.append(record)
            print(record['case'],record['side'],record['status'],flush=True)
    manifest={'schema':'threadlocal-reproduced-case-audit-1','input_manifest_sha256':sha(inputs),'tool_sha256':sha(args.tool),'configuration':{'workers':args.jobs,'heap':args.heap,'timeout':args.timeout,'compiler_release':17,'source_modified':False,'stubs_used':False,'input_scope':'target source and nested classes; dependency release jars resolve referenced classes'},'records':sorted(records,key=lambda r:(r['case'],r['side']))}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print('Outputs:',output)
    if any(r['status']!='OK' for r in records):
        raise SystemExit(1)
    if args.check_reference:
        reference=json.loads((ROOT/'results/case_diagnostics.json').read_text(encoding='utf-8'))['records']
        key=lambda r:(r['case'],r['side'])
        identity=lambda r:sorted((w.get('rule',''),w.get('tier',''),w.get('tl',''),w.get('method',''),str(w.get('line',''))) for w in r['diagnostics'])
        expected={key(r):identity(r) for r in reference if args.case=='all' or r['case']==args.case}
        actual={key(r):identity(r) for r in records}
        if expected!=actual:
            raise SystemExit('Diagnostic identities differ from the frozen case reference')
        print('Stable diagnostic identities match the frozen case reference.')

if __name__=='__main__':
    main()
