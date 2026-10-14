#!/usr/bin/env python3
"""Recount author-report evidence from the frozen CSV and explicit scope."""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'Commit-ID(If labelled with fixed or merged)'

def recount():
    source = ROOT / 'manifests/reports_source.csv'
    scope = ROOT / 'manifests/report_scope.json'
    excluded = {(r['repository'].lower(), int(r['issue_number'])) for r in json.loads(scope.read_text())['excluded_reports']}
    with source.open(encoding='utf-8-sig', newline='') as stream:
        raw = list(csv.DictReader(stream))
    records, seen = [], set()
    for row in raw:
        identity = (row['Rep'].strip().lower(), int(row['issue-ID']))
        if identity in seen:
            raise ValueError(f'Duplicate report: {identity}')
        seen.add(identity)
        if identity in excluded:
            continue
        pr = bool(row['PR-ID(s)'].strip() or row['PR-LINK(s)'].strip())
        value = row[COMMIT].strip()
        commits = re.findall(r'(?<![0-9a-z])[0-9a-f]{7,40}(?![0-9a-z])', value, re.I)
        merged = bool(re.search(r'\bmerged\b', value, re.I))
        marker = bool(re.search(r'\bfixed\b', value, re.I))
        if value and not (commits or merged or marker):
            raise ValueError(f'Unrecognized commit field for {identity}')
        confirmed = row['Confirmed(y/s)'].strip().lower() == 'y'
        rejected = row['Rejected(y/n)'].strip().lower() == 'y'
        activity = 'pr_and_commit_or_merged' if pr and (commits or merged) else 'pr_only' if pr else 'commit_or_merged_without_pr' if commits or merged else 'fixed_marker_only' if marker else 'no_recorded_repair'
        state = 'conflicting_flags' if confirmed and rejected else 'confirmed' if confirmed else 'known_rejected' if rejected else 'not_recorded'
        records.append({'repository':row['Rep'],'issue_number':identity[1], 'issue_url':row['ISSUE-LINK'], 'confirmed':confirmed,'known_rejected':rejected,'has_pr':pr,'recorded_commit':bool(commits),'explicit_merged_marker':merged,'fixed':bool(pr or commits or merged or marker),'activity':activity,'state':state})
    counts = {'raw_reports':len(raw),'reports':len(records),'repositories':len({r['repository'].lower() for r in records}),'excluded_reports':len(raw)-len(records)}
    for field in ('confirmed','known_rejected','has_pr','recorded_commit','explicit_merged_marker','fixed'):
        counts[field] = sum(r[field] for r in records)
    counts['unresolved_confirmation'] = sum(not r['confirmed'] and not r['known_rejected'] for r in records)
    counts['fixed_with_commit_or_merged'] = sum(r['fixed'] and (r['recorded_commit'] or r['explicit_merged_marker']) for r in records)
    counts['fixed_without_commit_or_merged'] = counts['fixed']-counts['fixed_with_commit_or_merged']
    counts['no_recorded_repair'] = sum(not r['fixed'] for r in records)
    counts['commit_without_pr'] = sum(r['recorded_commit'] and not r['has_pr'] for r in records)
    cross = {}
    for r in records:
        cross.setdefault(r['activity'],{})[r['state']] = cross.setdefault(r['activity'],{}).get(r['state'],0)+1
    expected={'raw_reports':65,'reports':64,'repositories':61,'excluded_reports':1,'confirmed':24,'known_rejected':14,'unresolved_confirmation':26,'has_pr':13,'recorded_commit':17,'explicit_merged_marker':0,'fixed':19,'fixed_with_commit_or_merged':17,'fixed_without_commit_or_merged':2,'no_recorded_repair':45,'commit_without_pr':6}
    if counts != expected:
        raise ValueError(f'Counts differ: {counts}')
    return {'schema':'threadlocal-report-recount-1','inputs':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in (source,scope)},'definition':'One repository/issue per report. Fixed includes any recorded PR, commit, or Fixed/Merged marker; PRs are counted irrespective of merge status. Confirmation is an independent CSV flag.','counts':counts,'cross_table':cross,'reports':records}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Compare with the checked-in report_counts.json snapshot.')
    parser.add_argument('--output',type=Path,help='Write JSON to a separate output file.')
    args=parser.parse_args()
    result=recount()
    if args.check:
        expected=json.loads((ROOT/'results/report_counts.json').read_text(encoding='utf-8'))
        if result!=expected:
            raise SystemExit('Report snapshot differs')
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(result['counts'],indent=2))

if __name__=='__main__':
    main()
