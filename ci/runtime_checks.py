#!/usr/bin/env python3
"""Runtime checks used by the pipeline (standard library only).

Usage:
  runtime_checks.py targets-up <prometheus-targets.json>
  runtime_checks.py prometheus <reports-dir>
  runtime_checks.py trivy-operator <reports-dir>
  runtime_checks.py kubescape <kubescape.json> <min-compliance-percent>
  runtime_checks.py lynis <lynis-report.dat> <min-hardening-index>
  runtime_checks.py falco <falco-log.txt> <pod-name>

Exit code 1 means "risk found" (the stage becomes UNSTABLE, the build continues).
"""
import json
import os
import re
import sys


def load(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def targets_up(path):
    data = load(path) or {}
    targets = data.get('data', {}).get('activeTargets', [])
    down = [t for t in targets if t.get('health') != 'up']
    print(f'Prometheus targets: {len(targets) - len(down)}/{len(targets)} up')
    for t in down:
        print('  DOWN:', t.get('scrapePool'), t.get('scrapeUrl'))
    return 1 if (down or not targets) else 0


def prometheus(rep):
    rc = targets_up(os.path.join(rep, 'prometheus-targets.json'))
    alerts = (load(os.path.join(rep, 'prometheus-alerts.json')) or {}).get('data', {}).get('alerts', [])
    firing = [a for a in alerts if a.get('state') == 'firing']
    print(f'Active alerts firing: {len(firing)}')
    graf = load(os.path.join(rep, 'grafana-health.json')) or {}
    ok = graf.get('database') == 'ok'
    print('Grafana health:', 'OK' if ok else 'KO')
    return 1 if (rc or not ok) else 0


def trivy_operator(rep):
    items = (load(os.path.join(rep, 'trivy-operator-vulns.json')) or {}).get('items', [])
    crit = high = 0
    for it in items:
        s = it.get('report', {}).get('summary', {})
        crit += int(s.get('criticalCount', 0))
        high += int(s.get('highCount', 0))
    print(f'Trivy Operator: {len(items)} reports, CRITICAL={crit}, HIGH={high}')
    return 1 if crit > 0 else 0


def _score(obj):
    """Compliance % from a Kubescape summary object (new or old format)."""
    if obj.get('complianceScore') is not None:
        return float(obj['complianceScore'])
    if obj.get('score') is not None:          # old format: risk score
        return 100.0 - float(obj['score'])
    return None


def kubescape(path, threshold):
    data = load(path)
    if not data:
        print('Kubescape: report missing or unreadable')
        return 1
    summary = data.get('summaryDetails', {}) or {}
    per_fw = {}
    for fw in summary.get('frameworks', []) or []:
        val = _score(fw)
        if val is not None:
            per_fw[fw.get('name', '?')] = val
    overall = _score(summary)
    if overall is None and per_fw:
        overall = sum(per_fw.values()) / len(per_fw)
    if overall is None:
        print('Kubescape: no compliance score found in report')
        return 1
    for name, val in per_fw.items():
        print(f'  {name}: {val:.1f}%')
    limit = float(threshold)
    print(f'Kubescape compliance: {overall:.1f}% (minimum {limit:.0f}%)')
    return 0 if overall >= limit else 1


def lynis(path, min_score):
    index = None
    warnings = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith('hardening_index='):
                    try:
                        index = int(line.split('=', 1)[1])
                    except ValueError:
                        pass
                elif line.startswith('warning[]='):
                    warnings.append(line.split('=', 1)[1])
    except OSError:
        print('Lynis: report file missing')
        return 1
    if index is None:
        print('Lynis: hardening index not found in report')
        return 1
    print(f'Lynis hardening index: {index}/100 (minimum {min_score})')
    print(f'Lynis warnings: {len(warnings)}')
    for w in warnings[:5]:
        print('  WARN:', w[:150])
    return 0 if index >= int(min_score) else 1


def falco(path, pod):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
    except OSError:
        print('Falco: log file missing')
        return 1
    alerts = [l for l in lines if pod and pod in l]
    if not alerts:   # fallback when pod metadata is not in the log lines
        alerts = [l for l in lines if re.search(r'shadow|pam\.conf|id_rsa|sensitive', l, re.I)]
    print(f'Falco: {len(alerts)} alert(s) detected for the simulated attack (pod {pod})')
    for l in alerts[:5]:
        print('  ', l[:200])
    return 0 if alerts else 1


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'targets-up':
        sys.exit(targets_up(sys.argv[2]))
    if cmd == 'prometheus':
        sys.exit(prometheus(sys.argv[2]))
    if cmd == 'trivy-operator':
        sys.exit(trivy_operator(sys.argv[2]))
    if cmd == 'kubescape':
        sys.exit(kubescape(sys.argv[2], sys.argv[3]))
    if cmd == 'lynis':
        sys.exit(lynis(sys.argv[2], sys.argv[3]))
    if cmd == 'falco':
        sys.exit(falco(sys.argv[2], sys.argv[3]))
    print(__doc__)
    sys.exit(2)
