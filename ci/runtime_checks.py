#!/usr/bin/env python3
"""Runtime checks used by the pipeline (standard library only).

Usage:
  runtime_checks.py targets-up <prometheus-targets.json>
  runtime_checks.py prometheus <reports-dir>
  runtime_checks.py trivy-operator <reports-dir>

Exit code 1 means "risk found" (the stage becomes UNSTABLE, the build continues).
"""
import json
import os
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


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'targets-up':
        sys.exit(targets_up(sys.argv[2]))
    if cmd == 'prometheus':
        sys.exit(prometheus(sys.argv[2]))
    if cmd == 'trivy-operator':
        sys.exit(trivy_operator(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
