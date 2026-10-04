#!/usr/bin/env python3
"""Builds the DevSecOps report from the files in reports/ (standard library only).

Outputs: devsecops-report.html (+ report.css), devsecops-report-email.html (inline CSS),
summary-line.txt, devsecops-summary.txt
"""
import glob
import html
import json
import os
import re
import xml.etree.ElementTree as ET

R = os.environ.get('REPORTS_DIR', 'reports')

CSS = """
body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#1f2937}
h1{color:#0f2a5c}h2{color:#1d4ed8;border-bottom:2px solid #e5e7eb;padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin:10px 0 20px}
th,td{border:1px solid #d1d5db;padding:6px 10px;text-align:left;font-size:14px}
th{background:#f3f4f6}
.ok{color:#047857;font-weight:bold}.warn{color:#b45309;font-weight:bold}.bad{color:#b91c1c;font-weight:bold}
.cards{display:flex;flex-wrap:wrap;gap:10px}.card{border:1px solid #d1d5db;border-radius:8px;padding:10px 14px;min-width:150px}
.card b{display:block;font-size:20px}
"""


def read(name, default=''):
    try:
        with open(os.path.join(R, name), encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        return default


def jload(name):
    try:
        return json.loads(read(name) or 'null')
    except ValueError:
        return None


def meta():
    m = {}
    for line in read('meta.txt').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            m[k.strip()] = v.strip()
    return m


def stages():
    out = []
    for line in read('stages.txt').splitlines():
        p = line.split('|')
        if len(p) == 3:
            out.append((p[0], p[1], int(p[2] or 0)))
    return out


def tests():
    total = failed = 0
    for f in glob.glob('target/surefire-reports/TEST-*.xml'):
        try:
            root = ET.parse(f).getroot()
            total += int(root.get('tests', 0))
            failed += int(root.get('failures', 0)) + int(root.get('errors', 0))
        except (ET.ParseError, ValueError):
            pass
    return total, failed


def coverage():
    try:
        root = ET.parse('target/site/jacoco/jacoco.xml').getroot()
        for c in root.findall('counter'):
            if c.get('type') == 'LINE':
                m, cv = int(c.get('missed')), int(c.get('covered'))
                return round(100 * cv / (m + cv)) if (m + cv) else 0
    except (OSError, ET.ParseError, ValueError):
        pass
    return None


def trivy_vulns(name):
    j = jload(name)
    if not j:
        return None
    n = {'CRITICAL': 0, 'HIGH': 0}
    for res in j.get('Results', []) or []:
        for v in res.get('Vulnerabilities', []) or []:
            if v.get('Severity') in n:
                n[v['Severity']] += 1
    return n


def trivy_iac(name):
    j = jload(name)
    if not j:
        return None
    return sum(len(r.get('Misconfigurations', []) or []) for r in j.get('Results', []) or [])


def zap():
    j = jload('zap-report.json')
    if not j:
        return None
    n = {'H': 0, 'M': 0, 'L': 0}
    for site in j.get('site', []) or []:
        for a in site.get('alerts', []) or []:
            code = str(a.get('riskcode', ''))
            key = {'3': 'H', '2': 'M', '1': 'L'}.get(code)
            if key:
                n[key] += 1
    return n


def gauntlt():
    t = read('gauntlt.txt')
    m = re.search(r'(\d+) scenarios?', t)
    if not m:
        return None
    total = int(m.group(1))
    p = re.search(r'(\d+) passed', t)
    return (int(p.group(1)) if p else 0), total


def kubescape():
    j = jload('kubescape.json')
    try:
        return round(float(j['summaryDetails']['complianceScore']))
    except (TypeError, KeyError, ValueError):
        return None


def lynis():
    t = read('lynis-hardening.txt').strip()
    return int(t) if t.isdigit() else None


def build():
    m = meta()
    tt, tf = tests()
    cov = coverage()
    sca = trivy_vulns('trivy-sca.json')
    img = trivy_vulns('trivy-image.json')
    iac = trivy_iac('trivy-iac.json')
    z = zap()
    g = gauntlt()
    ks = kubescape()
    ly = lynis()
    qg = m.get('qualityGate', 'N/A')

    def cnt(d):
        return 'n/a' if d is None else d['CRITICAL'] + d['HIGH']

    cards = [
        ('Quality Gate', qg),
        ('Tests', f'{tt - tf}/{tt}'),
        ('Coverage', 'n/a' if cov is None else f'{cov}%'),
        ('SCA (HIGH+CRIT)', cnt(sca)),
        ('Image (HIGH+CRIT)', cnt(img)),
        ('IaC findings', 'n/a' if iac is None else iac),
        ('ZAP H/M/L', 'n/a' if z is None else f"{z['H']}/{z['M']}/{z['L']}"),
        ('Gauntlt', 'n/a' if g is None else f'{g[0]}/{g[1]}'),
        ('Kubescape', 'n/a' if ks is None else f'{ks}%'),
        ('Lynis index', 'n/a' if ly is None else ly),
    ]

    summary = ' | '.join([
        f'QG {qg}', f'Tests {tt - tf}/{tt}',
        f'Cov {"n/a" if cov is None else str(cov) + "%"}',
        f'SCA {cnt(sca)}', f'Image {cnt(img)}',
        f'IaC {"n/a" if iac is None else iac}',
        f'ZAP H{z["H"]}/M{z["M"]}/L{z["L"]}' if z else 'ZAP n/a',
        f'Gauntlt {g[0]}/{g[1]}' if g else 'Gauntlt n/a',
    ])

    rows = ''
    for name, status, ms in stages():
        cls = {'SUCCESS': 'ok', 'FAILED': 'bad'}.get(status, 'warn')
        rows += (f'<tr><td>{html.escape(name)}</td><td class="{cls}">{status}</td>'
                 f'<td>{ms / 1000:.1f}s</td></tr>')

    def vuln_table(title, d):
        if d is None:
            return ''
        return (f'<h2>{title}</h2><p>CRITICAL: <b>{d["CRITICAL"]}</b> &nbsp; HIGH: <b>{d["HIGH"]}</b></p>')

    body = f"""
<h1>DevSecOps Report</h1>
<p>Result: <b>{html.escape(m.get('result', 'N/A'))}</b> &nbsp; Image: <b>{html.escape(m.get('image', ''))}</b></p>
<div class="cards">{''.join(f'<div class="card">{html.escape(k)}<b>{html.escape(str(v))}</b></div>' for k, v in cards)}</div>
<h2>Stages</h2>
<table><tr><th>Stage</th><th>Status</th><th>Duration</th></tr>{rows}</table>
{vuln_table('SCA - dependencies (Trivy fs)', sca)}
{vuln_table('Container image (Trivy image)', img)}
<h2>Secret scan</h2><pre>{html.escape(read('secret-scan.txt')[-2000:])}</pre>
"""

    page = lambda head: f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>DevSecOps Report</title>{head}</head><body>{body}</body></html>'

    os.makedirs(R, exist_ok=True)
    with open(os.path.join(R, 'report.css'), 'w', encoding='utf-8') as f:
        f.write(CSS)
    with open(os.path.join(R, 'devsecops-report.html'), 'w', encoding='utf-8') as f:
        f.write(page('<link rel="stylesheet" href="report.css">'))
    with open(os.path.join(R, 'devsecops-report-email.html'), 'w', encoding='utf-8') as f:
        f.write(page(f'<style>{CSS}</style>'))
    with open(os.path.join(R, 'summary-line.txt'), 'w', encoding='utf-8') as f:
        f.write(summary + '\n')
    with open(os.path.join(R, 'devsecops-summary.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(f'{k}: {v}' for k, v in cards) + '\n')
    print(summary)


if __name__ == '__main__':
    build()
