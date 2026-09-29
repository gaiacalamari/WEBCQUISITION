"""Report HTML autocontenuto (nessuna risorsa esterna, stampabile)."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .util import atomic_write_text

CSS = """
:root{--ink:#1d2733;--muted:#5b6876;--rule:#c9d1da;--panel:#f3f6f9;--ok:#1f7a4d;--warn:#9a6700;--bad:#b42318;--accent:#24527a}
*{box-sizing:border-box}
body{font-family:"Segoe UI",Calibri,"Helvetica Neue",Arial,sans-serif;color:var(--ink);margin:0;background:#fff;line-height:1.45}
main{max-width:1100px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:1.7rem;margin:0 0 4px;color:var(--accent)}
h2{font-size:1.15rem;margin:36px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--accent)}
.sub{color:var(--muted);margin:0 0 20px}
.verdict{display:flex;gap:18px;align-items:center;padding:16px 18px;border-left:6px solid var(--muted);background:var(--panel);margin:18px 0}
.verdict strong{font-size:1.4rem}
.verdict.COMPLETED{border-color:var(--ok)}.verdict.COMPLETED strong{color:var(--ok)}
.verdict.INCOMPLETE{border-color:var(--warn)}.verdict.INCOMPLETE strong{color:var(--warn)}
.verdict.FAILED{border-color:var(--bad)}.verdict.FAILED strong{color:var(--bad)}
.dry{background:#fff4ce;border:1px solid var(--warn);padding:10px 14px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--rule)}
th{background:var(--panel);font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
code,.hash{font-family:Consolas,"Cascadia Mono","Courier New",monospace;font-size:.82rem;word-break:break-all}
.sev-ERROR,.sev-CRITICAL{color:var(--bad);font-weight:600}.sev-WARNING{color:var(--warn);font-weight:600}
.scroll{overflow-x:auto}
.note{background:var(--panel);padding:10px 14px;border-left:4px solid var(--accent)}
@media print{main{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _e(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, (dict, list)):
        return f"<code>{html.escape(json.dumps(v, ensure_ascii=False))}</code>"
    return html.escape(str(v))


def _dl(pairs) -> str:
    return "<dl>" + "".join(f"<dt>{html.escape(k)}</dt><dd>{_e(v)}</dd>" for k, v in pairs) + "</dl>"


def generate_report(path: Path, manifest: dict, events: list[dict]) -> None:
    m = manifest
    acq, case, net, tls, integ = m["acquisition"], m["case"], m["network"], m["tls"], m["integrity"]
    state = acq["state"]
    parts = [
        "<!doctype html><html lang='it'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>WEBCQUISITION – {html.escape(case['case_id'])}</title><style>{CSS}</style></head><body><main>",
        f"<h1>Report di acquisizione {html.escape(case['case_id'])}</h1>",
        f"<p class='sub'>WEBCQUISITION {html.escape(m['tool']['version'])} · generato {html.escape(str(acq.get('finished_at_utc')))} UTC</p>",
    ]
    if m.get("dry_run"):
        parts.append(f"<p class='dry'>{html.escape(m.get('dry_run_notice') or 'DRY-RUN')}</p>")
    parts.append(f"<div class='verdict {html.escape(state)}'><strong>{html.escape(state)}</strong>"
                 f"<span>{html.escape(acq.get('state_meaning') or '')}</span></div>")

    parts.append("<h2>Caso e tempi</h2>")
    parts.append(_dl([
        ("ID caso", case["case_id"]), ("Operatore", case.get("operator")), ("Organizzazione", case.get("organization")),
        ("Inizio (UTC)", acq.get("started_at_utc")), ("Acquisizione attiva da (UTC)", acq.get("acquisition_active_at_utc")),
        ("Fine (UTC)", acq.get("finished_at_utc")), ("Motivo di chiusura", acq.get("stop_reason")),
        ("Fuso orario host", acq.get("host_timezone")), ("Fuso orario guest", acq.get("guest_timezone")),
        ("Offset orologio guest−host", acq.get("clock_offset_guest_minus_host")),
    ]))

    parts.append("<h2>Ambiente</h2>")
    hv, g = m["hypervisor"], m["guest"]
    parts.append(_dl([
        ("Host", f"{m['host']['hostname']} – {m['host']['os']}"),
        ("Hypervisor", f"{hv.get('provider')} {hv.get('provider_version') or ''}"),
        ("VM", f"{hv.get('vm_name')} (UUID {hv.get('vm_uuid')}, verificato: {'sì' if hv.get('vm_uuid_pinned') else 'no'})"),
        ("Snapshot ripristinato", hv.get("snapshot_restored")),
        ("Snapshot post-acquisizione", hv.get("post_acquisition_snapshot")),
        ("Schede di rete VM", hv.get("nics")),
        ("Agent", g.get("agent")),
        ("Windows", g.get("windows")), ("Firefox", g.get("firefox_version")), ("Wireshark/dumpcap", g.get("wireshark_version")),
        ("Sincronizzazione orologio guest", g.get("time_sync")),
    ]))

    parts.append("<h2>Traffico di rete</h2>")
    parts.append(_dl([
        ("Motore / modalità", f"{net.get('capture_engine')} / {net.get('capture_mode')}"),
        ("Interfaccia", net.get("interface")), ("Filtro di cattura", net.get("capture_filter") or "nessuno"),
        ("Comando", net.get("capture_command")), ("Pacchetti totali", net.get("packets_total")),
    ]))
    if net.get("pcap_files"):
        parts.append("<div class='scroll'><table><tr><th>File</th><th>Pacchetti</th><th>Primo pacchetto (UTC)</th>"
                     "<th>Ultimo pacchetto (UTC)</th><th>Valido</th><th>Coda troncata</th></tr>")
        for p in net["pcap_files"]:
            parts.append(f"<tr><td><code>{_e(p['path'])}</code></td><td>{_e(p['packets'])}</td><td>{_e(p['first_ts_utc'])}</td>"
                         f"<td>{_e(p['last_ts_utc'])}</td><td>{'sì' if p['valid'] else 'NO'}</td>"
                         f"<td>{'sì' if p['truncated_tail'] else 'no'}</td></tr>")
        parts.append("</table></div>")

    parts.append("<h2>TLS key log</h2>")
    parts.append(f"<p class='note'>{html.escape(tls['note'])}</p>")
    parts.append(_dl([("Abilitato", tls["enabled"]), ("Metodo", tls["method"]), ("File", tls["keylog_files"])]))

    parts.append("<h2>Anomalie</h2>")
    if m["issues"]:
        parts.append("<div class='scroll'><table><tr><th>Gravità</th><th>Codice</th><th>Descrizione</th><th>UTC</th></tr>")
        for i in m["issues"]:
            parts.append(f"<tr><td class='sev-{html.escape(i['severity'])}'>{html.escape(i['severity'])}</td>"
                         f"<td><code>{html.escape(i['code'])}</code></td><td>{html.escape(i['message'])}</td>"
                         f"<td>{html.escape(i['at_utc'])}</td></tr>")
        parts.append("</table></div>")
    else:
        parts.append("<p>Nessuna anomalia registrata.</p>")

    parts.append("<h2>File acquisiti e integrità</h2>")
    parts.append(_dl([
        ("Algoritmo", integ["algorithm"]), ("SHA-256 manifest guest", integ.get("guest_manifest_sha256")),
        ("File verificati sull'host", integ.get("verified_on_host")), ("Problemi", integ.get("problems") or "nessuno"),
        ("File inattesi", integ.get("unexpected_files") or "nessuno"),
    ]))
    parts.append("<div class='scroll'><table><tr><th>Percorso (acquired/)</th><th>Categoria</th><th>Byte</th><th>SHA-256</th></tr>")
    for f in m["files"]:
        parts.append(f"<tr><td><code>{_e(f['path'])}</code></td><td>{_e(f.get('category'))}</td>"
                     f"<td>{_e(f.get('size'))}</td><td class='hash'>{_e(f.get('sha256'))}</td></tr>")
    parts.append("</table></div>")

    parts.append("<h2>Cronologia eventi (host)</h2><div class='scroll'><table>"
                 "<tr><th>#</th><th>UTC</th><th>Evento</th><th>Gravità</th><th>Dettagli</th></tr>")
    for ev in events:
        details = ev.get("message") or ""
        if ev.get("data"):
            details += (" " if details else "") + json.dumps(ev["data"], ensure_ascii=False)[:400]
        parts.append(f"<tr><td>{ev['seq']}</td><td>{html.escape(ev['timestamp'])}</td><td><code>{html.escape(ev['event'])}</code></td>"
                     f"<td class='sev-{html.escape(ev['severity'])}'>{html.escape(ev['severity'])}</td>"
                     f"<td>{html.escape(details)}</td></tr>")
    parts.append("</table></div>")
    parts.append("<h2>Verifiche a carico dell'operatore</h2><p class='note'>Il report documenta le verifiche "
                 "automatiche. Restano a carico dell'operatore: coerenza tra quanto visualizzato e quanto "
                 "catturato, correttezza dell'orario di riferimento, verifica della decifratura TLS in Wireshark, "
                 "annotazione nel verbale dell'hash del sigillo (hashes/package-seal.json) e custodia del pacchetto.</p>")
    parts.append("</main></body></html>")
    atomic_write_text(path, "\n".join(parts))
