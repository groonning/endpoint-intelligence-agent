"""Reporting Engine — JSON, HTML, and (optional) PDF.

A report documents, per the brief: time, machine, method, finding and
recommendation, and keeps CONFIRMED findings separate from AI HYPOTHESES.

  * JSON is always produced (machine-readable, for the Orchestrator / SIEM).
  * HTML is always produced (self-contained, no external assets).
  * PDF is produced if a renderer is available (weasyprint, else wkhtmltopdf via
    pdfkit); otherwise the report notes that PDF was skipped — it never fails the
    run over a missing optional renderer.
"""
from __future__ import annotations

import html
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..analyzer.analyzer import Finding, Severity

_SEV_COLOR = {4: "#7c1d1d", 3: "#b91c1c", 2: "#b45309", 1: "#2563eb", 0: "#475569"}


@dataclass
class Report:
    json_path: str = ""
    html_path: str = ""
    pdf_path: str = ""
    pdf_skipped_reason: str = ""


class ReportBuilder:
    def __init__(self, out_dir: str = "reports"):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def build(self, session: dict, basename: str | None = None) -> Report:
        """`session` is the structured result from EndpointIntelligenceAgent.run_*:
        {
          "generated_at", "scope", "hosts": [
             {"host","os_name","method","collected_at",
              "findings":[Finding.dict...], "ai": {... hypothesis ...}}
          ],
          "audit_verified": bool, "ai_correlation": {...}
        }
        """
        stamp = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
        base = basename or f"endpoint_session_{stamp}"
        report = Report()

        json_path = self.out_dir / f"{base}.json"
        json_path.write_text(json.dumps(session, indent=2, ensure_ascii=False))
        report.json_path = str(json_path)

        html_doc = self._html(session, stamp)
        html_path = self.out_dir / f"{base}.html"
        html_path.write_text(html_doc, encoding="utf-8")
        report.html_path = str(html_path)

        pdf_path = self.out_dir / f"{base}.pdf"
        ok, reason = self._pdf(html_doc, pdf_path)
        if ok:
            report.pdf_path = str(pdf_path)
        else:
            report.pdf_skipped_reason = reason
        return report

    # --------------------------------------------------------------- HTML
    def _html(self, session: dict, stamp: str) -> str:
        hosts = session.get("hosts", [])
        total = sum(len(h.get("findings", [])) for h in hosts)
        sev_counts = {s: 0 for s in range(5)}
        for h in hosts:
            for f in h.get("findings", []):
                sev_counts[int(f.get("severity", 0))] += 1

        parts = [f"""<!DOCTYPE html><html lang="no"><head><meta charset="utf-8">
<title>Endpoint Intelligence rapport — {html.escape(stamp)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f8fafc;color:#0f172a}}
 header{{background:#0f172a;color:#fff;padding:24px 32px}}
 header h1{{margin:0;font-size:20px}} header .sub{{color:#94a3b8;font-size:13px;margin-top:4px}}
 main{{max-width:960px;margin:0 auto;padding:24px 32px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
 .card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px 16px;min-width:110px}}
 .card .n{{font-size:24px;font-weight:700}} .card .l{{font-size:12px;color:#64748b}}
 .host{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;margin:16px 0;overflow:hidden}}
 .host h2{{margin:0;padding:14px 18px;font-size:16px;background:#f1f5f9;border-bottom:1px solid #e2e8f0}}
 .host .meta{{padding:4px 18px;color:#64748b;font-size:12px}}
 .f{{padding:12px 18px;border-top:1px solid #f1f5f9}}
 .badge{{display:inline-block;color:#fff;border-radius:6px;padding:1px 8px;font-size:11px;font-weight:700;text-transform:uppercase}}
 .f .t{{font-weight:600;margin:6px 0 2px}} .f .d{{font-size:14px}} .f .r{{font-size:13px;color:#166534;margin-top:4px}}
 .ev{{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:6px 8px;margin-top:6px;white-space:pre-wrap;word-break:break-all}}
 .hyp{{background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:12px 16px;margin-top:8px}}
 .hyp .tag{{font-size:11px;font-weight:700;color:#92400e;text-transform:uppercase}}
 footer{{max-width:960px;margin:0 auto;padding:16px 32px;color:#94a3b8;font-size:12px}}
</style></head><body>
<header><h1>Endpoint Intelligence rapport</h1>
<div class="sub">Agent 2 · generert {html.escape(session.get('generated_at', stamp))} ·
scope: {html.escape(', '.join(session.get('scope', [])) or '—')} ·
revisjonslogg: {'verifisert ✓' if session.get('audit_verified') else 'ikke verifisert'}</div></header>
<main>
<div class="cards">
 <div class="card"><div class="n">{len(hosts)}</div><div class="l">verter</div></div>
 <div class="card"><div class="n">{total}</div><div class="l">funn</div></div>
 <div class="card"><div class="n" style="color:{_SEV_COLOR[4]}">{sev_counts[4]}</div><div class="l">kritisk</div></div>
 <div class="card"><div class="n" style="color:{_SEV_COLOR[3]}">{sev_counts[3]}</div><div class="l">høy</div></div>
 <div class="card"><div class="n" style="color:{_SEV_COLOR[2]}">{sev_counts[2]}</div><div class="l">medium</div></div>
</div>"""]

        corr = session.get("ai_correlation")
        if corr and corr.get("ok") and corr.get("text"):
            parts.append(f'<div class="hyp"><div class="tag">AI-hypotese · korrelasjon '
                         f'({html.escape((corr.get("route") or {}).get("model",""))})</div>'
                         f'<div>{_md(corr["text"])}</div></div>')

        for h in hosts:
            parts.append(f'<div class="host"><h2>{html.escape(h.get("host",""))} '
                         f'<span style="color:#64748b;font-weight:400">'
                         f'({html.escape(h.get("os_name",""))})</span></h2>')
            parts.append(f'<div class="meta">metode: {html.escape(h.get("method",""))} · '
                         f'innsamlet: {html.escape(h.get("collected_at",""))}</div>')
            fs = sorted(h.get("findings", []), key=lambda x: -int(x.get("severity", 0)))
            if h.get("error"):
                parts.append(f'<div class="f"><span class="badge" style="background:{_SEV_COLOR[3]}">'
                             f'ikke undersøkt</span><div class="d">{html.escape(h["error"])}</div></div>')
            elif not fs:
                parts.append('<div class="f"><div class="d">Ingen bekreftede funn.</div></div>')
            for f in fs:
                sev = int(f.get("severity", 0))
                parts.append(
                    f'<div class="f"><span class="badge" style="background:{_SEV_COLOR[sev]}">'
                    f'{html.escape(f.get("severity_label",""))}</span>'
                    f'<span style="color:#94a3b8;font-size:12px"> · {html.escape(f.get("source",""))}'
                    f' · {html.escape(f.get("category",""))}'
                    f'{"" if f.get("confirmed", True) else " · UBEKREFTET (omtrentlig treff)"}</span>'
                    f'<div class="t">{html.escape(f.get("title",""))}</div>'
                    f'<div class="d">{html.escape(f.get("detail",""))}</div>')
                if f.get("evidence"):
                    parts.append(f'<div class="ev">{html.escape(str(f["evidence"])[:400])}</div>')
                if f.get("recommendation"):
                    parts.append(f'<div class="r">→ {html.escape(f["recommendation"])}</div>')
                parts.append('</div>')
            files = h.get("files") or []
            if files:
                hits = sum(1 for x in files if x.get("yara"))
                parts.append(f'<div class="meta" style="padding-bottom:10px">filer hashet i godkjente '
                             f'kataloger: {len(files)} · YARA-treff: {hits}</div>')
            ai = h.get("ai")
            if ai and ai.get("ok") and ai.get("text"):
                model = (ai.get("route") or {}).get("model", "")
                parts.append(f'<div class="hyp" style="margin:12px 18px 16px">'
                             f'<div class="tag">AI-hypotese ({html.escape(model)})</div>'
                             f'<div>{_md(ai["text"])}</div></div>')
            parts.append('</div>')

        parts.append('</main><footer>Endpoint Intelligence Agent (Agent 2). '
                     'Bekreftede funn er regelbaserte observasjoner. AI-seksjoner '
                     'er hypoteser og må verifiseres manuelt.</footer></body></html>')
        return "\n".join(parts)

    # ---------------------------------------------------------------- PDF
    def _pdf(self, html_doc: str, out: Path) -> tuple[bool, str]:
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html_doc).write_pdf(str(out))
            return True, ""
        except Exception as e:
            reason = f"weasyprint unavailable ({e.__class__.__name__})"
        try:
            import pdfkit  # type: ignore
            pdfkit.from_string(html_doc, str(out))
            return True, ""
        except Exception:
            return False, reason + "; pdfkit/wkhtmltopdf unavailable — PDF skipped"


def _md(text: str) -> str:
    """Very small markdown-ish renderer for AI output (headings + line breaks)."""
    out = []
    for line in html.escape(text).splitlines():
        s = line.strip()
        if s.startswith("### "):
            out.append(f"<h4>{s[4:]}</h4>")
        elif s.startswith("## "):
            out.append(f"<h3>{s[3:]}</h3>")
        elif s.startswith("# "):
            out.append(f"<h3>{s[2:]}</h3>")
        elif s.startswith(("- ", "* ")):
            out.append(f"• {s[2:]}<br>")
        else:
            out.append(line + "<br>")
    return "\n".join(out)
