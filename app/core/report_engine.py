"""
app.core.report_engine
=========================

Last box in the architecture's GUI workflow arrow
("Results Normalization -> Report Generation -> Output to User").
Reads a completed ``Analysis`` and its ``Finding`` rows straight from
the database and renders HTML, PDF, JSON, or CSV -- every field in
every format comes from a real DB row; nothing here is templated
sample data.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import get_settings
from app.core.exceptions import ReportGenerationError
from app.core.sarif_export import write_sarif
from app.core.logger import get_logger
from app.database.database import session_scope
from app.database.models import Analysis, Finding, Project, Report, ReportFormat

logger = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "reports" / "templates"

_SEVERITY_COLORS = {
    "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
    "low": "#3b82f6", "info": "#8b96ab",
}


def _category_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        key = f.get("category") or "Uncategorised"
        counts[key] = counts.get(key, 0) + 1
    return counts


class ReportEngine:
    """Generates report artifacts from a completed analysis and records them in the ``reports`` table."""

    def __init__(self) -> None:
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def generate(self, analysis_id: int, fmt: ReportFormat) -> int:
        """Generate a report of the given format for ``analysis_id``. Returns the new Report row's id."""
        data = self._load_analysis_data(analysis_id)

        settings = get_settings()
        out_dir = settings.paths.reports_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_project_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in data["project"]["name"])
        base_name = f"{safe_project_name}_{analysis_id}_{timestamp}"

        try:
            if fmt == ReportFormat.HTML:
                file_path = out_dir / f"{base_name}.html"
                file_path.write_text(self._render_html(data), encoding="utf-8")
            elif fmt == ReportFormat.JSON:
                file_path = out_dir / f"{base_name}.json"
                file_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            elif fmt == ReportFormat.CSV:
                file_path = out_dir / f"{base_name}.csv"
                file_path.write_text(self._render_csv(data), encoding="utf-8")
            elif fmt == ReportFormat.PDF:
                file_path = out_dir / f"{base_name}.pdf"
                self._render_pdf(data, file_path)
            elif fmt == ReportFormat.SARIF:
                file_path = out_dir / f"{base_name}.sarif"
                write_sarif(data, file_path, tool_version=get_settings().version)
            elif fmt == ReportFormat.MARKDOWN:
                file_path = out_dir / f"{base_name}.md"
                file_path.write_text(self._render_markdown(data), encoding="utf-8")
            else:
                raise ReportGenerationError(f"Unsupported report format: {fmt}")
        except (OSError, UnicodeError) as exc:
            raise ReportGenerationError(
                f"Failed to write report file for analysis {analysis_id}", details={"error": str(exc)}
            ) from exc

        summary = (
            f"{data['finding_count']} finding(s), risk score "
            f"{data['analysis']['risk_score'] if data['analysis']['risk_score'] is not None else 'N/A'}"
        )
        with session_scope() as session:
            report = Report(
                analysis_id=analysis_id, format=fmt, file_path=str(file_path), summary=summary,
            )
            session.add(report)
            session.flush()
            report_id = report.id

        logger.info("Generated %s report for analysis %s at %s", fmt.value, analysis_id, file_path)
        return report_id

    # ------------------------------------------------------------------ #
    # Data loading (DB -> plain dict, detached from the session)
    # ------------------------------------------------------------------ #
    def _load_analysis_data(self, analysis_id: int) -> dict:
        with session_scope() as session:
            analysis = session.get(Analysis, analysis_id)
            if analysis is None:
                raise ReportGenerationError(f"Analysis {analysis_id} does not exist")
            project = session.get(Project, analysis.project_id)
            findings = (
                session.query(Finding)
                .filter_by(analysis_id=analysis_id)
                .order_by(Finding.severity)
                .all()
            )

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            finding_dicts = sorted(
                (
                    {
                        "title": f.title, "description": f.description, "severity": f.severity.value,
                        "category": f.category, "owasp_mapping": f.owasp_mapping,
                        "masvs_mapping": f.masvs_mapping, "mitre_mapping": f.mitre_mapping,
                        "evidence": f.evidence, "file_path": f.file_path, "line_number": f.line_number,
                        "recommendation": f.recommendation, "status": f.status.value,
                        # Professional reporting fields -- every output format
                        # (HTML/PDF/Markdown/SARIF) reads from this one dict, so
                        # adding them here makes them available everywhere at once.
                        "impact": f.impact, "reproduction_steps": f.reproduction_steps,
                        "affected_components": f.affected_components,
                        "cwe_id": f.cwe_id, "cvss_vector": f.cvss_vector, "cvss_score": f.cvss_score,
                        "confidence": f.confidence.value if f.confidence else "medium",
                        "references": list(f.references or []),
                    }
                    for f in findings
                ),
                key=lambda d: severity_order.get(d["severity"], 9),
            )

            severity_counts = {sev: 0 for sev in severity_order}
            for f in finding_dicts:
                severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

            return {
                "project": {
                    "name": project.name, "platform": project.platform.value,
                    "project_type": project.project_type.value, "target_path": project.target_path,
                },
                "analysis": {
                    "id": analysis.id, "workflow_name": analysis.workflow_name,
                    "analysis_type": analysis.analysis_type.value, "status": analysis.status.value,
                    "risk_score": analysis.risk_score,
                    "started_at": analysis.started_at, "completed_at": analysis.completed_at,
                },
                "findings": finding_dicts,
                "finding_count": len(finding_dicts),
                "severity_counts": severity_counts,
            }

    # ------------------------------------------------------------------ #
    # Renderers
    # ------------------------------------------------------------------ #
    def _render_html(self, data: dict) -> str:
        settings = get_settings()
        risk_score = data["analysis"]["risk_score"] or 0.0
        risk_class = "risk-high" if risk_score >= 7 else ("risk-medium" if risk_score >= 4 else "risk-low")
        template = self._jinja_env.get_template("static_analysis_report.html")
        return template.render(
            project=data["project"], analysis=data["analysis"], findings=data["findings"],
            severity_counts=list(data["severity_counts"].items()), severity_colors=_SEVERITY_COLORS,
            counts=data["severity_counts"],
            category_counts=_category_counts(data["findings"]),
            risk_class=risk_class, pentroid_version=settings.version,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

    def _render_csv(self, data: dict) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "Title", "Severity", "Category", "Description", "OWASP", "MASVS",
            "File", "Line", "Recommendation", "Status",
        ])
        for f in data["findings"]:
            writer.writerow([
                f["title"], f["severity"], f["category"] or "", f["description"] or "",
                f["owasp_mapping"] or "", f["masvs_mapping"] or "", f["file_path"] or "",
                f["line_number"] or "", f["recommendation"] or "", f["status"],
            ])
        return buffer.getvalue()

    def _render_markdown(self, data: dict) -> str:
        lines = [
            f"# Pentroid Report - {data['project']['name']}",
            "",
            f"**Platform:** {data['project']['platform']}  ",
            f"**Risk Score:** {data['analysis']['risk_score'] or 0:.1f} / 10  ",
            f"**Findings:** {data['finding_count']}",
            "",
            "## Findings",
            "",
        ]
        if not data["findings"]:
            lines.append("_No findings recorded for this analysis._")
        for f in data["findings"]:
            lines.append(f"### {f['title']} `{f['severity'].upper()}`")
            if f["description"]:
                lines.append(f["description"])
            if f["recommendation"]:
                lines.append(f"\n**Recommendation:** {f['recommendation']}")
            lines.append("")
        return "\n".join(lines)

    def _render_pdf(self, data: dict, file_path: Path) -> None:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("PentroidTitle", parent=styles["Title"], textColor=colors.HexColor("#1f8a52"))
        finding_title_style = ParagraphStyle("FindingTitle", parent=styles["Heading3"], spaceAfter=2)
        body_style = styles["BodyText"]

        doc = SimpleDocTemplate(str(file_path), pagesize=letter)
        story = [
            Paragraph("PENTROID Security Report", title_style),
            Paragraph(f"{data['project']['name']} &mdash; {data['project']['platform']}", styles["Heading2"]),
            Spacer(1, 12),
        ]

        summary_table = Table(
            [
                ["Risk Score", f"{data['analysis']['risk_score'] or 0:.1f} / 10"],
                ["Total Findings", str(data["finding_count"])],
                ["Analysis Type", data["analysis"]["analysis_type"]],
                ["Status", data["analysis"]["status"]],
            ],
            colWidths=[2 * inch, 3 * inch],
        )
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0f1520")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1a1a1a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        story.append(Paragraph("Findings", styles["Heading2"]))

        if not data["findings"]:
            story.append(Paragraph("No findings recorded for this analysis.", body_style))
        for f in data["findings"]:
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"{f['title']} [{f['severity'].upper()}]", finding_title_style))
            if f["description"]:
                story.append(Paragraph(f["description"], body_style))
            if f["recommendation"]:
                story.append(Paragraph(f"<b>Recommendation:</b> {f['recommendation']}", body_style))

        doc.build(story)


_report_engine: ReportEngine | None = None


def get_report_engine() -> ReportEngine:
    global _report_engine
    if _report_engine is None:
        _report_engine = ReportEngine()
    return _report_engine
