# AutoPen PDF Report Generator
# Executive-grade professional report
# Styled like a real penetration testing report
# Uses WeasyPrint for pixel-perfect PDF output

import os
from datetime import datetime
from jinja2 import Template
from weasyprint import HTML, CSS
from rich.console import Console

console = Console()


class PDFReportGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.output_dir = os.path.expanduser(
            config['reporting']['output_dir']
        )
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as e:
            console.print(f"[bold red]✗ Could not create report directory: {self.output_dir}[/bold red]")
            console.print(f"[yellow]Error: {e}[/yellow]")
            # We don't exit here, because generate() might still try to use it
            # and fail later, or we might want to fallback. 
            # But for now, we've warned the user.

    def generate(self, findings: list, target: str) -> str:
        """
        Generate professional PDF report.
        Returns path to generated PDF.
        """
        console.print("\n[bold white]Generating PDF report...[/bold white]")

        # Calculate statistics
        stats = self._calculate_stats(findings)

        # Always generate HTML report first
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        clean_target = target.replace('.', '_')

        html_filename = f"autopen_report_{clean_target}_{timestamp}.html"
        html_path = os.path.join(self.output_dir, html_filename)

        html_content = self._build_html(findings, target, stats)

        with open(html_path, 'w') as f:
            f.write(f"<style>{self._get_css()}</style>")
            f.write(html_content)

        console.print(
            f"[bold green]✓ HTML report generated:[/bold green] {html_path}"
        )

        # Try PDF generation
        pdf_filename = f"autopen_report_{clean_target}_{timestamp}.pdf"
        pdf_path = os.path.join(self.output_dir, pdf_filename)

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer,
                Table, TableStyle, PageBreak
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            doc = SimpleDocTemplate(
                pdf_path,
                pagesize=A4,
                rightMargin=2*cm,
                leftMargin=2*cm,
                topMargin=2*cm,
                bottomMargin=2*cm
            )

            styles = getSampleStyleSheet()
            story = []

            # Colors
            RED = colors.HexColor('#dc2626')
            DARK = colors.HexColor('#1f2937')
            GRAY = colors.HexColor('#6b7280')
            LIGHT = colors.HexColor('#f9fafb')

            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=28,
                textColor=RED,
                spaceAfter=10,
                alignment=TA_CENTER
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=RED,
                spaceAfter=12,
                borderPad=4
            )
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=10,
                spaceAfter=8
            )
            small_style = ParagraphStyle(
                'SmallStyle',
                parent=styles['Normal'],
                fontSize=9,
                textColor=GRAY
            )

            now = datetime.now()

            # ── COVER PAGE ──
            story.append(Spacer(1, 2*cm))
            story.append(Paragraph("AutoPen", title_style))
            story.append(Paragraph(
                "Automated Penetration Testing Tool",
                ParagraphStyle('sub', parent=styles['Normal'],
                               fontSize=14, textColor=GRAY,
                               alignment=TA_CENTER, spaceAfter=30)
            ))
            story.append(Spacer(1, 1*cm))
            story.append(Paragraph(
                "Security Assessment Report",
                ParagraphStyle('repTitle', parent=styles['Normal'],
                               fontSize=20, textColor=DARK,
                               alignment=TA_CENTER, spaceAfter=8)
            ))
            story.append(Spacer(1, 1*cm))

            # Cover table
            cover_data = [
                ['Target System', target],
                ['Assessment Date', now.strftime('%B %d, %Y')],
                ['Report Generated', now.strftime('%Y-%m-%d %H:%M:%S')],
                ['Tool Version', 'AutoPen v1.0'],
                ['Classification',
                 self.config['reporting']['classification']],
                ['Overall Risk', stats['risk_level']],
            ]
            cover_table = Table(cover_data, colWidths=[6*cm, 11*cm])
            cover_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('TEXTCOLOR', (0, 0), (0, -1), GRAY),
                ('TEXTCOLOR', (1, 0), (1, -1), DARK),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.lightgrey),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1),
                 [colors.white, colors.HexColor('#f9fafb')]),
            ]))
            story.append(cover_table)
            story.append(PageBreak())

            # ── EXECUTIVE SUMMARY ──
            story.append(Paragraph("1. Executive Summary", heading_style))
            story.append(Paragraph(
                f"AutoPen conducted an automated penetration test against "
                f"<b>{target}</b> on {now.strftime('%B %d, %Y')}. "
                f"The assessment identified <b>{stats['total']} security "
                f"vulnerabilities</b> across network services and web "
                f"applications. The overall risk is assessed as "
                f"<b>{stats['risk_level']}</b> with a risk score of "
                f"<b>{stats['risk_score']}/100</b>.",
                normal_style
            ))
            story.append(Spacer(1, 0.5*cm))

            # Risk summary table
            story.append(Paragraph("Risk Summary", styles['Heading2']))
            risk_data = [
                ['Severity', 'Count', 'Action Required'],
                ['CRITICAL', str(stats['critical']), 'Immediate — 24 hours'],
                ['HIGH', str(stats['high']), 'Urgent — 7 days'],
                ['MEDIUM', str(stats['medium']), 'Important — 30 days'],
                ['LOW', str(stats['low']), 'Planned — 90 days'],
                ['TOTAL', str(stats['total']), ''],
            ]
            risk_table = Table(
                risk_data,
                colWidths=[5*cm, 3*cm, 9*cm]
            )
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), DARK),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, 1),
                 colors.HexColor('#fef2f2')),
                ('BACKGROUND', (0, 2), (-1, 2),
                 colors.HexColor('#fff7ed')),
                ('BACKGROUND', (0, 3), (-1, 3),
                 colors.HexColor('#fffbeb')),
                ('BACKGROUND', (0, 4), (-1, 4),
                 colors.HexColor('#f0fdf4')),
                ('BACKGROUND', (0, 5), (-1, 5),
                 colors.HexColor('#f3f4f6')),
                ('FONTNAME', (0, 5), (-1, 5), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ]))
            story.append(risk_table)
            story.append(PageBreak())

            # ── DETAILED FINDINGS ──
            story.append(Paragraph("2. Detailed Findings", heading_style))

            severity_colors_map = {
                'CRITICAL': colors.HexColor('#dc2626'),
                'HIGH': colors.HexColor('#ea580c'),
                'MEDIUM': colors.HexColor('#d97706'),
                'LOW': colors.HexColor('#16a34a'),
            }

            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'LOW').upper()
                sev_color = severity_colors_map.get(
                    severity, colors.gray
                )
                cvss = finding.get('cvss_score', 'N/A')
                cvss_vector = finding.get('cvss_vector', 'N/A')

                # Finding header
                finding_data = [
                    [f"Finding {i:02d}",
                     finding.get('title', 'Unknown')[:60],
                     severity,
                     f"CVSS {cvss}"],
                ]
                finding_table = Table(
                    finding_data,
                    colWidths=[2*cm, 10*cm, 3*cm, 2.5*cm]
                )
                finding_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), LIGHT),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
                    ('TEXTCOLOR', (2, 0), (2, 0), sev_color),
                    ('FONTNAME', (2, 0), (2, 0), 'Helvetica-Bold'),
                    ('PADDING', (0, 0), (-1, -1), 8),
                    ('LINEAFTER', (0, 0), (-2, -1),
                     0.5, colors.lightgrey),
                    ('LINEBEFORE', (0, 0), (0, -1), 3, sev_color),
                ]))
                story.append(finding_table)

                # Finding details
                details_data = [
                    ['Target', finding.get('target', 'N/A')[:60]],
                    ['CVSS Vector', cvss_vector],
                    ['Description',
                     finding.get('description', 'N/A')[:200]],
                    ['Remediation',
                     finding.get('remediation', 'N/A')[:300]],
                ]
                details_table = Table(
                    details_data,
                    colWidths=[3*cm, 14*cm]
                )
                details_table.setStyle(TableStyle([
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('TEXTCOLOR', (0, 0), (0, -1), GRAY),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LINEBELOW', (0, 0), (-1, -2),
                     0.3, colors.lightgrey),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(details_table)
                story.append(Spacer(1, 0.4*cm))

            story.append(PageBreak())

            # ── REMEDIATION ROADMAP ──
            story.append(
                Paragraph("3. Remediation Roadmap", heading_style)
            )

            timelines = {
                'CRITICAL': '24 hours',
                'HIGH': '7 days',
                'MEDIUM': '30 days',
                'LOW': '90 days'
            }

            sorted_findings = sorted(
                findings,
                key=lambda x: (
                    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(
                        x.get('severity', 'LOW').upper()
                    )
                )
            )

            roadmap_data = [['#', 'Finding', 'Severity', 'CVSS', 'Fix By']]
            for i, f in enumerate(sorted_findings, 1):
                sev = f.get('severity', 'LOW').upper()
                roadmap_data.append([
                    str(i),
                    f.get('title', '')[:45],
                    sev,
                    str(f.get('cvss_score', 'N/A')),
                    timelines.get(sev, '90 days')
                ])

            roadmap_table = Table(
                roadmap_data,
                colWidths=[1*cm, 9*cm, 3*cm, 2*cm, 2.5*cm]
            )
            roadmap_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), DARK),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.white, LIGHT]),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ]))
            story.append(roadmap_table)

            # Build PDF
            doc.build(story)
            console.print(
                f"[bold green]✓ PDF report generated:[/bold green] "
                f"{pdf_path}"
            )
            return pdf_path

        except Exception as e:
            console.print(
                f"[yellow]PDF note: {e}[/yellow]\n"
                f"[bold green]✓ HTML report available:[/bold green] "
                f"{html_path}"
            )
            return html_path

    def _calculate_stats(self, findings: list) -> dict:
        """Calculate finding statistics for report"""
        stats = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }

        for f in findings:
            severity = f.get('severity', 'LOW').upper()
            if severity == 'CRITICAL':
                stats['critical'] += 1
            elif severity == 'HIGH':
                stats['high'] += 1
            elif severity == 'MEDIUM':
                stats['medium'] += 1
            else:
                stats['low'] += 1

            ftype = f.get('type', 'other')
            stats['by_type'][ftype] = stats['by_type'].get(ftype, 0) + 1

        # Risk score
        stats['risk_score'] = min(
            100,
            (stats['critical'] * 25) +
            (stats['high'] * 10) +
            (stats['medium'] * 5) +
            (stats['low'] * 1)
        )

        if stats['risk_score'] >= 75:
            stats['risk_level'] = 'CRITICAL'
            stats['risk_color'] = '#dc2626'
        elif stats['risk_score'] >= 50:
            stats['risk_level'] = 'HIGH'
            stats['risk_color'] = '#ea580c'
        elif stats['risk_score'] >= 25:
            stats['risk_level'] = 'MEDIUM'
            stats['risk_color'] = '#d97706'
        else:
            stats['risk_level'] = 'LOW'
            stats['risk_color'] = '#16a34a'

        return stats

    def _build_html(self, findings: list,
                    target: str, stats: dict) -> str:
        """Build complete HTML report"""
        now = datetime.now()

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AutoPen Security Assessment Report</title>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover-page">
    <div class="cover-header">
        <div class="logo-text">AutoPen</div>
        <div class="logo-sub">Automated Penetration Testing</div>
    </div>

    <div class="cover-title">
        <h1>Security Assessment Report</h1>
        <h2>Penetration Testing Summary</h2>
    </div>

    <div class="cover-details">
        <table class="cover-table">
            <tr>
                <td class="label">Target System</td>
                <td class="value">{target}</td>
            </tr>
            <tr>
                <td class="label">Assessment Date</td>
                <td class="value">{now.strftime('%B %d, %Y')}</td>
            </tr>
            <tr>
                <td class="label">Report Generated</td>
                <td class="value">{now.strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
            <tr>
                <td class="label">Tool Version</td>
                <td class="value">AutoPen v1.0</td>
            </tr>
            <tr>
                <td class="label">Classification</td>
                <td class="value">
                    {self.config['reporting']['classification']}
                </td>
            </tr>
        </table>
    </div>

    <div class="risk-badge" style="background:{stats['risk_color']}">
        Overall Risk: {stats['risk_level']}
    </div>

    <div class="cover-footer">
        This report contains sensitive security information.
        Handle according to your organization data classification policy.
    </div>
</div>

<!-- PAGE BREAK -->
<div class="page-break"></div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
    <h1 class="section-title">1. Executive Summary</h1>

    <div class="executive-box">
        <p>
            AutoPen conducted an automated penetration test against
            <strong>{target}</strong> on {now.strftime('%B %d, %Y')}.
            The assessment identified <strong>{stats['total']} security
            vulnerabilities</strong> across network services and web
            applications.
        </p>
        <p>
            The overall risk posture of the target system is assessed as
            <strong style="color:{stats['risk_color']}">
            {stats['risk_level']}</strong>
            with a risk score of <strong>{stats['risk_score']}/100</strong>.
            Immediate remediation is recommended for all critical and
            high severity findings.
        </p>
        <p>
            The most critical findings include exposed vulnerable network
            services with known public exploits, web application injection
            vulnerabilities, and information disclosure issues that could
            allow an attacker to gain unauthorized access to the system.
        </p>
    </div>

    <!-- Risk Summary Table -->
    <h2>Risk Summary</h2>
    <table class="summary-table">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Risk Impact</th>
                <th>Action Required</th>
            </tr>
        </thead>
        <tbody>
            <tr class="critical-row">
                <td><span class="badge critical">CRITICAL</span></td>
                <td>{stats['critical']}</td>
                <td>System compromise possible</td>
                <td>Immediate — within 24 hours</td>
            </tr>
            <tr class="high-row">
                <td><span class="badge high">HIGH</span></td>
                <td>{stats['high']}</td>
                <td>Significant data exposure risk</td>
                <td>Urgent — within 7 days</td>
            </tr>
            <tr class="medium-row">
                <td><span class="badge medium">MEDIUM</span></td>
                <td>{stats['medium']}</td>
                <td>Limited unauthorized access</td>
                <td>Important — within 30 days</td>
            </tr>
            <tr class="low-row">
                <td><span class="badge low">LOW</span></td>
                <td>{stats['low']}</td>
                <td>Minimal direct impact</td>
                <td>Planned — within 90 days</td>
            </tr>
            <tr class="total-row">
                <td><strong>TOTAL</strong></td>
                <td><strong>{stats['total']}</strong></td>
                <td colspan="2"></td>
            </tr>
        </tbody>
    </table>
</div>

<div class="page-break"></div>

<!-- SCOPE AND METHODOLOGY -->
<div class="section">
    <h1 class="section-title">2. Scope and Methodology</h1>

    <h2>Assessment Scope</h2>
    <table class="info-table">
        <tr>
            <td class="info-label">Target Host</td>
            <td>{target}</td>
        </tr>
        <tr>
            <td class="info-label">Assessment Type</td>
            <td>Automated Black-box Penetration Test</td>
        </tr>
        <tr>
            <td class="info-label">Modules Used</td>
            <td>Reconnaissance, SQL Injection, XSS,
                Directory Brute-forcing</td>
        </tr>
        <tr>
            <td class="info-label">Testing Window</td>
            <td>{now.strftime('%Y-%m-%d %H:%M')} — Assessment Complete</td>
        </tr>
    </table>

    <h2>Methodology</h2>
    <p>AutoPen follows a structured penetration testing methodology
    aligned with OWASP Testing Guide v4.2:</p>

    <ol class="methodology-list">
        <li><strong>Reconnaissance</strong> — Network scanning and
            service enumeration using Nmap. Identification of open
            ports, service versions, and potential CVE matches.</li>
        <li><strong>Web Crawling</strong> — Automated discovery of
            web application pages, forms, and injectable parameters
            without prior knowledge of application structure.</li>
        <li><strong>Vulnerability Detection</strong> — Active testing
            of discovered parameters using curated payload libraries
            for SQL injection and Cross-Site Scripting.</li>
        <li><strong>Directory Enumeration</strong> — Brute-force
            discovery of hidden directories, sensitive files, and
            administrative interfaces.</li>
        <li><strong>Risk Scoring</strong> — CVSS v3.1 scoring applied
            to all findings with justification for each vector.</li>
    </ol>
</div>

<div class="page-break"></div>

<!-- FINDINGS -->
<div class="section">
    <h1 class="section-title">3. Detailed Findings</h1>
"""

        # Add each finding
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'LOW').upper()
            severity_class = severity.lower()
            cvss = finding.get('cvss_score', 'N/A')
            cvss_vector = finding.get('cvss_vector', 'N/A')

            html += f"""
    <div class="finding-card {severity_class}-card">
        <div class="finding-header">
            <div class="finding-number">Finding {i:02d}</div>
            <div class="finding-title">{finding.get('title', 'Unknown')}</div>
            <div class="finding-badges">
                <span class="badge {severity_class}">{severity}</span>
                <span class="cvss-badge">CVSS {cvss}</span>
            </div>
        </div>

        <table class="finding-table">
            <tr>
                <td class="finding-label">Target</td>
                <td>{finding.get('target', 'N/A')}</td>
            </tr>
            <tr>
                <td class="finding-label">CVSS Vector</td>
                <td><code>{cvss_vector}</code></td>
            </tr>
            <tr>
                <td class="finding-label">Discovered</td>
                <td>{finding.get('discovered_at', 'N/A')}</td>
            </tr>
        </table>

        <h4>Description</h4>
        <p>{finding.get('description', 'N/A')}</p>

        <h4>Evidence</h4>
        <pre class="evidence-box">{finding.get('evidence', 'N/A')}</pre>

        <h4>Remediation</h4>
        <p>{finding.get('remediation', 'N/A')}</p>
    </div>
"""

        html += """
</div>

<div class="page-break"></div>

<!-- REMEDIATION ROADMAP -->
<div class="section">
    <h1 class="section-title">4. Remediation Roadmap</h1>
    <p>The following remediation plan prioritizes findings by severity
    and recommended timeline:</p>

    <table class="roadmap-table">
        <thead>
            <tr>
                <th>#</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>Timeline</th>
            </tr>
        </thead>
        <tbody>
"""

        timelines = {
            'CRITICAL': '24 hours',
            'HIGH': '7 days',
            'MEDIUM': '30 days',
            'LOW': '90 days'
        }

        sorted_findings = sorted(
            findings,
            key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(
                x.get('severity', 'LOW').upper()
            )
        )

        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get('severity', 'LOW').upper()
            timeline = timelines.get(severity, '90 days')
            html += f"""
            <tr>
                <td>{i}</td>
                <td>{finding.get('title', 'Unknown')[:60]}</td>
                <td><span class="badge {severity.lower()}">{severity}</span></td>
                <td>{finding.get('cvss_score', 'N/A')}</td>
                <td>{timeline}</td>
            </tr>
"""

        html += """
        </tbody>
    </table>
</div>

</body>
</html>
"""
        return html

    def _get_css(self) -> str:
        """Professional report CSS styling"""
        return """
            @page {
                margin: 2cm;
                @bottom-center {
                    content: "AutoPen Security Report | CONFIDENTIAL | Page "
                             counter(page) " of " counter(pages);
                    font-size: 9pt;
                    color: #6b7280;
                }
            }

            body {
                font-family: Arial, sans-serif;
                font-size: 11pt;
                color: #1f2937;
                line-height: 1.6;
            }

            .page-break { page-break-after: always; }

            /* Cover Page */
            .cover-page {
                text-align: center;
                padding: 50px 0;
            }

            .logo-text {
                font-size: 48pt;
                font-weight: bold;
                color: #dc2626;
                letter-spacing: 4px;
            }

            .logo-sub {
                font-size: 14pt;
                color: #6b7280;
                margin-bottom: 60px;
            }

            .cover-title h1 {
                font-size: 28pt;
                color: #1f2937;
                margin-bottom: 10px;
            }

            .cover-title h2 {
                font-size: 16pt;
                color: #6b7280;
                font-weight: normal;
                margin-bottom: 60px;
            }

            .cover-table {
                margin: 0 auto;
                width: 80%;
                border-collapse: collapse;
            }

            .cover-table td {
                padding: 12px 20px;
                border-bottom: 1px solid #e5e7eb;
                text-align: left;
            }

            .cover-table .label {
                font-weight: bold;
                color: #6b7280;
                width: 40%;
            }

            .cover-table .value {
                color: #1f2937;
            }

            .risk-badge {
                display: inline-block;
                margin: 40px auto;
                padding: 15px 40px;
                color: white;
                font-size: 18pt;
                font-weight: bold;
                border-radius: 8px;
            }

            .cover-footer {
                margin-top: 60px;
                font-size: 9pt;
                color: #9ca3af;
            }

            /* Sections */
            .section { margin-bottom: 30px; }

            .section-title {
                font-size: 18pt;
                color: #dc2626;
                border-bottom: 2px solid #dc2626;
                padding-bottom: 8px;
                margin-bottom: 20px;
            }

            h2 {
                font-size: 13pt;
                color: #374151;
                margin-top: 20px;
            }

            h4 {
                font-size: 11pt;
                color: #374151;
                margin: 12px 0 6px 0;
            }

            /* Executive Box */
            .executive-box {
                background: #f9fafb;
                border-left: 4px solid #dc2626;
                padding: 20px;
                margin: 20px 0;
                border-radius: 4px;
            }

            /* Tables */
            .summary-table, .roadmap-table {
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
            }

            .summary-table th, .roadmap-table th {
                background: #1f2937;
                color: white;
                padding: 10px 12px;
                text-align: left;
                font-size: 10pt;
            }

            .summary-table td, .roadmap-table td {
                padding: 10px 12px;
                border-bottom: 1px solid #e5e7eb;
                font-size: 10pt;
            }

            .critical-row { background: #fef2f2; }
            .high-row { background: #fff7ed; }
            .medium-row { background: #fffbeb; }
            .low-row { background: #f0fdf4; }
            .total-row { background: #f3f4f6; }

            .info-table {
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
            }

            .info-table td {
                padding: 8px 12px;
                border-bottom: 1px solid #e5e7eb;
            }

            .info-label {
                font-weight: bold;
                color: #6b7280;
                width: 30%;
            }

            /* Badges */
            .badge {
                display: inline-block;
                padding: 3px 10px;
                border-radius: 4px;
                font-size: 9pt;
                font-weight: bold;
                color: white;
            }

            .badge.critical { background: #dc2626; }
            .badge.high { background: #ea580c; }
            .badge.medium { background: #d97706; }
            .badge.low { background: #16a34a; }

            .cvss-badge {
                display: inline-block;
                padding: 3px 10px;
                border-radius: 4px;
                font-size: 9pt;
                font-weight: bold;
                background: #1f2937;
                color: white;
                margin-left: 8px;
            }

            /* Finding Cards */
            .finding-card {
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                margin: 20px 0;
                padding: 20px;
                page-break-inside: avoid;
            }

            .critical-card { border-left: 5px solid #dc2626; }
            .high-card { border-left: 5px solid #ea580c; }
            .medium-card { border-left: 5px solid #d97706; }
            .low-card { border-left: 5px solid #16a34a; }

            .finding-header {
                display: flex;
                align-items: center;
                margin-bottom: 15px;
                flex-wrap: wrap;
            }

            .finding-number {
                font-size: 9pt;
                color: #9ca3af;
                margin-right: 12px;
            }

            .finding-title {
                font-size: 12pt;
                font-weight: bold;
                color: #1f2937;
                flex: 1;
            }

            .finding-table {
                width: 100%;
                border-collapse: collapse;
                margin: 10px 0;
            }

            .finding-table td {
                padding: 6px 10px;
                border-bottom: 1px solid #f3f4f6;
                font-size: 10pt;
            }

            .finding-label {
                font-weight: bold;
                color: #6b7280;
                width: 20%;
            }

            .evidence-box {
                background: #1f2937;
                color: #d1fae5;
                padding: 12px;
                border-radius: 6px;
                font-size: 9pt;
                white-space: pre-wrap;
                word-break: break-all;
            }

            code {
                font-family: monospace;
                font-size: 9pt;
                background: #f3f4f6;
                padding: 2px 6px;
                border-radius: 3px;
            }

            .methodology-list li {
                margin: 8px 0;
            }
        """
