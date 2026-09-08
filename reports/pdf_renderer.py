# reports/pdf_renderer.py

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm

class PDFRenderer:

    @staticmethod
    def render(findings, dependencies, meta, output_path):

        styles = getSampleStyleSheet()
        body = styles["BodyText"]

        title = ParagraphStyle(
            'title',
            parent=styles['Heading1'],
            fontSize=22,
            textColor="#0b3d91",
            spaceAfter=20
        )

        finding_title = ParagraphStyle(
            'ftitle',
            fontSize=13,
            textColor="#d62828",
            spaceAfter=8
        )

        doc = SimpleDocTemplate(output_path, pagesize=A4)
        elements = []

        elements.append(Paragraph("Hexora Enterprise SAST Report", title))
        elements.append(Paragraph(f"Generated: {meta['timestamp']}", body))
        elements.append(Paragraph(f"Total Files: {meta['total_files']}", body))
        elements.append(Paragraph(f"Total Findings: {meta['total_findings']}", body))
        elements.append(Spacer(1, 20))

        # Summary table
        sev = {"critical":0, "high":0, "medium":0, "low":0}
        for f in findings: sev[f["severity"]] += 1

        data = [
            ["Severity", "Count"],
            ["Critical", sev["critical"]],
            ["High", sev["high"]],
            ["Medium", sev["medium"]],
            ["Low", sev["low"]],
        ]

        table = Table(data, colWidths=[5*cm, 5*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0b3d91")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f5f5f5")),
            ('BOX',(0,0),(-1,-1),1,colors.gray),
            ('GRID',(0,0),(-1,-1),0.3,colors.gray)
        ]))
        elements.append(table)
        elements.append(PageBreak())

        # FINDINGS
        for f in findings:
            elements.append(Paragraph(f"{f['rule']} – [{f['severity'].upper()}]", finding_title))
            elements.append(Paragraph(f"<b>Category:</b> {f['category']}", body))
            elements.append(Paragraph(f"<b>File:</b> {f['file']}", body))
            elements.append(Paragraph(f"<b>Line:</b> {f['line_no']}", body))
            elements.append(Paragraph(f"<b>Description:</b> {f['description']}", body))
            elements.append(Paragraph(f"<b>Remediation:</b> {f['remediation']}", body))

            code = f.get("line", "").replace("<", "&lt;")
            codeblock = Paragraph(
                f"<font face='Courier'>{code}</font>",
                ParagraphStyle("CodeBlock",
                    fontSize=8,
                    textColor=colors.black,
                    backColor=colors.HexColor("#efefef"),
                    leading=10,
                    leftIndent=6,
                    rightIndent=6,
                )
            )
            elements.append(codeblock)
            elements.append(Spacer(1, 18))
            elements.append(PageBreak())

        doc.build(elements)
        return output_path