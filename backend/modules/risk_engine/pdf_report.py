# backend/modules/risk_engine/pdf_report.py
# Module 8.5 — Professional PDF Report Generator
# pip install reportlab

import io
from datetime import datetime
from reportlab.lib              import colors
from reportlab.lib.pagesizes    import letter
from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units        import inch
from reportlab.platypus         import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums        import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes  import Drawing, Wedge, String, Rect
from reportlab.graphics         import renderPDF

# ── Colour palette ────────────────────────────────────────────────────────────
DARK_BG    = colors.HexColor("#0a0f1e")
BLUE       = colors.HexColor("#2563EB")
LIGHT_BLUE = colors.HexColor("#DBEAFE")
RED        = colors.HexColor("#DC2626")
LIGHT_RED  = colors.HexColor("#FEE2E2")
ORANGE     = colors.HexColor("#EA580C")
LIGHT_ORG  = colors.HexColor("#FFEDD5")
AMBER      = colors.HexColor("#D97706")
LIGHT_AMB  = colors.HexColor("#FEF3C7")
GREEN      = colors.HexColor("#16A34A")
LIGHT_GRN  = colors.HexColor("#DCFCE7")
SLATE      = colors.HexColor("#334155")
SLATE_LIGHT= colors.HexColor("#94a3b8")
WHITE      = colors.white
BLACK      = colors.HexColor("#111827")
LIGHT_GRAY = colors.HexColor("#F8FAFC")
MID_GRAY   = colors.HexColor("#E2E8F0")

SEV_COLORS = {
    "Critical": (RED,       LIGHT_RED),
    "High":     (ORANGE,    LIGHT_ORG),
    "Medium":   (AMBER,     LIGHT_AMB),
    "Low":      (BLUE,      LIGHT_BLUE),
    "None":     (GREEN,     LIGHT_GRN),
    "Info":     (SLATE,     LIGHT_GRAY),
}

GRADE_COLORS = {
    "A+": GREEN, "A": GREEN, "B": BLUE,
    "C": AMBER,  "D": ORANGE, "F": RED,
}


def _styles():
    base = getSampleStyleSheet()
    custom = {
        "Title":      ParagraphStyle("Title",      fontSize=28, textColor=WHITE,      fontName="Helvetica-Bold",  alignment=TA_CENTER, spaceAfter=6),
        "Subtitle":   ParagraphStyle("Subtitle",   fontSize=13, textColor=SLATE_LIGHT, fontName="Helvetica",      alignment=TA_CENTER, spaceAfter=4),
        "H1":         ParagraphStyle("H1",         fontSize=16, textColor=BLUE,        fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
                                     borderPad=4, borderColor=BLUE, borderWidth=0),
        "H2":         ParagraphStyle("H2",         fontSize=13, textColor=SLATE,       fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "H3":         ParagraphStyle("H3",         fontSize=11, textColor=BLACK,       fontName="Helvetica-Bold", spaceBefore=6, spaceAfter=3),
        "Body":       ParagraphStyle("Body",       fontSize=9,  textColor=BLACK,       fontName="Helvetica",      spaceAfter=4, leading=14),
        "Small":      ParagraphStyle("Small",      fontSize=8,  textColor=SLATE,       fontName="Helvetica",      spaceAfter=2, leading=11),
        "Code":       ParagraphStyle("Code",       fontSize=7.5, textColor=colors.HexColor("#1E3A5F"),
                                     fontName="Courier", spaceAfter=2, leading=11,
                                     backColor=colors.HexColor("#F0F4F8"), leftIndent=8, rightIndent=8),
        "BulletItem": ParagraphStyle("BulletItem", fontSize=9, textColor=BLACK, fontName="Helvetica",
                                     leftIndent=16, spaceAfter=3, bulletIndent=6, leading=13),
        "Label":      ParagraphStyle("Label",      fontSize=7.5, textColor=SLATE, fontName="Helvetica-Bold",
                                     spaceBefore=2, spaceAfter=1),
    }
    return custom


def _sev_badge_cell(severity: str) -> Table:
    """Small severity badge as a mini-table."""
    bg, _ = SEV_COLORS.get(severity, SEV_COLORS["Info"])
    t = Table([[severity]], colWidths=[0.8*inch], rowHeights=[0.2*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("TEXTCOLOR",  (0,0), (-1,-1), WHITE),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 7),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1), 2),
    ]))
    return t


def _cover_page(styles, report: dict) -> list:
    elems = []
    exec_s = report.get("executive_summary", {})
    grade  = report.get("overall_grade", "F")
    score  = report.get("overall_score", 0)
    grade_color = GRADE_COLORS.get(grade, RED)

    # Dark header block
    header_data = [[
        Paragraph(f'<font color="white"><b>E-WMEAP</b></font>', styles["Title"]),
    ]]
    header_table = Table(header_data, colWidths=[7*inch])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING", (0,0), (-1,-1), 24),
        ("BOTTOMPADDING",(0,0),(-1,-1), 16),
    ]))
    elems.append(header_table)
    elems.append(Spacer(1, 0.1*inch))

    # Report title
    elems.append(Paragraph("Security Assessment Report", ParagraphStyle(
        "RT", fontSize=20, textColor=SLATE, fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4
    )))
    elems.append(Paragraph(report.get("target", ""), ParagraphStyle(
        "URL", fontSize=11, textColor=BLUE, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=2
    )))
    elems.append(Paragraph(
        f"Scan Date: {report.get('scan_timestamp', '')[:10]}  |  Scan ID: {report.get('scan_id', '')}",
        ParagraphStyle("Meta", fontSize=9, textColor=SLATE_LIGHT, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=16)
    ))

    # Score + grade big display
    score_data = [[
        Paragraph(f'<font color="{grade_color.hexval()}" size="48"><b>{grade}</b></font>',
                  ParagraphStyle("GradeBig", fontSize=48, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f'<font size="9" color="{SLATE.hexval()}">SECURITY SCORE</font><br/>'
                  f'<font size="36"><b>{score}</b></font><br/>'
                  f'<font size="9" color="{SLATE_LIGHT.hexval()}">/100</font>',
                  ParagraphStyle("ScoreBig", fontSize=36, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f'<font size="9" color="{SLATE.hexval()}">RISK LEVEL</font><br/>'
                  f'<font size="13"><b>{exec_s.get("overall_risk_level","")}</b></font>',
                  ParagraphStyle("RiskBig", fontSize=13, fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]]
    score_table = Table(score_data, colWidths=[2.3*inch, 2.3*inch, 2.3*inch])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), LIGHT_GRAY),
        ("BOX",        (0,0), (-1,-1), 1, MID_GRAY),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, MID_GRAY),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 16),
        ("BOTTOMPADDING",(0,0),(-1,-1), 16),
    ]))
    elems.append(score_table)
    elems.append(Spacer(1, 0.15*inch))

    # Severity summary bar
    sev_counts = report.get("severity_counts", {})
    sev_data = [[sev, str(sev_counts.get(sev, 0))]
                for sev in ("Critical", "High", "Medium", "Low")]
    sev_table = Table(
        [[Paragraph(f'<b>{row[0]}</b>', ParagraphStyle("SC", fontSize=9, fontName="Helvetica-Bold",
                    textColor=SEV_COLORS[row[0]][0], alignment=TA_CENTER)),
          Paragraph(f'<b>{row[1]}</b>', ParagraphStyle("SN", fontSize=16, fontName="Helvetica-Bold",
                    textColor=SEV_COLORS[row[0]][0], alignment=TA_CENTER))]
         for row in sev_data],
        colWidths=[1.75*inch] * 4,
        rowHeights=None,
    )
    # Rebuild as 1 row 8 cols
    row = []
    for sev in ("Critical","High","Medium","Low"):
        count = sev_counts.get(sev, 0)
        bg, _ = SEV_COLORS[sev]
        row.extend([
            Paragraph(f'<font color="white"><b>{sev}</b></font>',
                      ParagraphStyle("sh", fontSize=8, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph(f'<font color="white"><b>{count}</b></font>',
                      ParagraphStyle("sn", fontSize=20, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        ])

    sev_table2 = Table([row[:8]], colWidths=[0.875*inch]*8)
    sev_colors_style = []
    for i, sev in enumerate(("Critical","High","Medium","Low")):
        bg, _ = SEV_COLORS[sev]
        sev_colors_style.extend([
            ("BACKGROUND", (i*2, 0), (i*2+1, 0), bg),
        ])
    sev_table2.setStyle(TableStyle(sev_colors_style + [
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    elems.append(sev_table2)
    elems.append(Spacer(1, 0.15*inch))

    # Chains
    if report.get("total_chains", 0) > 0:
        elems.append(Paragraph(
            f"⛓ {report['total_chains']} Vulnerability Chain(s) Detected",
            ParagraphStyle("Chain", fontSize=10, textColor=RED, fontName="Helvetica-Bold",
                           alignment=TA_CENTER, spaceAfter=4)
        ))

    elems.append(PageBreak())
    return elems


def _exec_summary_section(styles, report: dict) -> list:
    elems = []
    exec_s = report.get("executive_summary", {})

    elems.append(Paragraph("Executive Summary", styles["H1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=8))

    # Narrative
    elems.append(Paragraph("Assessment Overview", styles["H2"]))
    elems.append(Paragraph(exec_s.get("narrative", ""), styles["Body"]))
    elems.append(Spacer(1, 0.1*inch))

    # Top findings table
    top = exec_s.get("top_findings", [])
    if top:
        elems.append(Paragraph("Top Critical Findings", styles["H2"]))
        rows = [["Finding", "Severity", "CVSS", "Description"]]
        for f in top:
            bg, _ = SEV_COLORS.get(f["severity"], SEV_COLORS["Info"])
            rows.append([
                Paragraph(f.get("title", ""), styles["Small"]),
                Paragraph(f'<font color="white"><b>{f["severity"]}</b></font>',
                          ParagraphStyle("SB", fontSize=8, fontName="Helvetica-Bold", alignment=TA_CENTER)),
                Paragraph(str(f.get("cvss_score", "")), styles["Small"]),
                Paragraph(f.get("description", "")[:120], styles["Small"]),
            ])
        t = Table(rows, colWidths=[1.6*inch, 0.8*inch, 0.5*inch, 3.9*inch])
        ts = [
            ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
            ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.3, MID_GRAY),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]
        for i, f in enumerate(top, 1):
            bg, _ = SEV_COLORS.get(f["severity"], SEV_COLORS["Info"])
            ts.append(("BACKGROUND", (1, i), (1, i), bg))
        t.setStyle(TableStyle(ts))
        elems.append(t)
        elems.append(Spacer(1, 0.1*inch))

    # Immediate actions
    actions = exec_s.get("immediate_actions", [])
    if actions:
        elems.append(Paragraph("Immediate Actions Required", styles["H2"]))
        for i, action in enumerate(actions, 1):
            elems.append(Paragraph(f"{i}. {action}", styles["BulletItem"]))

    elems.append(PageBreak())
    return elems


def _findings_section(styles, report: dict) -> list:
    elems = []
    elems.append(Paragraph("Technical Findings", styles["H1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=8))

    findings = report.get("findings", [])
    if not findings:
        elems.append(Paragraph("No findings to report.", styles["Body"]))
        return elems

    for f in findings:
        sev = f.get("severity", "Info")
        bg, light_bg = SEV_COLORS.get(sev, SEV_COLORS["Info"])
        cvss = f.get("cvss", {})

        # Finding header
        header_data = [[
            Paragraph(f'<font color="white"><b>{f.get("type","").replace("_"," ")}</b></font>',
                      ParagraphStyle("FH", fontSize=9, fontName="Helvetica-Bold")),
            Paragraph(f'<font color="white"><b>{f.get("module","")}</b></font>',
                      ParagraphStyle("FM", fontSize=8, fontName="Helvetica", alignment=TA_RIGHT)),
        ]]
        ht = Table(header_data, colWidths=[4.5*inch, 2.3*inch])
        ht.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), SLATE),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))

        # Detail rows
        detail_rows = []
        if f.get("description"):
            detail_rows.append(["Description", f.get("description", "")])
        if cvss.get("score"):
            detail_rows.append(["CVSS Score",
                f'{cvss["score"]} ({cvss.get("severity","")}) — {cvss.get("vector","")}'])
        if f.get("recommendation"):
            detail_rows.append(["Remediation", f.get("recommendation", "")])

        detail_data = [
            [Paragraph(row[0], styles["Label"]),
             Paragraph(str(row[1])[:300], styles["Small"])]
            for row in detail_rows
        ]
        if detail_data:
            dt = Table(detail_data, colWidths=[1.2*inch, 5.6*inch])
            dt.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), light_bg),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ("TOPPADDING",    (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                ("LEFTPADDING",   (0,0), (0,-1), 8),
                ("BOX",           (0,0), (-1,-1), 0.3, MID_GRAY),
            ]))
            elems.append(KeepTogether([ht, dt, Spacer(1, 0.08*inch)]))
        else:
            elems.append(KeepTogether([ht, Spacer(1, 0.08*inch)]))

    return elems


def _chains_section(styles, report: dict) -> list:
    chains = report.get("chains", [])
    if not chains:
        return []

    elems = []
    elems.append(PageBreak())
    elems.append(Paragraph("Vulnerability Chains", styles["H1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=RED, spaceAfter=8))
    elems.append(Paragraph(
        "The following vulnerability chains were detected — individual findings that combine to create a more severe attack path.",
        styles["Body"]
    ))
    elems.append(Spacer(1, 0.1*inch))

    for c in chains:
        elems.append(Paragraph(f"⛓ {c.get('name','')}", styles["H2"]))
        rows = [
            ["Severity",    c.get("severity","")],
            ["CVSS Score",  f"{c.get('cvss',{}).get('score','')} — {c.get('cvss',{}).get('vector','')}"],
            ["Components",  " + ".join(c.get("components",[]))],
            ["Description", c.get("description","")],
            ["Impact",      c.get("impact","")],
            ["Remediation", c.get("remediation","")],
        ]
        t = Table(
            [[Paragraph(r[0], styles["Label"]), Paragraph(str(r[1]), styles["Small"])] for r in rows],
            colWidths=[1.2*inch, 5.6*inch]
        )
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), LIGHT_RED),
            ("BOX",           (0,0), (-1,-1), 0.5, RED),
            ("INNERGRID",     (0,0), (-1,-1), 0.2, colors.HexColor("#FECACA")),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (0,-1), 8),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 0.12*inch))

    return elems


def _remediation_section(styles, report: dict) -> list:
    priority = report.get("priority_list", [])
    if not priority:
        return []

    elems = []
    elems.append(PageBreak())
    elems.append(Paragraph("Remediation Priority List", styles["H1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=8))

    rows = [["#", "Finding", "Module", "Severity", "CVSS", "Recommendation"]]
    for i, item in enumerate(priority, 1):
        bg, _ = SEV_COLORS.get(item["severity"], SEV_COLORS["Info"])
        rows.append([
            str(i),
            Paragraph(item.get("title","")[:40], styles["Small"]),
            Paragraph(item.get("module",""), styles["Small"]),
            Paragraph(f'<b>{item["severity"]}</b>',
                      ParagraphStyle("SB2", fontSize=7, fontName="Helvetica-Bold",
                                     textColor=bg, alignment=TA_CENTER)),
            str(item.get("cvss_score","")),
            Paragraph(item.get("recommendation","")[:80], styles["Small"]),
        ])

    t = Table(rows, colWidths=[0.25*inch, 1.5*inch, 1.1*inch, 0.75*inch, 0.4*inch, 2.8*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0), 7),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
        ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, MID_GRAY),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("FONTSIZE",      (0,0), (-1,-1), 7),
    ]))
    elems.append(t)
    return elems


def _threat_intel_section(styles, report: dict) -> list:
    ti = report.get("threat_intel", {})
    if not ti:
        return []

    elems = []
    elems.append(PageBreak())
    elems.append(Paragraph("Threat Intelligence", styles["H1"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=BLUE, spaceAfter=8))

    for api_name, key in [("Shodan", "shodan"), ("AlienVault OTX", "otx"), ("AbuseIPDB", "abuseipdb")]:
        data = ti.get(key, {})
        if not data.get("available"):
            elems.append(Paragraph(
                f"{api_name}: Not configured — set {api_name.upper().replace(' ','_')}_API_KEY",
                styles["Small"]
            ))
            continue

        elems.append(Paragraph(api_name, styles["H2"]))
        note = data.get("risk_note", "")
        if note:
            elems.append(Paragraph(note, styles["Body"]))

        rows = []
        if key == "shodan":
            if data.get("indexed"):
                rows = [
                    ["Organisation", data.get("org","")],
                    ["Country",      data.get("country","")],
                    ["Open Ports",   ", ".join(str(p) for p in data.get("ports",[])[:10])],
                    ["Known CVEs",   ", ".join(data.get("vulns",[])[:5])],
                    ["Last Seen",    data.get("last_seen","")],
                ]
        elif key == "otx":
            rows = [
                ["Threat Pulses",  str(data.get("pulse_count","0"))],
                ["IP Reputation",  data.get("ip_reputation","unknown")],
            ]
        elif key == "abuseipdb":
            rows = [
                ["Abuse Score",    f'{data.get("abuse_score",0)}%'],
                ["Total Reports",  str(data.get("total_reports",0))],
                ["ISP",            data.get("isp","")],
                ["Usage Type",     data.get("usage_type","")],
            ]

        if rows:
            t = Table(
                [[Paragraph(r[0], styles["Label"]), Paragraph(str(r[1]), styles["Small"])] for r in rows],
                colWidths=[1.5*inch, 5.3*inch]
            )
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GRAY),
                ("BOX",           (0,0), (-1,-1), 0.5, MID_GRAY),
                ("INNERGRID",     (0,0), (-1,-1), 0.2, MID_GRAY),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING",   (0,0), (0,-1), 8),
            ]))
            elems.append(t)
            elems.append(Spacer(1, 0.08*inch))

    return elems


def generate_pdf(report: dict) -> bytes:
    """Generate complete PDF report. Returns bytes."""
    buf    = io.BytesIO()
    styles = _styles()

    def on_first_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE_LIGHT)
        canvas.drawString(0.5*inch, 0.3*inch,
                          f"E-WMEAP Security Report | {report.get('target','')} | {report.get('scan_timestamp','')[:10]}")
        canvas.drawRightString(7.5*inch, 0.3*inch, "CONFIDENTIAL")
        canvas.restoreState()

    def on_later_pages(canvas, doc):
        on_first_page(canvas, doc)
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE_LIGHT)
        canvas.drawRightString(7.5*inch, 0.3*inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.6*inch, rightMargin=0.6*inch,
        topMargin=0.6*inch,  bottomMargin=0.5*inch,
    )

    story = []
    story.extend(_cover_page(styles, report))
    story.extend(_exec_summary_section(styles, report))
    story.extend(_findings_section(styles, report))
    story.extend(_chains_section(styles, report))
    story.extend(_remediation_section(styles, report))
    story.extend(_threat_intel_section(styles, report))

    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    return buf.getvalue()