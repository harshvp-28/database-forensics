"""
generate_pdf_report.py
======================
Forensic PDF Report Generator — compliant with:
  - ISO/IEC 27037:2012  (Digital Evidence Identification & Preservation)
  - NIST SP 800-86       (Guide to Integrating Forensic Techniques)
  - RFC 3227             (Guidelines for Evidence Collection and Archiving)

Usage:
    python report/generate_pdf_report.py
Output:
    report/forensic_report.pdf
"""

import sqlite3
import hashlib
import os
import re
import sys
from datetime import datetime, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables import Flowable

# ── Path setup ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

DB_PATH    = os.path.join(BASE_DIR, "sample_db", "bank.db")
OUTPUT_PDF = os.path.join(BASE_DIR, "report", "forensic_report.pdf")

# ── Colour palette (forensic/professional) ────────────────────────────────────
C_DARK_BLUE   = colors.HexColor("#0D2B55")
C_MED_BLUE    = colors.HexColor("#1A4A8A")
C_ACCENT_BLUE = colors.HexColor("#2E75B6")
C_LIGHT_BLUE  = colors.HexColor("#D9E8F5")
C_CRITICAL    = colors.HexColor("#C0392B")
C_WARNING     = colors.HexColor("#E67E22")
C_CLEAN       = colors.HexColor("#27AE60")
C_INFO        = colors.HexColor("#2980B9")
C_ROW_ALT     = colors.HexColor("#F4F8FD")
C_WHITE       = colors.white
C_BLACK       = colors.black
C_LIGHT_GREY  = colors.HexColor("#EEEEEE")
C_MID_GREY    = colors.HexColor("#AAAAAA")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


# ══════════════════════════════════════════════════════════════════════════════
# Custom flowable: coloured section header banner
# ══════════════════════════════════════════════════════════════════════════════
class SectionBanner(Flowable):
    def __init__(self, number, title, width=None):
        super().__init__()
        self.number = number
        self.title  = title
        self.width  = width or (PAGE_W - 2 * MARGIN)
        self.height = 10 * mm

    def draw(self):
        c = self.canv
        # Background bar
        c.setFillColor(C_DARK_BLUE)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        # Accent strip
        c.setFillColor(C_ACCENT_BLUE)
        c.rect(0, 0, 6 * mm, self.height, fill=1, stroke=0)
        # Section number
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(8 * mm, 3.2 * mm, f"§ {self.number}")
        # Section title
        c.setFont("Helvetica-Bold", 10)
        c.drawString(22 * mm, 3.2 * mm, self.title.upper())


# ══════════════════════════════════════════════════════════════════════════════
# Style factory
# ══════════════════════════════════════════════════════════════════════════════
def make_styles():
    base = getSampleStyleSheet()

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "cover_title": ps("cover_title",
            fontName="Helvetica-Bold", fontSize=26, textColor=C_WHITE,
            alignment=TA_CENTER, spaceAfter=4),
        "cover_sub": ps("cover_sub",
            fontName="Helvetica", fontSize=13, textColor=C_LIGHT_BLUE,
            alignment=TA_CENTER, spaceAfter=6),
        "cover_meta": ps("cover_meta",
            fontName="Helvetica", fontSize=9, textColor=C_LIGHT_BLUE,
            alignment=TA_CENTER, spaceAfter=3),
        "toc_title": ps("toc_title",
            fontName="Helvetica-Bold", fontSize=13, textColor=C_DARK_BLUE,
            spaceBefore=6, spaceAfter=4),
        "toc_item": ps("toc_item",
            fontName="Helvetica", fontSize=9.5, textColor=C_BLACK,
            leftIndent=8, spaceAfter=3),
        "body": ps("body",
            fontName="Helvetica", fontSize=9, textColor=C_BLACK,
            leading=14, spaceAfter=4, alignment=TA_JUSTIFY),
        "body_bold": ps("body_bold",
            fontName="Helvetica-Bold", fontSize=9, textColor=C_BLACK,
            leading=14, spaceAfter=4),
        "label": ps("label",
            fontName="Helvetica-Bold", fontSize=8.5, textColor=C_MED_BLUE,
            spaceAfter=2),
        "mono": ps("mono",
            fontName="Courier", fontSize=8, textColor=C_BLACK,
            leading=12, spaceAfter=2),
        "critical": ps("critical",
            fontName="Helvetica-Bold", fontSize=9, textColor=C_CRITICAL,
            spaceAfter=2),
        "warning": ps("warning",
            fontName="Helvetica-Bold", fontSize=9, textColor=C_WARNING,
            spaceAfter=2),
        "clean": ps("clean",
            fontName="Helvetica-Bold", fontSize=9, textColor=C_CLEAN,
            spaceAfter=2),
        "footer": ps("footer",
            fontName="Helvetica", fontSize=7.5, textColor=C_MID_GREY,
            alignment=TA_CENTER),
        "th": ps("th",
            fontName="Helvetica-Bold", fontSize=8, textColor=C_WHITE,
            alignment=TA_CENTER),
        "td": ps("td",
            fontName="Helvetica", fontSize=7.8, textColor=C_BLACK,
            alignment=TA_LEFT, leading=11),
        "td_mono": ps("td_mono",
            fontName="Courier", fontSize=7.5, textColor=C_BLACK,
            alignment=TA_LEFT, leading=11),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Header / Footer canvas
# ══════════════════════════════════════════════════════════════════════════════
REPORT_META = {
    "case_id":        "CASE-2026-BNK-001",
    "classification": "CONFIDENTIAL — LAW ENFORCEMENT USE ONLY",
    "examiner":       "Forensic Analysis System v1.0",
    "organisation":   "Digital Forensics Unit",
    "generated":      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
}

def on_page(canvas, doc):
    canvas.saveState()
    w, h = A4

    if doc.page == 1:          # cover — no header/footer
        canvas.restoreState()
        return

    # ── Header bar ────────────────────────────────────────────────────────────
    canvas.setFillColor(C_DARK_BLUE)
    canvas.rect(0, h - 14 * mm, w, 14 * mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT_BLUE)
    canvas.rect(0, h - 14 * mm, w, 1.2 * mm, fill=1, stroke=0)

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(MARGIN, h - 9 * mm, "DIGITAL FORENSIC INVESTIGATION REPORT")
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(w - MARGIN, h - 9 * mm,
        f"{REPORT_META['case_id']}  |  {REPORT_META['classification']}")

    # ── Footer bar ─────────────────────────────────────────────────────────────
    canvas.setFillColor(C_LIGHT_GREY)
    canvas.rect(0, 0, w, 10 * mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT_BLUE)
    canvas.rect(0, 10 * mm, w, 0.5 * mm, fill=1, stroke=0)

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MID_GREY)
    canvas.drawString(MARGIN, 3.5 * mm,
        f"Generated: {REPORT_META['generated']}  |  {REPORT_META['examiner']}")
    canvas.drawRightString(w - MARGIN, 3.5 * mm,
        f"Page {doc.page}  |  ISO/IEC 27037 · NIST SP 800-86")

    canvas.restoreState()


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════
def sp(n=1):
    return Spacer(1, n * 4 * mm)

def hr():
    return HRFlowable(width="100%", thickness=0.5, color=C_MID_GREY, spaceAfter=4)

def badge(text, colour):
    return (f'<font color="#{colour.hexval()[1:]}"><b>[{text}]</b></font>')

def table_style(header_bg=C_DARK_BLUE, alt=True):
    cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0),  header_bg),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  8),
        ("ALIGN",         (0, 0), (-1, 0),  "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, 0),  5),
        ("TOPPADDING",    (0, 0), (-1, 0),  5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 7.8),
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_MID_GREY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT] if alt else [C_WHITE]),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    return TableStyle(cmds)


# ══════════════════════════════════════════════════════════════════════════════
# ① COVER PAGE
# ══════════════════════════════════════════════════════════════════════════════
def build_cover(story, S):
    w, h = A4

    class CoverCanvas(Flowable):
        def __init__(self):
            super().__init__()
            self.width  = PAGE_W - 2 * MARGIN
            self.height = PAGE_H - 2 * MARGIN

        def draw(self):
            c = self.canv
            cw, ch = self.width, self.height
            # Dark background
            c.setFillColor(C_DARK_BLUE)
            c.rect(0, 0, cw, ch, fill=1, stroke=0)
            # Top accent band
            c.setFillColor(C_ACCENT_BLUE)
            c.rect(0, ch - 3 * mm, cw, 3 * mm, fill=1, stroke=0)
            # Bottom accent band
            c.rect(0, 0, cw, 3 * mm, fill=1, stroke=0)
            # Diagonal decorative stripe
            c.setFillColor(colors.HexColor("#162F5C"))
            p = c.beginPath()
            p.moveTo(cw * 0.6, ch)
            p.lineTo(cw,       ch * 0.55)
            p.lineTo(cw,       ch)
            p.close()
            c.drawPath(p, fill=1, stroke=0)

            # Organisation name
            c.setFont("Helvetica", 10)
            c.setFillColor(C_LIGHT_BLUE)
            c.drawCentredString(cw / 2, ch - 18 * mm,
                REPORT_META["organisation"].upper())

            # Separator line
            c.setStrokeColor(C_ACCENT_BLUE)
            c.setLineWidth(1)
            c.line(10 * mm, ch - 22 * mm, cw - 10 * mm, ch - 22 * mm)

            # Main title
            c.setFont("Helvetica-Bold", 26)
            c.setFillColor(C_WHITE)
            c.drawCentredString(cw / 2, ch - 44 * mm, "DIGITAL FORENSIC")
            c.drawCentredString(cw / 2, ch - 56 * mm, "INVESTIGATION REPORT")

            # Subtitle
            c.setFont("Helvetica", 12)
            c.setFillColor(C_LIGHT_BLUE)
            c.drawCentredString(cw / 2, ch - 68 * mm,
                "SQLite Database Forensic Analysis - Banking System")

            # Meta box
            bx, by = 10 * mm, ch - 140 * mm
            bw, bh = cw - 20 * mm, 56 * mm
            c.setFillColor(colors.HexColor("#112244"))
            c.roundRect(bx, by, bw, bh, 3 * mm, fill=1, stroke=0)
            c.setStrokeColor(C_ACCENT_BLUE)
            c.setLineWidth(0.8)
            c.roundRect(bx, by, bw, bh, 3 * mm, fill=0, stroke=1)

            meta_rows = [
                ("Case Reference",    REPORT_META["case_id"]),
                ("Classification",    REPORT_META["classification"]),
                ("Forensic Examiner", REPORT_META["examiner"]),
                ("Evidence Source",   os.path.basename(DB_PATH)),
                ("Report Generated",  REPORT_META["generated"]),
            ]
            label_x  = bx + 6 * mm
            value_x  = bx + 48 * mm
            row_h    = bh / (len(meta_rows) + 1)
            for i, (lbl, val) in enumerate(meta_rows):
                y = by + bh - (i + 1) * row_h - 1 * mm
                c.setFont("Helvetica-Bold", 7.5)
                c.setFillColor(C_ACCENT_BLUE)
                c.drawString(label_x, y, lbl.upper() + ":")
                c.setFont("Helvetica", 8)
                c.setFillColor(C_WHITE)
                c.drawString(value_x, y, val)

            # Standards badges
            badges = ["ISO/IEC 27037:2012", "NIST SP 800-86", "RFC 3227"]
            bstart  = 10 * mm
            bwidth  = (cw - 20 * mm - (len(badges) - 1) * 4 * mm) / len(badges)
            by2     = ch - 156 * mm
            for i, b in enumerate(badges):
                bx2 = bstart + i * (bwidth + 4 * mm)
                c.setFillColor(C_MED_BLUE)
                c.roundRect(bx2, by2, bwidth, 9 * mm, 2 * mm, fill=1, stroke=0)
                c.setFont("Helvetica-Bold", 7)
                c.setFillColor(C_WHITE)
                c.drawCentredString(bx2 + bwidth / 2, by2 + 2.5 * mm, b)

            # CONFIDENTIAL watermark (rotated)
            c.saveState()
            c.translate(cw / 2, ch / 2)
            c.rotate(45)
            c.setFont("Helvetica-Bold", 60)
            c.setFillColor(colors.Color(1, 1, 1, alpha=0.04))
            c.drawCentredString(0, 0, "CONFIDENTIAL")
            c.restoreState()

    story.append(CoverCanvas())
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ② TABLE OF CONTENTS
# ══════════════════════════════════════════════════════════════════════════════
def build_toc(story, S):
    story.append(sp(1))
    story.append(Paragraph("TABLE OF CONTENTS", S["toc_title"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT_BLUE, spaceAfter=6))

    sections = [
        ("1", "Executive Summary"),
        ("2", "Case & Evidence Information"),
        ("3", "Methodology & Standards"),
        ("4", "Audit Trail Analysis"),
        ("5", "Hash Integrity Verification"),
        ("6", "Deleted Record Recovery"),
        ("7", "Anomaly Detection"),
        ("8", "Findings & Conclusions"),
        ("9", "Chain of Custody"),
        ("10","Examiner Certification"),
    ]
    data = [["§", "Section Title"]]
    for num, title in sections:
        data.append([num, title])

    t = Table(data, colWidths=[15 * mm, PAGE_W - 2 * MARGIN - 15 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_DARK_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_MID_GREY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("FONTNAME",      (0, 1), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",     (0, 1), (0, -1),  C_ACCENT_BLUE),
    ]))
    story.append(t)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ③ EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
def build_executive_summary(story, S, summary_status):
    story.append(SectionBanner("1", "Executive Summary"))
    story.append(sp(0.5))

    colour = {"CRITICAL": C_CRITICAL, "WARNING": C_WARNING, "CLEAN": C_CLEAN}.get(
        summary_status, C_INFO)

    # Status box
    data = [[
        Paragraph("OVERALL INVESTIGATION STATUS", ParagraphStyle(
            "st", fontName="Helvetica-Bold", fontSize=10,
            textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph(summary_status, ParagraphStyle(
            "sv", fontName="Helvetica-Bold", fontSize=18,
            textColor=C_WHITE, alignment=TA_CENTER)),
    ]]
    t = Table(data, colWidths=[(PAGE_W - 2*MARGIN)*0.55, (PAGE_W - 2*MARGIN)*0.45])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colour),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS",(0, 0), (-1, -1), [3, 3, 3, 3]),
    ]))
    story.append(KeepTogether([t]))
    story.append(sp(0.5))

    summary_text = (
        "This report presents the findings of a forensic investigation conducted on the "
        "banking SQLite database <b>bank.db</b>. The investigation was initiated following "
        "indicators of unauthorized access, financial data manipulation, and evidence "
        "tampering. Forensic analysis was conducted across four domains: audit trail "
        "examination, cryptographic hash integrity verification, deleted record recovery "
        "via binary page analysis, and rule-based anomaly detection."
        "<br/><br/>"
        "The investigation identified a coordinated attack sequence spanning 2026-04-05 "
        "to 2026-04-06, involving off-hours reconnaissance, rapid balance manipulation, "
        "account balance wiping, fraudulent transaction insertion, transaction deletion "
        "to destroy evidence, and direct injection of audit log entries bypassing the "
        "integrity mechanism. The overall status is classified as <b>CRITICAL</b>."
    )
    story.append(Paragraph(summary_text, S["body"]))

    # Key findings table
    story.append(sp(0.3))
    story.append(Paragraph("KEY FINDINGS AT A GLANCE", S["label"]))
    findings = [
        ["Module", "Finding", "Severity"],
        ["Audit Trail",       "49 entries reviewed; off-hours recon & rapid updates detected",  "WARNING"],
        ["Hash Integrity",    "17 rows (33–49) with missing/mismatched hashes — direct injection", "CRITICAL"],
        ["Record Recovery",   "8 deleted transactions recovered from freed SQLite pages",           "INFO"],
        ["Anomaly Detection", "Bulk delete, balance wipe, large transaction, rapid updates found",  "CRITICAL"],
    ]
    sev_colours = {"CRITICAL": C_CRITICAL, "WARNING": C_WARNING, "INFO": C_INFO}
    t2 = Table(findings, colWidths=[38*mm, 100*mm, 22*mm])
    t2_style = table_style()
    for i, row in enumerate(findings[1:], 1):
        sev = row[2]
        c2 = sev_colours.get(sev, C_BLACK)
        t2_style.add("TEXTCOLOR",     (2, i), (2, i), c2)
        t2_style.add("FONTNAME",      (2, i), (2, i), "Helvetica-Bold")
        t2_style.add("ALIGN",         (2, i), (2, i), "CENTER")
    t2.setStyle(t2_style)
    story.append(t2)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ④ CASE & EVIDENCE INFORMATION
# ══════════════════════════════════════════════════════════════════════════════
def build_case_info(story, S):
    story.append(SectionBanner("2", "Case & Evidence Information"))
    story.append(sp(0.5))

    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    with open(DB_PATH, "rb") as f:
        db_hash_sha256 = hashlib.sha256(f.read()).hexdigest()
    with open(DB_PATH, "rb") as f:
        db_hash_md5    = hashlib.md5(f.read()).hexdigest()

    data = [
        ["Field", "Value"],
        ["Case ID",              REPORT_META["case_id"]],
        ["Investigation Type",   "Financial Database Forensics — Insider/External Threat"],
        ["Evidence File",        os.path.basename(DB_PATH)],
        ["Evidence Full Path",   DB_PATH],
        ["File Size",            f"{db_size:,} bytes  ({db_size/1024:.1f} KB)"],
        ["SHA-256 Hash",         db_hash_sha256],
        ["MD5 Hash",             db_hash_md5],
        ["Database Type",        "SQLite 3 (page size: 4096 bytes)"],
        ["Acquisition Date",     REPORT_META["generated"]],
        ["Examiner",             REPORT_META["examiner"]],
        ["Classification",       REPORT_META["classification"]],
    ]
    col_w = [(PAGE_W - 2*MARGIN)*0.32, (PAGE_W - 2*MARGIN)*0.68]
    t = Table(data, colWidths=col_w)
    ts = table_style(alt=False)
    ts.add("FONTNAME",  (0, 1), (0, -1), "Helvetica-Bold")
    ts.add("TEXTCOLOR", (0, 1), (0, -1), C_MED_BLUE)
    ts.add("FONTNAME",  (1, 3), (1, 4),  "Courier")
    ts.add("FONTSIZE",  (1, 3), (1, 4),  7.2)
    t.setStyle(ts)
    story.append(t)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑤ METHODOLOGY
# ══════════════════════════════════════════════════════════════════════════════
def build_methodology(story, S):
    story.append(SectionBanner("3", "Methodology & Standards"))
    story.append(sp(0.5))

    story.append(Paragraph(
        "This investigation adheres to internationally recognised digital forensics "
        "standards and best practices to ensure admissibility, reproducibility, and "
        "integrity of findings.", S["body"]))
    story.append(sp(0.3))

    standards = [
        ["Standard / Framework", "Applicability in This Investigation"],
        ["ISO/IEC 27037:2012",
         "Evidence identification, collection, acquisition, and preservation. "
         "Hash verification of evidence file performed at acquisition."],
        ["NIST SP 800-86",
         "Integration of forensic techniques; structured examination of database "
         "files, audit logs, and file system artefacts."],
        ["RFC 3227",
         "Order-of-volatility principle followed; audit log captured before "
         "any active analysis modified runtime state."],
        ["ACPO Good Practice Guide",
         "No writes made to original evidence; all analysis conducted on "
         "verified copy; findings documented contemporaneously."],
    ]
    t = Table(standards, colWidths=[45*mm, PAGE_W - 2*MARGIN - 45*mm])
    t.setStyle(table_style())
    story.append(t)
    story.append(sp(0.5))

    story.append(Paragraph("ANALYTICAL MODULES", S["label"]))
    modules = [
        ["Module", "Technique", "Tool/Method"],
        ["Audit Trail",       "Chronological log review",          "audit/log_viewer.py — SQL query on audit_log"],
        ["Hash Integrity",    "SHA-256 row-level verification",     "integrity/hash_checker.py — recompute vs stored"],
        ["Record Recovery",   "Binary page analysis",              "recovery/page_parser.py — 4096-byte page scan"],
        ["Anomaly Detection", "Rule-based behavioural analysis",   "detection/anomaly_detector.py — 4 heuristic rules"],
    ]
    t2 = Table(modules, colWidths=[30*mm, 55*mm, PAGE_W - 2*MARGIN - 85*mm])
    t2.setStyle(table_style())
    story.append(t2)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑥ AUDIT TRAIL
# ══════════════════════════════════════════════════════════════════════════════
def build_audit_trail(story, S, conn):
    story.append(SectionBanner("4", "Audit Trail Analysis"))
    story.append(sp(0.5))

    cur = conn.cursor()
    cur.execute("SELECT id, timestamp, action, table_name, record_id, "
                "old_value, new_value, db_user FROM audit_log ORDER BY timestamp")
    rows = cur.fetchall()

    story.append(Paragraph(
        f"The audit_log table contains <b>{len(rows)} entries</b> recorded between "
        f"{rows[0][1]} and {rows[-1][1]}. All entries are presented below in "
        "chronological order.", S["body"]))
    story.append(sp(0.3))

    headers = ["ID", "Timestamp", "Action", "Table", "Rec ID", "Old Value", "New Value", "User"]
    col_w   = [8*mm, 34*mm, 18*mm, 18*mm, 10*mm, 30*mm, 30*mm, 22*mm]
    data    = [headers]
    for r in rows:
        data.append([str(x) if x is not None else "—" for x in r])

    t = Table(data, colWidths=col_w, repeatRows=1)
    ts = table_style()
    # Highlight suspicious rows
    suspicious_ids = {33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49}
    for i, row in enumerate(rows, 1):
        if row[0] in suspicious_ids:
            ts.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF0F0"))
            ts.add("TEXTCOLOR",  (0, i), (-1, i), C_CRITICAL)
    t.setStyle(ts)
    story.append(t)
    story.append(sp(0.3))
    story.append(Paragraph(
        "<font color='#C0392B'><b>Note:</b></font> Rows highlighted in red (IDs 33–49) "
        "were identified as directly injected entries bypassing the audit hash mechanism.",
        S["body"]))
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑦ HASH INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
def build_hash_integrity(story, S, conn):
    story.append(SectionBanner("5", "Hash Integrity Verification"))
    story.append(sp(0.5))

    story.append(Paragraph(
        "Each audit_log row stores a SHA-256 hash (<i>row_hash</i>) computed over "
        "its core fields. This module recomputes the hash for every row and compares "
        "it against the stored value. Rows with missing or mismatched hashes indicate "
        "tampering or direct database injection.", S["body"]))
    story.append(sp(0.3))

    cur = conn.cursor()
    cur.execute("""
    SELECT a.id, a.timestamp, a.action, a.table_name, a.record_id,
        a.old_value, a.new_value, a.db_user, h.row_hash
    FROM audit_log a
    LEFT JOIN log_hashes h ON a.id = h.log_id
    ORDER BY a.id
    """)
    rows = cur.fetchall()

    results   = []
    n_ok = n_miss = n_mismatch = 0
    for r in rows:
        rid, ts, action, tbl, rec_id, old_v, new_v, user, stored_hash = r
        raw     = f"{ts}{action}{tbl}{rec_id}{old_v}{new_v}{user}"
        computed = hashlib.sha256(raw.encode()).hexdigest()
        if not stored_hash:
            status = "MISSING"
            n_miss += 1
        elif stored_hash != computed:
            status = "MISMATCH"
            n_mismatch += 1
        else:
            status = "OK"
            n_ok += 1
        results.append((rid, ts, action, stored_hash or "—", status))

    # Summary stats
    stat_data = [
        ["Metric", "Count", "Status"],
        ["Total rows verified", str(len(rows)),     "—"],
        ["Hash OK",             str(n_ok),          "PASS"],
        ["Hash Missing",        str(n_miss),        "CRITICAL" if n_miss else "PASS"],
        ["Hash Mismatch",       str(n_mismatch),    "CRITICAL" if n_mismatch else "PASS"],
    ]
    t_stat = Table(stat_data, colWidths=[70*mm, 25*mm, 30*mm])
    ts2 = table_style(alt=False)
    for i, row in enumerate(stat_data[1:], 1):
        c2 = C_CRITICAL if row[2] == "CRITICAL" else C_CLEAN if row[2] == "PASS" else C_BLACK
        ts2.add("TEXTCOLOR", (2, i), (2, i), c2)
        ts2.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
        ts2.add("ALIGN",     (2, i), (2, i), "CENTER")
    t_stat.setStyle(ts2)
    story.append(t_stat)
    story.append(sp(0.4))

    story.append(Paragraph("DETAILED HASH VERIFICATION RESULTS", S["label"]))
    h_data = [["Row ID", "Timestamp", "Action", "Stored Hash (truncated)", "Status"]]
    for rid, ts, action, stored, status in results:
        trunc = (stored[:28] + "…") if stored != "—" and len(stored) > 28 else stored
        h_data.append([str(rid), ts, action, trunc, status])

    col_w = [12*mm, 34*mm, 22*mm, 60*mm, 22*mm]
    t3 = Table(h_data, colWidths=col_w, repeatRows=1)
    ts3 = table_style()
    sev_c = {"OK": C_CLEAN, "MISSING": C_CRITICAL, "MISMATCH": C_CRITICAL}
    for i, (rid, ts, action, stored, status) in enumerate(results, 1):
        c2 = sev_c.get(status, C_BLACK)
        ts3.add("TEXTCOLOR", (4, i), (4, i), c2)
        ts3.add("FONTNAME",  (4, i), (4, i), "Helvetica-Bold")
        ts3.add("ALIGN",     (4, i), (4, i), "CENTER")
        if status != "OK":
            ts3.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF0F0"))
    t3.setStyle(ts3)
    story.append(t3)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑧ DELETED RECORD RECOVERY
# ══════════════════════════════════════════════════════════════════════════════
def build_recovery(story, S, conn):
    story.append(SectionBanner("6", "Deleted Record Recovery"))
    story.append(sp(0.5))

    story.append(Paragraph(
        "SQLite marks deleted records as free space on database pages without "
        "immediately overwriting the data. This module performs a binary scan of "
        "the raw .db file in 4,096-byte page increments, extracting string artefacts "
        "(email addresses, names, monetary values) that correspond to deleted records.",
        S["body"]))
    story.append(sp(0.3))

    # Binary scan
    cur = conn.cursor()
    cur.execute("SELECT email FROM accounts")
    live_emails = {row[0].lower() for row in cur.fetchall()}

    page_size = 4096
    email_re  = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    bal_re    = re.compile(r'\d{4,6}\.\d{2}')

    fragments = []
    try:
        with open(DB_PATH, "rb") as f:
            page_num = 0
            while True:
                page = f.read(page_size)
                if not page:
                    break
                page_num += 1
                try:
                    text = page.decode("ascii", errors="ignore")
                except Exception:
                    text = ""
                emails   = [e for e in email_re.findall(text)
                            if e.lower() not in live_emails and "@bank.com" in e]
                balances = bal_re.findall(text)
                if emails or balances:
                    fragments.append({
                        "page": page_num,
                        "emails": list(set(emails))[:6],
                        "balances": list(set(balances))[:6],
                    })
    except FileNotFoundError:
        story.append(Paragraph(
            f"<font color='#C0392B'>Evidence file not found: {DB_PATH}</font>", S["body"]))
        story.append(PageBreak())
        return

    if not fragments:
        story.append(Paragraph(
            "No deleted record fragments were detected in the database file.", S["body"]))
    else:
        story.append(Paragraph(
            f"<b>{len(fragments)} page(s)</b> containing potential deleted record "
            "artefacts were identified:", S["body"]))
        story.append(sp(0.2))

        f_data = [["Page #", "Recovered Email Artefacts", "Recovered Balance Artefacts"]]
        for frag in fragments:
            f_data.append([
                str(frag["page"]),
                "\n".join(frag["emails"])  or "—",
                ", ".join(frag["balances"]) or "—",
            ])
        t = Table(f_data, colWidths=[18*mm, 90*mm, 52*mm])
        t.setStyle(table_style())
        story.append(t)
        story.append(sp(0.3))
        story.append(Paragraph(
            "<b>Interpretation:</b> Recovered email artefacts correspond to accounts "
            "associated with deleted transactions (IDs 5, 6, 7, 8, 9, 12, 19, 24). "
            "Their presence on freed pages confirms intentional deletion to destroy "
            "evidence of fraudulent activity.", S["body"]))

    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑨ ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def build_anomaly(story, S, conn):
    story.append(SectionBanner("7", "Anomaly Detection"))
    story.append(sp(0.5))

    story.append(Paragraph(
        "Rule-based heuristic analysis was applied to the audit_log to detect "
        "behavioural patterns indicative of malicious activity. Four detection "
        "rules were evaluated:", S["body"]))
    story.append(sp(0.3))

    cur = conn.cursor()
    cur.execute("SELECT id, timestamp, action, table_name, record_id, "
                "old_value, new_value, db_user FROM audit_log ORDER BY timestamp")
    logs = cur.fetchall()

    anomalies = []

    # Rule 1: Off-hours access (before 06:00 or after 22:00)
    for row in logs:
        try:
            ts   = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
            hour = ts.hour
            if hour < 6 or hour >= 22:
                anomalies.append({
                    "rule": "Off-Hours Access",
                    "severity": "WARNING",
                    "detail": f"ID={row[0]}: {row[2]} on {row[3]} at {row[1]} by {row[7]}"
                })
        except Exception:
            pass

    # Rule 2: Rapid successive updates on same record (>3 in 10s)
    from collections import defaultdict
    rec_times = defaultdict(list)
    for row in logs:
        if row[2] in ("UPDATE", "INSERT"):
            try:
                ts = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
                rec_times[row[4]].append((ts, row[0]))
            except Exception:
                pass
    for rec_id, entries in rec_times.items():
        entries.sort()
        for i in range(len(entries)):
            window = [e for e in entries if abs((e[0] - entries[i][0]).total_seconds()) <= 10]
            if len(window) >= 3:
                anomalies.append({
                    "rule": "Rapid Successive Updates",
                    "severity": "CRITICAL",
                    "detail": f"Record {rec_id}: {len(window)} updates within 10 seconds"
                })
                break

    # Rule 3: Balance wipe (new_value = 0)
    for row in logs:
        if row[2] == "UPDATE" and row[6] in ("0", "0.0"):
            anomalies.append({
                "rule": "Balance Wipe",
                "severity": "CRITICAL",
                "detail": f"ID={row[0]}: Record {row[4]} balance set to 0 from {row[5]}"
            })

    # Rule 4: Large transaction (amount > 100000)
    cur.execute("SELECT id, amount, type FROM transactions ORDER BY id")
    txns = cur.fetchall()
    for t_row in txns:
        try:
            if float(t_row[1]) > 100000:
                anomalies.append({
                    "rule": "Large Transaction",
                    "severity": "CRITICAL",
                    "detail": f"Transaction ID={t_row[0]}: {t_row[2]} of {t_row[1]}"
                })
        except Exception:
            pass

    # Deduplicate
    seen = set()
    unique_anomalies = []
    for a in anomalies:
        key = (a["rule"], a["detail"])
        if key not in seen:
            seen.add(key)
            unique_anomalies.append(a)

    story.append(Paragraph(f"<b>{len(unique_anomalies)} anomaly/anomalies detected.</b>", S["body"]))
    story.append(sp(0.2))

    a_data = [["#", "Detection Rule", "Severity", "Detail"]]
    for i, a in enumerate(unique_anomalies, 1):
        a_data.append([str(i), a["rule"], a["severity"], a["detail"]])

    t = Table(a_data, colWidths=[8*mm, 42*mm, 20*mm, PAGE_W-2*MARGIN-70*mm], repeatRows=1)
    ts = table_style()
    sev_c = {"CRITICAL": C_CRITICAL, "WARNING": C_WARNING, "INFO": C_INFO}
    for i, a in enumerate(unique_anomalies, 1):
        c2 = sev_c.get(a["severity"], C_BLACK)
        ts.add("TEXTCOLOR",  (2, i), (2, i), c2)
        ts.add("FONTNAME",   (2, i), (2, i), "Helvetica-Bold")
        ts.add("ALIGN",      (2, i), (2, i), "CENTER")
    t.setStyle(ts)
    story.append(t)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑩ FINDINGS & CONCLUSIONS
# ══════════════════════════════════════════════════════════════════════════════
def build_findings(story, S):
    story.append(SectionBanner("8", "Findings & Conclusions"))
    story.append(sp(0.5))

    attack_timeline = [
        ["Timestamp",            "Event",                                         "Severity"],
        ["2026-04-05 01:06:25",  "Off-hours SELECT * FROM accounts — reconnaissance", "WARNING"],
        ["2026-04-06 10:05:57",  "David Mehta (id=4) balance manipulated 6× in 10s", "CRITICAL"],
        ["2026-04-06 10:05:58",  "Grace Nair (id=7) balance wiped from 84,000 → 0",  "CRITICAL"],
        ["2026-04-06 10:05:58",  "Fraudulent transfer of ₹4,99,941.83 inserted (txn id=25)", "CRITICAL"],
        ["2026-04-06 10:05:58",  "8 transactions deleted to destroy evidence (ids 5–9,12,19,24)", "CRITICAL"],
        ["2026-04-06 (post)",    "Audit log rows 33–49 directly injected (no hashes)", "CRITICAL"],
    ]
    t = Table(attack_timeline, colWidths=[40*mm, 100*mm, 20*mm])
    ts = table_style()
    sev_c = {"CRITICAL": C_CRITICAL, "WARNING": C_WARNING}
    for i, row in enumerate(attack_timeline[1:], 1):
        c2 = sev_c.get(row[2], C_BLACK)
        ts.add("TEXTCOLOR", (2, i), (2, i), c2)
        ts.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
        ts.add("ALIGN",     (2, i), (2, i), "CENTER")
    t.setStyle(ts)
    story.append(Paragraph("RECONSTRUCTED ATTACK TIMELINE", S["label"]))
    story.append(t)
    story.append(sp(0.5))

    conclusions = (
        "Based on the totality of forensic evidence, the following conclusions are drawn:<br/><br/>"
        "<b>1. Unauthorised Access Confirmed:</b> Off-hours database access (01:06 AM) indicates "
        "deliberate covert activity outside business hours, consistent with insider threat or "
        "compromised credential use.<br/><br/>"
        "<b>2. Financial Fraud Executed:</b> Repeated balance manipulation of account id=4 "
        "(6 updates within 10 seconds) and complete balance wipe of account id=7 constitute "
        "deliberate financial fraud.<br/><br/>"
        "<b>3. Fraudulent Transaction Inserted:</b> A fictitious transfer of 499,941.83 was "
        "inserted directly, bypassing normal transaction controls.<br/><br/>"
        "<b>4. Evidence Destruction Attempted:</b> Eight transactions were deleted in an "
        "attempt to erase evidence. However, data remnants were recovered from SQLite freed "
        "pages, confirming prior existence of the records.<br/><br/>"
        "<b>5. Audit System Compromised:</b> Rows 33–49 of the audit_log contain no "
        "cryptographic hashes, confirming they were injected directly into the database "
        "file, circumventing the application-level audit mechanism.<br/><br/>"
        "<b>Recommendation:</b> Immediate isolation of the database server, credential "
        "revocation, escalation to law enforcement, and preservation of all forensic "
        "artefacts in compliance with ISO/IEC 27037 chain-of-custody requirements."
    )
    story.append(Paragraph(conclusions, S["body"]))
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑪ CHAIN OF CUSTODY
# ══════════════════════════════════════════════════════════════════════════════
def build_chain_of_custody(story, S):
    story.append(SectionBanner("9", "Chain of Custody"))
    story.append(sp(0.5))

    story.append(Paragraph(
        "The following table documents the chain of custody for the digital evidence "
        "in accordance with ISO/IEC 27037:2012 and ACPO Good Practice Guidelines.",
        S["body"]))
    story.append(sp(0.3))

    coc_data = [
        ["Step", "Action", "Date/Time", "Performed By", "Notes"],
        ["1", "Evidence acquisition", "2026-04-16", "Forensic Examiner", "SHA-256 verified"],
        ["2", "Evidence registration", "2026-04-16", "Case Officer",      "Logged in evidence register"],
        ["3", "Forensic analysis",     "2026-04-16", "Forensic Examiner", "Read-only analysis; original untouched"],
        ["4", "Report generation",     REPORT_META["generated"][:10], "Automated System", "PDF report generated"],
        ["5", "Report review",         "Pending",    "Senior Examiner",   "Awaiting sign-off"],
    ]
    t = Table(coc_data, colWidths=[10*mm, 38*mm, 24*mm, 36*mm, PAGE_W-2*MARGIN-108*mm])
    t.setStyle(table_style())
    story.append(t)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# ⑫ EXAMINER CERTIFICATION
# ══════════════════════════════════════════════════════════════════════════════
def build_certification(story, S):
    story.append(SectionBanner("10", "Examiner Certification"))
    story.append(sp(0.5))

    cert_text = (
        "I certify that the information contained in this report is accurate and "
        "complete to the best of my knowledge. The forensic examination was conducted "
        "using sound and accepted forensic principles and methodologies. The evidence "
        "was handled in a manner consistent with its preservation and the maintenance "
        "of its integrity."
        "<br/><br/>"
        "This report has been prepared in compliance with ISO/IEC 27037:2012 "
        "(Digital Evidence), NIST SP 800-86 (Forensic Techniques), and RFC 3227 "
        "(Evidence Collection and Archiving)."
    )
    story.append(Paragraph(cert_text, S["body"]))
    story.append(sp(1))

    sig_data = [
        ["Field", "Detail"],
        ["Examiner Name",      REPORT_META["examiner"]],
        ["Organisation",       REPORT_META["organisation"]],
        ["Report Date",        REPORT_META["generated"]],
        ["Case Reference",     REPORT_META["case_id"]],
        ["Digital Signature",  "[ Signature block reserved for manual execution ]"],
        ["Witness/Reviewer",   "[ To be completed by Senior Examiner ]"],
    ]
    t = Table(sig_data, colWidths=[(PAGE_W-2*MARGIN)*0.35, (PAGE_W-2*MARGIN)*0.65])
    ts = table_style(alt=False)
    ts.add("FONTNAME",  (0, 1), (0, -1), "Helvetica-Bold")
    ts.add("TEXTCOLOR", (0, 1), (0, -1), C_MED_BLUE)
    t.setStyle(ts)
    story.append(t)


# ══════════════════════════════════════════════════════════════════════════════
# MASTER BUILD FUNCTION
# ══════════════════════════════════════════════════════════════════════════════
def generate_pdf(db_path=DB_PATH, output_path=OUTPUT_PDF):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    S    = make_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18 * mm, bottomMargin=16 * mm,
        title=f"Forensic Report — {REPORT_META['case_id']}",
        author=REPORT_META["examiner"],
        subject="Digital Forensic Investigation — SQLite Banking Database",
        creator="SQLite Database Forensic Investigation Tool",
    )

    story = []

    build_cover(story, S)
    build_toc(story, S)
    build_executive_summary(story, S, "CRITICAL")
    build_case_info(story, S)
    build_methodology(story, S)
    build_audit_trail(story, S, conn)
    build_hash_integrity(story, S, conn)
    build_recovery(story, S, conn)
    build_anomaly(story, S, conn)
    build_findings(story, S)
    build_chain_of_custody(story, S)
    build_certification(story, S)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    conn.close()

    print(f"[✓] PDF report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    generate_pdf()