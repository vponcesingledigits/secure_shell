from __future__ import annotations

from io import BytesIO
from typing import Any, Dict, Iterable, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfbase.pdfmetrics import stringWidth

BRAND_BLUE = colors.HexColor("#1f6fb2")
BRAND_NAVY = colors.HexColor("#17324d")
LIGHT_BLUE = colors.HexColor("#eaf4ff")
BORDER = colors.HexColor("#c9d8e8")
TEXT = colors.HexColor("#243447")
MUTED = colors.HexColor("#6b7b8c")


def build_asbuilt_pdf(project: Dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=0.55 * inch, rightMargin=0.55 * inch, topMargin=0.55 * inch, bottomMargin=0.55 * inch)
    styles = get_styles()
    story: List[Any] = []

    site = project.get("site", {}) or {}
    title = site.get("property_name") or site.get("Property Name") or "Single Digits Topology / As-Built"
    story.append(Paragraph("Single Digits Engineering Platform", styles["Kicker"]))
    story.append(Paragraph(escape(title), styles["Title"]))
    story.append(Paragraph("Topology and As-Built Documentation", styles["Subtitle"]))
    story.append(Spacer(1, 0.18 * inch))
    story.append(kv_table([
        ("Site Code", site.get("site_code", "")),
        ("Brand", site.get("brand", "")),
        ("Property Type", site.get("property_type", "")),
        ("Prepared By", site.get("prepared_by", "")),
        ("Document Version", site.get("document_version", "")),
        ("Generated", project.get("generated_at", "")),
    ]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("This report is generated from LLDP topology discovery plus optional manual As-Built cards. Blank optional fields are intentionally omitted from summary sections where practical.", styles["Small"]))
    story.append(PageBreak())

    add_section(story, styles, "Site Information", dict_to_rows(site))
    add_section(story, styles, "Documentation Checklist", checklist_rows(project.get("documentation_checklist", {}) or {}))
    add_section(story, styles, "ISP Circuits", card_rows(project.get("isp_circuits", []) or []))
    add_section(story, styles, "Firewalls", card_rows(project.get("manual_firewalls", []) or []))
    add_section(story, styles, "Gateways", card_rows(project.get("manual_gateways", []) or []))
    add_section(story, styles, "ESXi Hosts", card_rows(project.get("manual_esxi_hosts", []) or []))
    add_section(story, styles, "Virtualized Services - PGA", card_rows(project.get("manual_pga_interfaces", []) or []))
    add_section(story, styles, "Virtualized Services - RPM", card_rows(project.get("manual_rpm_vms", []) or []))
    add_section(story, styles, "VLAN Summary", table_rows(project.get("vlans", []) or [], ["vlan_id", "vlan_name", "purpose", "subnet", "gateway_ip", "dhcp_source", "notes"]))
    add_section(story, styles, "Manual Links", table_rows(project.get("manual_links", []) or [], ["from_device", "from_interface", "to_device", "to_interface", "link_type", "vlan_network", "notes"]))

    story.append(PageBreak())
    story.append(Paragraph("Switch Inventory", styles["H1"]))
    devices = [d for d in project.get("devices", []) or [] if d.get("role") == "switch"]
    story.extend(make_table_block(devices, ["name", "management_ip", "ssh_target_ip", "vendor", "model", "software_version", "mstp_priority"], empty="No switches discovered."))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Topology Links", styles["H1"]))
    story.extend(make_table_block(project.get("links", []) or [], ["source_device", "source_port", "target_device", "target_port", "target_ip", "target_role"], empty="No LLDP links discovered."))

    story.append(PageBreak())
    story.append(Paragraph("Port Documentation Preview", styles["H1"]))
    story.append(Paragraph("Patch Panel Port is intentionally blank in generated exports. Remote Hostname is LLDP system-name only.", styles["Small"]))
    ports = project.get("ports", []) or []
    story.extend(make_table_block(ports[:160], ["switch_name", "local_port_id", "local_port_name", "patch_panel_port", "remote_hostname", "remote_ip", "suggested_port_name"], empty="No port rows generated."))
    if len(ports) > 160:
        story.append(Paragraph(f"Port table truncated in PDF preview. Full export contains {len(ports)} rows in TSV/JSON.", styles["Small"]))

    doc.build(story, onFirstPage=page_decor, onLaterPages=page_decor)
    return buf.getvalue()


def get_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "Title": ParagraphStyle("Title", parent=base["Title"], textColor=BRAND_NAVY, fontSize=24, leading=28, spaceAfter=8),
        "Subtitle": ParagraphStyle("Subtitle", parent=base["Normal"], textColor=BRAND_BLUE, fontSize=13, leading=16, spaceAfter=10),
        "Kicker": ParagraphStyle("Kicker", parent=base["Normal"], textColor=BRAND_BLUE, fontSize=9, leading=11, spaceAfter=3, uppercase=True),
        "H1": ParagraphStyle("H1", parent=base["Heading1"], textColor=BRAND_NAVY, fontSize=16, leading=19, spaceBefore=12, spaceAfter=8),
        "H2": ParagraphStyle("H2", parent=base["Heading2"], textColor=BRAND_BLUE, fontSize=12, leading=15, spaceBefore=8, spaceAfter=5),
        "Small": ParagraphStyle("Small", parent=base["Normal"], textColor=MUTED, fontSize=8, leading=10),
        "Normal": ParagraphStyle("Normal", parent=base["Normal"], textColor=TEXT, fontSize=9, leading=11),
    }


def page_decor(canvas, doc):
    canvas.saveState()
    width, height = letter
    canvas.setFillColor(LIGHT_BLUE)
    canvas.rect(0, height - 0.36 * inch, width, 0.36 * inch, fill=1, stroke=0)
    canvas.setFillColor(BRAND_BLUE)
    canvas.rect(0, height - 0.39 * inch, width, 0.03 * inch, fill=1, stroke=0)
    canvas.setFillColor(BRAND_NAVY)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(0.55 * inch, height - 0.23 * inch, "Single Digits Engineering Platform")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(width - 0.55 * inch, 0.32 * inch, f"Page {doc.page}")
    canvas.restoreState()


def add_section(story: List[Any], styles: Dict[str, ParagraphStyle], title: str, rows: List[List[str]]):
    story.append(Paragraph(title, styles["H1"]))
    if not rows:
        story.append(Paragraph("No entries provided.", styles["Small"]))
        return
    story.append(simple_table(rows))
    story.append(Spacer(1, 0.08 * inch))


def make_table_block(items: List[Dict[str, Any]], fields: List[str], empty: str) -> List[Any]:
    if not items:
        return [Paragraph(empty, get_styles()["Small"])]
    rows = [[labelize(f) for f in fields]]
    for item in items:
        rows.append([str(item.get(f, "") or "") for f in fields])
    return [simple_table(rows, header=True)]


def card_rows(cards: List[Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for i, card in enumerate(cards, 1):
        title = card.get("label") or card.get("hostname") or card.get("pga_vm_name") or card.get("rpm_vm_name") or card.get("local_id") or f"Card {i}"
        rows.append([f"Card {i}", str(title)])
        for k, v in flatten(card).items():
            if k in {"local_id", "salesforce.salesforce_record_id", "zabbix.host_id"}:
                continue
            if v not in (None, "", [], {}):
                rows.append([labelize(k), str(v)])
    return rows


def table_rows(items: List[Dict[str, Any]], fields: List[str]) -> List[List[str]]:
    if not items:
        return []
    rows = [[labelize(f) for f in fields]]
    for item in items:
        rows.append([str(item.get(f, "") or "") for f in fields])
    return rows


def dict_to_rows(data: Dict[str, Any]) -> List[List[str]]:
    return [[labelize(k), str(v)] for k, v in data.items() if v not in (None, "", [], {})]


def checklist_rows(data: Dict[str, Any]) -> List[List[str]]:
    return [[labelize(k), "Yes" if bool(v) else "No"] for k, v in data.items()]


def simple_table(rows: List[List[str]], header: bool = False) -> Table:
    if not rows:
        rows = [["No entries", ""]]
    # Basic word wrapping through Paragraph in cells.
    styles = get_styles()
    wrapped = [[Paragraph(escape(str(cell)), styles["Normal"]) for cell in row] for row in rows]
    col_count = max(len(r) for r in rows)
    widths = dynamic_widths(rows, 7.4 * inch)
    tbl = Table(wrapped, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.extend([("BACKGROUND", (0, 0), (-1, 0), LIGHT_BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), BRAND_NAVY), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")])
    else:
        style.append(("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE))
    tbl.setStyle(TableStyle(style))
    return tbl


def kv_table(rows: List[tuple[str, Any]]) -> Table:
    return simple_table([[k, str(v or "")] for k, v in rows])


def dynamic_widths(rows: List[List[str]], total: float) -> List[float]:
    col_count = max(len(r) for r in rows)
    if col_count <= 2:
        return [2.0 * inch, total - 2.0 * inch]
    return [total / col_count] * col_count


def flatten(d: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(flatten(v, key))
        else:
            out[key] = v
    return out


def labelize(key: str) -> str:
    return key.replace(".", " / ").replace("_", " ").title()


def escape(value: str) -> str:
    return (value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
