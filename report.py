import argparse
import os
from datetime import date

import requests
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle, Paragraph
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a Veracode Agent-Based SCA PDF report for a project")
    parser.add_argument("--workspace", required=True, help="Workspace name")
    parser.add_argument("--app", required=True, help="Application name")
    parser.add_argument("--region", default="com", help="Veracode Region (default: com)")
    parser.add_argument("--output", default="report.pdf", help="PDF file path")
    parser.add_argument("--vuln-methods", action="store_true", help="Fetch only issues with vulnerable methods")
    return parser.parse_args()

args = parse_args()

try:
    API_ID = os.environ["VERACODE_API_KEY_ID"]
    API_KEY = os.environ["VERACODE_API_KEY_SECRET"]
except KeyError:
    raise EnvironmentError("Missing Veracode API credentials in environment variables: 'api_id' and/or 'api_key'")

workspace = args.workspace
app_name = args.app
region = args.region
pdf_filename = args.output
vuln_methods = args.vuln_methods


styles = getSampleStyleSheet()
cell_style = styles["BodyText"]
cell_style.alignment = 1
header_style = ParagraphStyle(
    name="HeaderInfo",
    parent=styles["BodyText"],
    alignment=1,
    fontName="Helvetica-Bold",
    textColor=HexColor("#FFFFFF")
)

INFO_HEADER = ["Library", "Usage", "Version", "Release Date", "Latest Safe Version", "Latest Version", "Latest Version Release Date"]
VULN_HEADER = ["CVE", "Description", "Severity", "Disclosure Date"]
COL_WIDTHS_INFO = [70, 60, 50, 70, 90, 80, 115]
COL_WIDTHS_VULN = [90, 255, 80, 110]

COLOR_INFO_HEADER = HexColor("#4F81BD")
COLOR_INFO_BODY = HexColor("#E6EEF7")
COLOR_VULN_HEADER = HexColor("#A94442")
COLOR_VULN_BODY = HexColor("#F2DEDE")
COLOR_TEXT_HEADER = HexColor("#FFFFFF")

MARGIN_BOTTOM = 150
Y_INIT = 770


def cvss_score_to_severity(score):
    try:
        score = float(score)
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        elif score <= 10.0:
            return "Critical"
        else:
            return "N/A"
    except ValueError:
        return "N/A"


def veracode_get(url, params=None):
    try:
        response = requests.get(url, auth=RequestsAuthPluginVeracodeHMAC(API_ID, API_KEY), params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"API request error: {e}")
        return {}

def get_workspace_id():
    data = veracode_get(f"https://api.veracode.{region}/srcclr/v3/workspaces")
    return next((ws['id'] for ws in data.get('_embedded', {}).get('workspaces', []) if ws['name'] == workspace), None)

def get_project_id(workspace_id):
    data = veracode_get(f"https://api.veracode.{region}/srcclr/v3/workspaces/{workspace_id}/projects", {"search": app_name})
    return next((p['id'] for p in data.get('_embedded', {}).get('projects', [])), None)

def get_issues(workspace_id, project_id, vuln_methods):
    all_issues = []
    base_url = f"https://api.veracode.{region}/srcclr/v3/workspaces/{workspace_id}/projects/{project_id}/issues"
    params = {"size": 100, "page": 0}
    if vuln_methods:
        params["vuln_methods"] = True

    data = veracode_get(base_url, params=params)
    all_issues.extend(data.get('_embedded', {}).get('issues', []))

    page_info = data.get("page", {})
    total_pages = page_info.get("total_pages", 1)

    for page in range(1, total_pages):
        params["page"] = page
        data = veracode_get(base_url, params=params)
        all_issues.extend(data.get("_embedded", {}).get("issues", []))

    return all_issues

def get_issue_data(issue_url):
    return veracode_get(issue_url)

def get_vulnerability_data(vuln_url):
    return veracode_get(vuln_url)


def create_table(data, col_widths, header_color, body_color, header_text_color):
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR", (0, 0), (-1, 0), header_text_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 1), (-1, -1), body_color)
    ]))
    return table

def draw_table_on_canvas(table, c, y_position):
    if y_position < MARGIN_BOTTOM:
        c.showPage()
        c.setFont("Helvetica", 12)
        y_position = Y_INIT

    table_width, table_height = table.wrapOn(c, A4[0], A4[1])
    table.drawOn(c, 30, y_position - table_height)

    return y_position - table_height - 20

def generate_pdf(workspace_id, project_id, vuln_methods):
    issues = get_issues(workspace_id, project_id, vuln_methods)
    c = canvas.Canvas(pdf_filename, pagesize=A4)

    width, _ = A4
    y_position = Y_INIT

    c.setFont("Helvetica", 20)
    c.setFillColor(HexColor("#0096FF"))
    c.drawString(65, 650, "AGENT-BASED SCAN SCA SECURITY REPORT")

    c.setFont("Helvetica", 14)
    c.setFillColor(HexColor("#000000"))
    c.drawString(65, 600, f"{date.today():%B %d, %Y}")
    c.drawString(65, 580, app_name)
    c.setFont("Helvetica", 8)
    c.setFillColor(HexColor("#A9A9A9"))
    c.drawRightString(width - 40, 30, "1")

    c.showPage()

    c.setFont("Helvetica", 20)
    c.setFillColor(HexColor("#0096FF"))
    c.drawString(30, 800, "ISSUES")
    c.setStrokeColor(HexColor("#0096FF"))
    c.line(30, 790, 560, 790)

    c.setFont("Helvetica", 12)
    c.setFillColor(HexColor("#000000"))

    for issue in issues:
        issue_data = get_issue_data(issue['_links']['self']['href'])
        vulnerability = get_vulnerability_data(issue['vulnerability']['_links']['self']['href'])
        library = issue_data.get('library', {})
        fix_info = issue_data.get('fix_info', {})

        info_data = [[Paragraph(col, header_style) for col in INFO_HEADER], [
            Paragraph(library.get('name', ''), cell_style),
            Paragraph('Direct' if library.get('direct') else 'Transitive', cell_style),
            Paragraph(library.get('version', ''), cell_style),
            Paragraph(library.get('release_date', ''), cell_style),
            Paragraph(fix_info.get('latest_safe_version', ''), cell_style),
            Paragraph(library.get('latest_version', ''), cell_style),
            Paragraph(library.get('latest_version_release_date', ''), cell_style),
        ]]
        info_table = create_table(info_data, COL_WIDTHS_INFO, COLOR_INFO_HEADER, COLOR_INFO_BODY, COLOR_TEXT_HEADER)
        y_position = draw_table_on_canvas(info_table, c, y_position)

        vuln_data = [[Paragraph(col, header_style) for col in VULN_HEADER], [
            Paragraph(vulnerability.get('exploitability', {}).get('cve_full', 'N/A'), cell_style),
            Paragraph(vulnerability.get('overview', ''), cell_style),
            Paragraph(cvss_score_to_severity(vulnerability.get('cvss3', '')), cell_style),
            Paragraph(vulnerability.get('disclosure_date', ''), cell_style),
        ]]
        vuln_table = create_table(vuln_data, COL_WIDTHS_VULN, COLOR_VULN_HEADER, COLOR_VULN_BODY, COLOR_TEXT_HEADER)
        y_position = draw_table_on_canvas(vuln_table, c, y_position)

    c.setFont("Helvetica", 8)
    c.setFillColor(HexColor("#A9A9A9"))
    c.drawRightString(width - 40, 30, "2")
    c.save()


if __name__ == '__main__':
    workspace_id = get_workspace_id()
    if not workspace_id:
        raise ValueError(f"Workspace '{workspace}' not found.")
    project_id = get_project_id(workspace_id)
    if not project_id:
        raise ValueError(f"Project '{app_name}' not found.")
    generate_pdf(workspace_id, project_id, vuln_methods)