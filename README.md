# Veracode Agent SCA Project PDF

This Python script generates a professional PDF report for a Veracode Agent-Based SCA (Software Composition Analysis) project. It fetches issues via the Veracode API and formats them into structured tables using ReportLab.

## Features

* Fetch issues from Veracode SCA (Agent-Based) API
* Generate a styled PDF with:

  * Project metadata
  * Table of vulnerable libraries
  * CVE descriptions and severity levels
* Optional filtering of issues by vulnerable methods

## Requirements

* Python 3.8+
* Veracode API credentials
* Veracode SCA project and workspace

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/Veracode-Agent-SCA-Project-PDF.git
cd Veracode-Agent-SCA-Project-PDF
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

Required packages:

* `requests`
* `reportlab`
* `veracode-api-signing`

3. Export Veracode API credentials:

```bash
export VERACODE_API_KEY_ID="YOUR_VERACODE_API_KEY_ID"
export VERACODE_API_KEY_SECRET="YOUR_VERACODE_API_KEY_SECRET"
```

## Usage

```bash
python report.py \
  --workspace VeraTestWS \
  --app veracode4560044/verademo \
  --region eu \
  --output /path/to/output.pdf \
  [--vuln-methods]
```

### Arguments

| Argument         | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--workspace`    | Name of the Veracode workspace                               |
| `--app`          | Application name (e.g., `org/project`)                       |
| `--region`       | Veracode region (`com`, `eu`) — default: `com`         |
| `--output`       | Path to the output PDF file — default: `report.pdf`          |
| `--vuln-methods` | Optional flag to include only issues with vulnerable methods |

## Output

The script creates a multi-page PDF with:

* A title and metadata page
* A list of issues, including:

  * A table of affected libraries
  * A table of related CVEs, descriptions, severity and disclosure dates

---
