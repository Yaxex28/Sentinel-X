import sys
from pathlib import Path
sys.path.insert(0, "src")

from storage.database import init_db
from reporting.report_data import build_report_data
from reporting.html_report import render_html


def main():
    conn = init_db("data/sentinel.db")
    data = build_report_data(conn)
    out = Path("reports/incident_report.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(data), encoding="utf-8")
    print("Wrote " + str(out))


if __name__ == "__main__":
    main()