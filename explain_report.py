import sys
sys.path.insert(0, "src")

from storage.database import init_db
from reporting.report_data import build_report_data
from ai.explainer import explain

data = build_report_data(init_db("data/sentinel.db"))
for i, cluster in enumerate(data["clusters"], start=1):
    if cluster["flagged"]:
        print("Cluster " + str(i) + ":")
        print(explain(cluster))
        print()