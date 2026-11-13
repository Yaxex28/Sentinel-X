import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from src.engine.timeline_engine import cluster_events, summarize_cluster, is_interesting
from src.engine.threat_scoring import score_event

logger = logging.getLogger(__name__)

class Scenario:
    """A collection of events representing a specific behavior (benign or malicious)."""
    def __init__(self, name: str, is_malicious: bool, events: List[Dict[str, Any]]):
        self.name = name
        self.is_malicious = is_malicious
        self.events = events

    def to_event_rows(self) -> List[Tuple]:
        """Convert dictionary events to the tuple format expected by the engine."""
        rows = []
        for e in self.events:
            # Format: (id, timestamp, host, source, event_type, severity, description, raw_data)
            row = (
                e.get("id", "evt-123"),
                e.get("timestamp", datetime.now().isoformat()),
                e.get("host", "test-host"),
                e.get("source", "test-source"),
                e.get("event_type", "generic"),
                e.get("severity", "low"),
                e.get("description", ""),
                json.dumps(e.get("raw_data", {}))
            )
            rows.append(row)
        return rows

class EvaluationResult:
    """Detailed result of an evaluation run containing key metrics."""
    def __init__(self, total_scenarios: int, tp: int, fp: int, tn: int, fn: int, duration_hours: float):
        self.total_scenarios = total_scenarios
        self.tp = tp
        self.fp = fp
        self.tn = tn
        self.fn = fn
        self.duration_hours = duration_hours

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_flags_per_hour(self) -> float:
        return self.fp / self.duration_hours if self.duration_hours > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"--- Evaluation Results ---\n"
            f"Total Scenarios: {self.total_scenarios}\n"
            f"Precision:       {self.precision:.2%}\n"
            f"Recall (Det Rate): {self.recall:.2%}\n"
            f"F1 Score:        {self.f1_score:.2f}\n"
            f"False Flags/Hr:  {self.false_flags_per_hour:.2f}\n"
            f"--------------------------\n"
            f"TP: {self.tp}, FP: {self.fp}, TN: {self.tn}, FN: {self.fn}"
        )

class EvaluationHarness:
    """Runner for executing and measuring Sentinel-X detection performance."""
    def __init__(self):
        self.scenarios: List[Scenario] = []

    def add_scenario(self, scenario: Scenario):
        self.scenarios.append(scenario)

    def run(self) -> EvaluationResult:
        tp, fp, tn, fn = 0, 0, 0, 0
        total_duration_seconds = 0.0

        for scenario in self.scenarios:
            rows = scenario.to_event_rows()
            rows.sort(key=lambda x: x[1])

            if rows:
                start = datetime.fromisoformat(rows[0][1])
                end = datetime.fromisoformat(rows[-1][1])
                total_duration_seconds += max((end - start).total_seconds(), 1.0)

            clusters = cluster_events(rows)
            detected = False

            for cluster in clusters:
                summary = summarize_cluster(cluster)
                if is_interesting(summary):
                    detected = True
                    break

            if scenario.is_malicious:
                if detected:
                    tp += 1
                else:
                    fn += 1
            else:
                if detected:
                    fp += 1
                else:
                    tn += 1

        duration_hours = total_duration_seconds / 3600.0
        return EvaluationResult(len(self.scenarios), tp, fp, tn, fn, duration_hours)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    harness = EvaluationHarness()

    now = datetime.now()
    m_scenario = Scenario("Brute Force", True, [
        {"timestamp": (now + timedelta(seconds=i)).isoformat(), "event_type": "login_failure", "severity": "high", "source": f"src-{i}"}
        for i in range(5)
    ])

    b_scenario = Scenario("Normal Browsing", False, [
        {"timestamp": (now + timedelta(minutes=10, seconds=i)).isoformat(), "event_type": "process_started", "severity": "low", "source": "chrome"}
        for i in range(2)
    ])

    harness.add_scenario(m_scenario)
    harness.add_scenario(b_scenario)

    results = harness.run()
    print(results)
