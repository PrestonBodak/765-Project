import shutil
import uuid
from datetime import datetime
from pathlib import Path

from ClamScanner import ClamScanner
from PlanExecutor import PlanExecutor
from ReportPlanCreator import ReportPlanCreator
from TraceeScanner import TraceeScanner
from TrivyScanner import TrivyScanner


class SecurityScan:
    """Coordinate one complete scan for one container image."""

    def __init__(self, image):
        run_id = "{}_{}".format(
            datetime.now().strftime("%Y%m%d_%H%M%S"),
            uuid.uuid4().hex[:6],
        )
        self.run_dir = Path("scan_runs") / run_id
        self.raw_dir = self.run_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.image = image
        self.executor = PlanExecutor()
        self.report_creator = ReportPlanCreator()
        self.image_id = self.executor.image_id(image)
        self.report = self.report_creator.create_report(image, self.image_id)
        self.plan = self.report_creator.create_plan(image, self.image_id)

    def _save(self):
        self.report_creator.save(self.run_dir, self.report, self.plan)

    def _copy_output(self, source, destination):
        source_path = Path(source)
        if source_path.exists():
            shutil.copyfile(source_path, self.raw_dir / destination)
            return "raw/{}".format(destination)
        return None

    def run(self, silent=False):
        print("\nStarting security scan for {}".format(self.image))

        filesystem_dir = self.executor.export_filesystem(self.image, self.run_dir)
        if filesystem_dir is None:
            self.plan["decision"] = "inconclusive"
            self.report["stages"]["clamav"] = {"status": "filesystem_export_error"}
            self._save()
            print("Security scan stopped because the image filesystem could not be exported.")
            return self.report, self.plan

        try:
            clam_result = ClamScanner().scan_path(silent, str(filesystem_dir))
            clam_output = self._copy_output(
                "scan_outputs/clam_out.txt", "clam_out.txt"
            )
            self.report["stages"]["clamav"] = {
                "result": clam_result,
                "evidence": clam_output,
            }
        finally:
            self.executor.remove_export(self.run_dir)

        if clam_result["status"] != "clean":
            self.plan["decision"] = "rejected" if clam_result["status"] == "malware" else "inconclusive"
            self._save()
            print("Security scan stopped after ClamAV: {}.".format(clam_result["status"]))
            return self.report, self.plan

        trivy = TrivyScanner()
        trivy.scan(True, 1, self.image)
        self.executor.redact_secret_values()
        trivy_output = self._copy_output(
            "scan_outputs/trivy_out.json", "trivy_out.json"
        )
        trivy_errors = self._copy_output(
            "scan_outputs/trivy_err.txt", "trivy_err.txt"
        )
        vulnerabilities = self.report_creator.summarize_vulnerabilities()
        secrets = self.report_creator.summarize_secrets()
        misconfigurations = self.report_creator.summarize_misconfigurations()

        self.report["stages"]["trivy"] = {
            "status": "completed" if vulnerabilities is not None and secrets is not None and misconfigurations is not None else "error",
            "vulnerabilities": vulnerabilities or [],
            "secrets": secrets or [],
            "misconfigurations": misconfigurations or [],
            "evidence": trivy_output,
            "errors": trivy_errors,
        }

        if vulnerabilities is None or secrets is None or misconfigurations is None:
            self.plan["decision"] = "inconclusive"
            self._save()
            print("Security scan stopped because Trivy did not produce valid JSON.")
            return self.report, self.plan

        if not silent:
            self.report_creator.print_vulnerability_summary(vulnerabilities)
            self.report_creator.print_secret_summary(secrets)
            self.report_creator.print_misconfiguration_summary(misconfigurations)

        self.plan["actions"].extend(
            self.report_creator.actions_for(vulnerabilities, secrets, misconfigurations)
        )

        TraceeScanner().scan(silent, self.image)
        tracee_output = self._copy_output(
            "scan_outputs/tracee_out.txt", "tracee_out.txt"
        )
        self.report["stages"]["tracee"] = {
            "status": "completed" if tracee_output else "error",
            "evidence": tracee_output,
        }

        self.plan["decision"] = "review_required" if self.plan["actions"] else "ready_for_review"
        self._save()
        print("Security scan complete.")
        print("Report: {}/report.json".format(self.run_dir))
        print("Plan: {}/plan.json".format(self.run_dir))
        return self.report, self.plan
