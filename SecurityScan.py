import shutil
import uuid
from collections import Counter
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

    def _reject_image(self):
        answer = input(
            "Rejecting this image stops the plan. The candidate will be discarded "
            "and no further changes will be made. Continue? [y/N] "
        ).strip().lower()
        if answer != "y":
            return False

        self.plan["decision"] = "rejected"
        self.plan["rejection_reason"] = "User rejected a security finding."
        for action in self.plan["actions"]:
            if action["status"] == "pending":
                action["status"] = "skipped"
        self._save()
        print("Image rejected. No changes were applied.")
        return True

    def _review_vulnerabilities(self, findings, actions):
        self.plan.setdefault("reviews", {})["vulnerabilities"] = "in_progress"
        for finding, action in zip(findings, actions):
            print("\n{} [{}] - {}".format(
                finding["id"], finding["severity"], finding["package"]
            ))
            print("Installed: {}".format(finding["installed_version"]))
            if finding["can_update"]:
                print("Available fix: {}".format(finding["fixed_version"]))
                print("[f] Accept the available fix")
            else:
                print("No fix is currently available.")
            print("[a] Accept the risk")
            print("[r] Reject the image")

            choices = {"a", "r"}
            if finding["can_update"]:
                choices.add("f")
            while True:
                choice = input("Choose an action: ").strip().lower()
                if choice in choices:
                    break
                print("Choose one of: {}".format(", ".join(sorted(choices))))

            if choice == "r":
                self._save()
                return not self._reject_image()

            if choice == "f":
                action["decision"] = "accept_fix"
                action["approved"] = True
                action["status"] = "approved"
            else:
                action["decision"] = "accept_risk"
                action["status"] = "accepted_risk"
            self._save()

        self.plan["reviews"]["vulnerabilities"] = "completed"
        self._save()
        return True

    def _review_optional_findings(self, section, findings, actions):
        self.plan.setdefault("reviews", {})[section] = "in_progress"
        for finding, action in zip(findings, actions):
            print("\n{} [{}]".format(
                finding.get("title", finding.get("type", finding.get("id", "Finding"))),
                finding.get("severity", "UNKNOWN"),
            ))
            detail = finding.get("description") or finding.get("file") or finding.get("target")
            if detail:
                print("Details: {}".format(detail))
            if finding.get("resolution"):
                print("Suggested change: {}".format(finding["resolution"]))
            print("[l] Leave alone")
            print("[c] Add the suggested change to the plan")
            print("[r] Reject the image")

            while True:
                choice = input("Choose an action: ").strip().lower()
                if choice in {"l", "c", "r"}:
                    break
                print("Choose one of: l, c, r")

            if choice == "r":
                self._save()
                return not self._reject_image()
            if choice == "l":
                action["status"] = "accepted_risk"
                action["decision"] = "leave_alone"
            else:
                action["approved"] = True
                action["status"] = "approved"
                action["decision"] = "change"
            self._save()

        self.plan["reviews"][section] = "completed"
        self._save()
        return True

    def _review_plan(self, vulnerabilities, secrets, misconfigurations):
        self.plan["reviews"] = {
            "vulnerabilities": "completed" if not vulnerabilities else "pending",
            "secrets": "completed" if not secrets else "pending",
            "misconfigurations": "completed" if not misconfigurations else "pending",
        }
        print("\nSecurity findings")
        print("Vulnerabilities: {}".format(len(vulnerabilities)))
        for severity, count in sorted(Counter(
            f["severity"].upper() for f in vulnerabilities
        ).items()):
            print("  {}: {}".format(severity, count))
        print("Secrets: {}".format(len(secrets)))
        print("Misconfigurations: {}".format(len(misconfigurations)))
        print("Report: {}/report.json".format(self.run_dir))

        actions = self.plan["actions"]
        vulnerability_end = len(vulnerabilities)
        secret_end = vulnerability_end + len(secrets)

        sections = {
            "1": ("vulnerabilities", vulnerabilities, actions[:vulnerability_end]),
            "2": ("secrets", secrets, actions[vulnerability_end:secret_end]),
            "3": ("misconfigurations", misconfigurations, actions[secret_end:]),
        }

        def print_menu():
            print("\nReview sections")
            for number, (section, findings, _) in sections.items():
                if findings:
                    state = " (reviewed)" if self.plan["reviews"][section] == "completed" else ""
                    print("{}. Review {}{}".format(number, section, state))
            print("4. Apply approved changes")

        while True:
            print_menu()
            choice = input("Choose an option: ").strip()
            if choice == "4":
                if not all(value == "completed" for value in self.plan["reviews"].values()):
                    print("Review every non-empty section before applying changes.")
                    continue
                break
            if choice not in sections or not sections[choice][1]:
                print("Choose one of the displayed options.")
                continue

            section, findings, section_actions = sections[choice]
            if section == "vulnerabilities":
                completed = self._review_vulnerabilities(findings, section_actions)
            else:
                completed = self._review_optional_findings(section, findings, section_actions)
            if not completed:
                return False

        print("\nAll findings have been reviewed.")
        apply_choice = input("Apply the approved changes? [y/N] ").strip().lower()
        if apply_choice != "y":
            self.plan["decision"] = "reviewed_pending_apply"
            self._save()
            print("Plan saved. No changes were applied.")
            return True

        for action in actions:
            if action.get("approved"):
                action["execution"] = self.executor.execute(
                    action, image=self.image, run_dir=self.run_dir, plan=self.plan
                )
                if action["execution"]["status"] == "manual_review_required":
                    action["status"] = "manual_review_required"

        self.plan["decision"] = "changes_applied"
        self._save()
        print("Approved changes were submitted to the plan executor.")
        return True

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

        if not silent:
            self._save()
            review_completed = self._review_plan(
                vulnerabilities, secrets, misconfigurations
            )
            if review_completed is False:
                print("Security scan stopped because the image was rejected.")
                return self.report, self.plan
        else:
            self.plan["decision"] = "review_required" if self.plan["actions"] else "ready_for_review"
        self._save()
        print("Security scan complete.")
        print("Report: {}/report.json".format(self.run_dir))
        print("Plan: {}/plan.json".format(self.run_dir))
        return self.report, self.plan
