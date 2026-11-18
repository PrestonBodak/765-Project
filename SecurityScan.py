import shutil
from pathlib import Path

from ClamScanner import ClamScanner
from PlanExecutor import PlanExecutor
from ReportPlanCreator import ReportPlanCreator
from TraceeScanner import TraceeScanner
from TrivyScanner import TrivyScanner
from ScanPaths import SCAN_DIR, reset_runtime_dirs


class SecurityScan:
    """Coordinate one complete scan for one container image."""

    def __init__(self, image, source_path=None, compose_service=None):
        reset_runtime_dirs()
        self.run_dir = SCAN_DIR
        self.raw_dir = self.run_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.image = image
        self.source_path = source_path
        self.compose_service = compose_service
        self.executor = PlanExecutor()
        self.report_creator = ReportPlanCreator()
        self.image_id = self.executor.image_id(image)
        self.report = self.report_creator.create_report(image, self.image_id)
        self.plan = self.report_creator.create_plan(
            image, self.image_id, source_path, compose_service
        )

    def _save(self):
        self.report_creator.save(self.run_dir, self.report, self.plan)

    def _copy_output(self, source, destination):
        source_path = Path(source)
        if source_path.exists():
            shutil.copyfile(source_path, self.raw_dir / destination)
            return "raw/{}".format(destination)
        return None

    def _verify_candidate(self, candidate_image, action, plan):
        """Run the existing scanners against a candidate image."""
        verification_dir = self.run_dir / "verification"
        candidate_verification_dir = verification_dir / action.get("id", "candidate")
        candidate_verification_dir.mkdir(parents=True, exist_ok=True)
        filesystem_dir = self.executor.export_filesystem(
            candidate_image, verification_dir
        )
        if filesystem_dir is None:
            return {"status": "failed", "reason": "Could not export candidate filesystem."}

        try:
            clam_result = ClamScanner().scan_path(True, str(filesystem_dir))
        finally:
            self.executor.remove_export(verification_dir)

        if clam_result["status"] != "clean":
            return {"status": "failed", "reason": "ClamAV rejected the candidate.", "clamav": clam_result}

        TrivyScanner().scan(True, 1, candidate_image)
        self.executor.redact_secret_values()
        trivy_report = self.report_creator._load_trivy_report()
        if trivy_report is None:
            return {"status": "failed", "reason": "Trivy did not produce valid JSON."}

        tracee_result = TraceeScanner().scan(True, candidate_image)
        tracee_output = SCAN_DIR / "tracee_out.json"
        tracee_error = SCAN_DIR / "tracee_err.txt"
        if (
            not tracee_output.exists()
            or not tracee_result
            or tracee_result.get("status") != "completed"
        ):
            return {"status": "failed", "reason": "Tracee did not produce output."}

        candidate_tracee_output = candidate_verification_dir / "tracee_out.json"
        candidate_tracee_error = candidate_verification_dir / "tracee_err.txt"
        shutil.copyfile(tracee_output, candidate_tracee_output)
        if tracee_error.exists():
            shutil.copyfile(tracee_error, candidate_tracee_error)
        tracee_error_text = tracee_error.read_text(errors="replace") if tracee_error.exists() else ""
        fatal_lines = [
            line for line in tracee_error_text.splitlines()
            if '"level":"fatal"' in line.lower()
            or '"level":"error"' in line.lower()
            or " fatal " in line.lower()
        ]

        candidate_tracee = self.report_creator.summarize_tracee()
        if candidate_tracee is None or candidate_tracee.get("parse_errors"):
            return {"status": "failed", "reason": "Tracee produced invalid candidate output."}
        if not candidate_tracee.get("event_count"):
            return {"status": "failed", "reason": "Tracee observed no candidate startup events."}
        if fatal_lines:
            return {
                "status": "failed",
                "reason": "Tracee reported an immediate candidate startup error.",
                "tracee_errors": fatal_lines[-5:],
            }

        candidate_vulnerabilities = self.report_creator.summarize_vulnerabilities(trivy_report)
        candidate_secrets = self.report_creator.summarize_secrets(trivy_report)
        candidate_misconfigurations = self.report_creator.summarize_misconfigurations(trivy_report)
        baseline_trivy = self.report.get("stages", {}).get("trivy", {})
        baseline_tracee = self.report.get("stages", {}).get("tracee", {}).get("findings", [])

        baseline_vulnerabilities = baseline_trivy.get("vulnerabilities", [])
        baseline_secrets = baseline_trivy.get("secrets", [])
        baseline_misconfigurations = baseline_trivy.get("misconfigurations", [])
        baseline_vulnerability_keys = {
            (finding.get("id"), finding.get("package"))
            for finding in baseline_vulnerabilities
        }
        candidate_vulnerability_keys = {
            (finding.get("id"), finding.get("package"))
            for finding in candidate_vulnerabilities
        }
        new_vulnerabilities = candidate_vulnerability_keys - baseline_vulnerability_keys
        new_secrets = {
            (finding.get("file"), finding.get("line"))
            for finding in candidate_secrets
        } - {
            (finding.get("file"), finding.get("line"))
            for finding in baseline_secrets
        }
        new_misconfigurations = {
            finding.get("id") for finding in candidate_misconfigurations
        } - {finding.get("id") for finding in baseline_misconfigurations}
        baseline_runtime_keys = {
            (finding.get("category"), finding.get("destination"), finding.get("resource"))
            for finding in baseline_tracee
        }
        new_runtime = [
            finding for finding in candidate_tracee.get("findings", [])
            if (
                finding.get("category"),
                finding.get("destination"),
                finding.get("resource"),
            ) not in baseline_runtime_keys
            and finding.get("severity") in {"CRITICAL", "HIGH"}
        ]

        if new_vulnerabilities or new_secrets or new_misconfigurations or new_runtime:
            return {
                "status": "failed",
                "reason": "The candidate introduced new security findings.",
                "new_vulnerabilities": sorted(new_vulnerabilities),
                "new_secrets": sorted(new_secrets),
                "new_misconfigurations": sorted(new_misconfigurations),
                "new_runtime_behaviors": new_runtime,
            }

        if action.get("executor") == "update_image_package" and action.get("id") in {
            finding.get("id") for finding in candidate_vulnerabilities
        }:
            return {"status": "failed", "reason": "The requested vulnerability remains after the package update."}

        if action.get("executor") == "remove_secret_from_image":
            parameters = action.get("parameters", {})
            if any(
                finding.get("file") == parameters.get("file")
                and str(finding.get("line")) == str(parameters.get("line"))
                for finding in candidate_secrets
            ):
                return {"status": "failed", "reason": "The requested secret remains in the candidate."}

        return {
            "status": "passed",
            "candidate_image": candidate_image,
            "action": action.get("id"),
            "comparison": {
                "new_vulnerabilities": 0,
                "new_secrets": 0,
                "new_misconfigurations": 0,
                "new_runtime_behaviors": 0,
            },
            "startup": {
                "event_count": candidate_tracee.get("event_count", 0),
                "tracee_output": str(candidate_tracee_output),
                "tracee_errors": str(candidate_tracee_error) if candidate_tracee_error.exists() else None,
            },
        }

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
        fixable = [
            (finding, action)
            for finding, action in zip(findings, actions)
            if finding["can_update"]
        ]
        if fixable:
            print("\n[f] Accept all available fixes")
        print("[i] Review vulnerabilities individually")
        print("[r] Reject the image")
        while True:
            choice = input("Choose an action: ").strip().lower()
            if choice in {"i", "r"} or (choice == "f" and fixable):
                break
            print("Choose one of the displayed options.")

        if choice == "r":
            self._save()
            return not self._reject_image()
        if choice == "f":
            for finding, action in fixable:
                action["approved"] = True
                action["status"] = "approved"
                action["decision"] = "accept_fix"
            self._save()
            remaining = [
                (finding, action)
                for finding, action in zip(findings, actions)
                if not finding["can_update"]
            ]
            findings = [finding for finding, _ in remaining]
            actions = [action for _, action in remaining]
            if not findings:
                self.plan["reviews"]["vulnerabilities"] = "completed"
                self._save()
                return True

        for finding, action in zip(findings, actions):
            print("\n{} [{}] - {}".format(
                finding["id"], finding["severity"], finding["package"]
            ))
            print("What this means: {}".format(
                finding.get("title") or "A known problem was found in this package."
            ))
            print("Installed: {}".format(finding["installed_version"]))
            if finding["can_update"]:
                print("Available fix: {}".format(finding["fixed_version"]))
                print("[f] Accept the available fix")
            else:
                print("No fix is currently available.")
            if finding.get("url"):
                print("More information: {}".format(finding["url"]))
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

    def _review_runtime_findings(self, findings, actions):
        self.plan.setdefault("reviews", {})["runtime_behavior"] = "in_progress"
        for finding, action in zip(findings, actions):
            print("\n{} [{}]".format(finding["description"], finding["severity"]))
            if finding.get("destination"):
                print("Destination: {}".format(finding["destination"]))
            if finding.get("resource"):
                print("Resource: {}".format(finding["resource"]))
            print("This is a behavior Tracee observed while the image was running.")
            print("Technical details are saved in {}/report.json.".format(self.run_dir))
            print("[a] Accept this behavior")
            print("[r] Reject the image")

            while True:
                choice = input("Choose an action: ").strip().lower()
                if choice in {"a", "r"}:
                    break
                print("Choose one of: a, r")

            if choice == "r":
                self._save()
                return not self._reject_image()

            action["approved"] = True
            action["status"] = "approved"
            action["decision"] = "accept_behavior"
            self._save()

        self.plan["reviews"]["runtime_behavior"] = "completed"
        self._save()
        return True

    def _review_plan(self, vulnerabilities, secrets, misconfigurations, runtime_findings):
        self.plan["reviews"] = {
            "vulnerabilities": "completed" if not vulnerabilities else "pending",
            "secrets": "completed" if not secrets else "pending",
            "misconfigurations": "completed" if not misconfigurations else "pending",
            "runtime_behavior": "completed" if not runtime_findings else "pending",
        }
        print("\nSecurity review")
        print("Known software problems: {}".format(len(vulnerabilities)))
        fixable = sum(finding["can_update"] for finding in vulnerabilities)
        print("  Updates available: {}".format(fixable))
        print("  No update currently available: {}".format(len(vulnerabilities) - fixable))
        print("Possible credentials inside the image: {}".format(len(secrets)))
        print("Docker configuration problems: {}".format(len(misconfigurations)))
        print("Unexpected runtime behaviors: {}".format(len(runtime_findings)))
        print("Report: {}/report.json".format(self.run_dir))

        actions = self.plan["actions"]
        vulnerability_end = len(vulnerabilities)
        secret_end = vulnerability_end + len(secrets)
        misconfiguration_end = secret_end + len(misconfigurations)

        sections = {
            "1": ("vulnerabilities", vulnerabilities, actions[:vulnerability_end]),
            "2": ("secrets", secrets, actions[vulnerability_end:secret_end]),
            "3": ("misconfigurations", misconfigurations, actions[secret_end:misconfiguration_end]),
            "4": ("runtime_behavior", runtime_findings, actions[misconfiguration_end:]),
        }
        section_labels = {
            "vulnerabilities": "vulnerabilities",
            "secrets": "secrets",
            "misconfigurations": "misconfigurations",
            "runtime_behavior": "runtime behavior",
        }
        apply_option = "5" if runtime_findings else "4"

        def print_menu():
            print("\nReview sections")
            for number, (section, findings, _) in sections.items():
                if findings:
                    state = " (reviewed)" if self.plan["reviews"][section] == "completed" else ""
                    print("{}. Review {}{}".format(number, section_labels[section], state))
            print("{}. Apply approved changes".format(apply_option))

        while True:
            print_menu()
            choice = input("Choose an option: ").strip()
            if choice == apply_option:
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
            elif section == "runtime_behavior":
                completed = self._review_runtime_findings(findings, section_actions)
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

        execution = self.executor.execute_plan(
            self.plan,
            self.image,
            self.run_dir,
            verify=self._verify_candidate,
            source_path=self.source_path,
            compose_service=self.compose_service,
        )
        if self.plan.get("candidate_archive"):
            self.report["candidate_image"] = self.plan.get("candidate_image")
            self.report["candidate_archive"] = self.plan["candidate_archive"]
            print("Fixed image retained locally: {}".format(self.plan["candidate_archive"]))
        self._save()
        print("Plan execution result: {}".format(execution["status"]))
        return True

    def run(self, silent=False):
        print("\nStarting security scan for {}".format(self.image))

        print("Preparing the image filesystem for scanning...", flush=True)
        filesystem_dir = self.executor.export_filesystem(self.image, self.run_dir)
        if filesystem_dir is None:
            self.plan["decision"] = "inconclusive"
            self.report["stages"]["clamav"] = {"status": "filesystem_export_error"}
            self._save()
            print("Security scan stopped because the image filesystem could not be exported.")
            return self.report, self.plan

        try:
            print("Scanning for malware with ClamAV...", flush=True)
            clam_result = ClamScanner().scan_path(True, str(filesystem_dir))
            clam_output = self._copy_output(
                SCAN_DIR / "clam_out.txt", "clam_out.txt"
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
        print("Scanning for vulnerabilities, secrets, and misconfigurations with Trivy...", flush=True)
        trivy.scan(True, 1, self.image)
        self.executor.redact_secret_values()
        trivy_output = self._copy_output(
            SCAN_DIR / "trivy_out.json", "trivy_out.json"
        )
        trivy_errors = self._copy_output(
            SCAN_DIR / "trivy_err.txt", "trivy_err.txt"
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
            self.report_creator.actions_for(
                vulnerabilities, secrets, misconfigurations, source_path=self.source_path
            )
        )

        print("Scanning runtime behavior with Tracee...", flush=True)
        tracee_result = TraceeScanner().scan(True, self.image)
        tracee_output = self._copy_output(
            SCAN_DIR / "tracee_out.json", "tracee_out.json"
        )
        tracee_errors = self._copy_output(
            SCAN_DIR / "tracee_err.txt", "tracee_err.txt"
        )
        tracee_summary = self.report_creator.summarize_tracee()
        tracee_findings = tracee_summary["findings"] if tracee_summary else []
        self.report["stages"]["tracee"] = {
            "status": "completed"
            if tracee_output and tracee_result and tracee_result.get("status") == "completed"
            else "error",
            "evidence": tracee_output,
            "errors": tracee_errors,
            "configuration": (tracee_result or {}).get("configuration", []),
            "event_count": (tracee_summary or {}).get("event_count", 0),
            "parse_errors": (tracee_summary or {}).get("parse_errors", 0),
            "findings": tracee_findings,
        }

        if not tracee_output or not tracee_result or tracee_result.get("status") != "completed":
            self.plan["decision"] = "inconclusive"
            self._save()
            print("Security scan stopped because Tracee failed to start or collect runtime events.")
            return self.report, self.plan

        if tracee_summary is None or tracee_summary["parse_errors"]:
            self.plan["decision"] = "inconclusive"
            self._save()
            print("Security scan stopped because Tracee did not produce valid JSON output.")
            return self.report, self.plan

        self.plan["actions"].extend(
            self.report_creator.actions_for([], [], [], tracee_findings, self.source_path)
        )

        if not silent:
            self._save()
            review_completed = self._review_plan(
                vulnerabilities, secrets, misconfigurations, tracee_findings
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
