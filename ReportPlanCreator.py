import json
import re
from pathlib import Path
from PlanExecutor import PlanExecutor
from ScanPaths import SCAN_DIR


class ReportPlanCreator:
    """Parse scanner evidence and present report and plan information."""

    def create_report(self, image, image_id):
        return {
            "image": image,
            "original_image_id": image_id,
            "stages": {},
        }

    def create_plan(self, image, image_id, source_path=None, compose_service=None):
        return {
            "decision": "pending",
            "original_image": {
                "reference": image,
                "image_id": image_id,
            },
            "source_path": str(source_path) if source_path else None,
            "compose_service": compose_service,
            "candidate_image": None,
            "actions": [],
        }

    def save(self, run_dir, report, plan):
        run_dir = Path(run_dir)
        with open(run_dir / "report.json", "w") as report_file:
            json.dump(report, report_file, indent=2)
        with open(run_dir / "plan.json", "w") as plan_file:
            json.dump(plan, plan_file, indent=2)

    def _load_trivy_report(self, report_path=None):
        report_path = SCAN_DIR / "trivy_out.json" if report_path is None else report_path
        try:
            with open(report_path, "r") as report_file:
                return json.load(report_file)
        except (OSError, json.JSONDecodeError):
            return None

    def _load_tracee_events(self, report_path=None):
        report_path = SCAN_DIR / "tracee_out.json" if report_path is None else report_path
        try:
            with open(report_path, "r") as report_file:
                lines = report_file.readlines()
        except OSError:
            return None

        events = []
        parse_errors = 0
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if isinstance(event, dict):
                events.append(event)
        return events, parse_errors

    @staticmethod
    def _tracee_event_name(event):
        return str(
            event.get("eventName", event.get("event_name", event.get("name", "")))
        ).lower()

    @staticmethod
    def _tracee_evidence(event):
        return json.dumps(event, separators=(",", ":"))[:500]

    @staticmethod
    def _tracee_values(value):
        """Return scalar values from Tracee's nested argument structure."""
        if isinstance(value, dict):
            values = []
            for item in value.values():
                values.extend(ReportPlanCreator._tracee_values(item))
            return values
        if isinstance(value, list):
            values = []
            for item in value:
                values.extend(ReportPlanCreator._tracee_values(item))
            return values
        return [str(value)]

    @classmethod
    def _tracee_details(cls, event):
        """Extract the small pieces of event data useful to a new admin."""
        arguments = event.get("args", [])
        values = []
        named_values = {}
        for argument in arguments if isinstance(arguments, list) else []:
            if not isinstance(argument, dict):
                continue
            name = str(argument.get("name", "")).lower()
            value = argument.get("value")
            named_values[name] = value
            values.extend(cls._tracee_values(value))

        destination = ""
        address = named_values.get("addr")
        if isinstance(address, dict):
            ip = address.get("sin_addr") or address.get("sin6_addr")
            port = address.get("sin_port")
            if ip:
                destination = str(ip)
                if port:
                    destination += ":{}".format(port)
        if not destination:
            for value in values:
                if value.startswith("/"):
                    continue
                match = re.search(
                    r"(?:https?://|ftp://)[^\s\"']+|"
                    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
                    value,
                )
                if match:
                    destination = match.group(0).rstrip(".,)")
                    break

        resource = ""
        for name, value in named_values.items():
            if name in {"pathname", "path", "filename", "target", "name"}:
                candidates = cls._tracee_values(value)
                if candidates and candidates[0].startswith((
                    "/var/run/docker.sock", "/etc/shadow", "/root/.ssh",
                    "/proc/", "/sys/", "/dev/mem",
                )):
                    resource = candidates[0]
                    break
        if not resource:
            for value in values:
                if value.startswith((
                    "/var/run/docker.sock", "/etc/shadow", "/root/.ssh",
                    "/proc/", "/sys/", "/dev/mem",
                )):
                    resource = value
                    break
        return {"destination": destination, "resource": resource}

    def summarize_tracee(self, report=None):
        """Turn Tracee JSON events into a small set of reviewable findings."""
        loaded = self._load_tracee_events() if report is None else report
        if loaded is None:
            return None

        events, parse_errors = loaded
        findings = []
        seen = set()

        def add(category, severity, summary, event):
            event_name = self._tracee_event_name(event)
            details = self._tracee_details(event)
            key = (
                category,
                event_name,
                event.get("processName", ""),
                details["destination"],
                details["resource"],
            )
            if key in seen:
                return
            seen.add(key)
            description = summary
            if category == "network_activity" and details["destination"]:
                description = "The container attempted to contact {} while network access was disabled.".format(
                    details["destination"]
                )
            elif category == "sensitive_resource_access" and details["resource"]:
                description = "The container attempted to access the sensitive resource {}.".format(
                    details["resource"]
                )
            findings.append({
                "id": "tracee-{}-{}".format(category, len(findings) + 1),
                "category": category,
                "severity": severity,
                "title": summary,
                "summary": summary,
                "description": description,
                "event": event_name or "unknown event",
                "process": event.get("processName", "unknown process"),
                "destination": details["destination"],
                "resource": details["resource"],
                "evidence": self._tracee_evidence(event),
            })

        download_commands = ("curl", "wget", "busybox", "git", "ftp", "scp")
        shell_commands = ("/bin/sh", "/bin/bash", "bash", "sh -c", "sudo")
        escape_commands = ("/mount", "mount ", "nsenter", "unshare", "insmod")
        sensitive_paths = (
            "/var/run/docker.sock",
            "/etc/shadow",
            "/root/.ssh",
            "/proc/",
            "/sys/",
            "/dev/mem",
        )
        escape_events = (
            "mount", "umount", "setns", "unshare", "ptrace", "bpf",
            "init_module", "finit_module", "open_by_handle_at", "mknod",
        )
        privilege_events = ("setuid", "setgid", "setresuid", "setresgid", "capset")
        network_events = ("connect", "connectat", "sendto", "sendmsg", "dns")
        persistence_paths = ("/etc/cron", "/etc/systemd", ".bashrc", ".profile")
        download_seen = False

        for event in events:
            event_name = self._tracee_event_name(event)
            event_text = json.dumps(event, separators=(",", ":")).lower()

            if event_name in {"execve", "execveat"} and any(
                command in event_text for command in download_commands
            ):
                download_seen = True
                add(
                    "code_download",
                    "HIGH",
                    "The container downloaded or retrieved code during startup.",
                    event,
                )

            if event_name in {"execve", "execveat"} and any(
                command in event_text for command in shell_commands
            ):
                category = "code_download_and_execution" if download_seen else "unexpected_execution"
                add(
                    category,
                    "CRITICAL" if download_seen else "HIGH",
                    "The container downloaded and executed code."
                    if download_seen
                    else "The container launched a shell or elevated command.",
                    event,
                )

            if any(event_name.startswith(name) for name in network_events):
                add(
                    "network_activity",
                    "HIGH",
                    "The container attempted network communication while network access was denied.",
                    event,
                )

            if any(path in event_text for path in sensitive_paths):
                add(
                    "sensitive_resource_access",
                    "HIGH",
                    "The container accessed a sensitive host or credential resource.",
                    event,
                )

            if any(event_name == name or event_name.startswith(name + "_") for name in escape_events):
                add(
                    "host_escape_behavior",
                    "CRITICAL",
                    "The container attempted an operation associated with host or namespace access.",
                    event,
                )

            if event_name in {"execve", "execveat"} and any(
                command in event_text for command in escape_commands
            ):
                add(
                    "host_escape_behavior",
                    "CRITICAL",
                    "The container attempted to launch a host or namespace access tool.",
                    event,
                )

            if any(event_name == name or event_name.startswith(name + "_") for name in privilege_events):
                add(
                    "privilege_change",
                    "HIGH",
                    "The container attempted to change user identity or Linux capabilities.",
                    event,
                )

            if any(path in event_text for path in persistence_paths) and any(
                word in event_name for word in ("write", "open", "create", "rename", "unlink")
            ):
                add(
                    "persistence_change",
                    "HIGH",
                    "The container modified a location commonly used for automatic startup.",
                    event,
                )

        return {
            "findings": findings,
            "event_count": len(events),
            "parse_errors": parse_errors,
        }

    def summarize_vulnerabilities(self, report=None):
        report = self._load_trivy_report() if report is None else report
        if report is None:
            return None
        findings = []
        for result in report.get("Results", []):
            for vulnerability in result.get("Vulnerabilities", []) or []:
                fixed_version = vulnerability.get("FixedVersion", "")
                findings.append({
                    "id": vulnerability.get("VulnerabilityID", "Unknown"),
                    "severity": vulnerability.get("Severity", "UNKNOWN"),
                    "package": vulnerability.get("PkgName", "Unknown package"),
                    "installed_version": vulnerability.get("InstalledVersion", "Unknown"),
                    "fixed_version": fixed_version,
                    "can_update": bool(fixed_version),
                    "title": vulnerability.get("Title", "No description provided."),
                    "url": vulnerability.get("PrimaryURL", ""),
                })
        return findings

    def summarize_secrets(self, report=None):
        report = self._load_trivy_report() if report is None else report
        if report is None:
            return None
        findings = []
        for result in report.get("Results", []):
            for secret in result.get("Secrets", []) or []:
                findings.append({
                    "type": secret.get("Title", secret.get("Category", "Unknown secret")),
                    "file": secret.get("Target", result.get("Target", "Unknown target")),
                    "line": secret.get("StartLine", "unknown"),
                    "severity": secret.get("Severity", "UNKNOWN"),
                })
        return findings

    def summarize_misconfigurations(self, report=None):
        report = self._load_trivy_report() if report is None else report
        if report is None:
            return None
        findings = []
        for result in report.get("Results", []):
            for misconfiguration in result.get("Misconfigurations", []) or []:
                findings.append({
                    "id": misconfiguration.get("ID", "Unknown"),
                    "severity": misconfiguration.get("Severity", "UNKNOWN"),
                    "title": misconfiguration.get("Title", "Configuration issue"),
                    "target": result.get("Target", "Unknown target"),
                    "status": misconfiguration.get("Status", "FAIL"),
                    "description": misconfiguration.get("Description", ""),
                    "resolution": misconfiguration.get("Resolution", "Review the Docker configuration."),
                    "url": misconfiguration.get("PrimaryURL", ""),
                })
        return findings

    def print_vulnerability_summary(self, findings):
        if not findings:
            print("Trivy found no known vulnerabilities.")
            return
        print("\nTrivy found {} known vulnerabilit{}:".format(
            len(findings), "y" if len(findings) == 1 else "ies"
        ))
        for finding in findings:
            print("\n{} [{}] - {}".format(finding["id"], finding["severity"], finding["package"]))
            print("Installed version: {}".format(finding["installed_version"]))
            if finding["can_update"]:
                print("A fixed version is available: {}".format(finding["fixed_version"]))
                print("Recommended action: update the image or rebuild it with this package updated.")
            else:
                print("No fixed version is currently available.")
                print("Recommended action: review a newer or alternative image, or accept the risk.")

    def print_secret_summary(self, findings):
        if not findings:
            print("No secrets were detected.")
            return
        print("\nTrivy found {} possible secret{}:".format(len(findings), "" if len(findings) == 1 else "s"))
        for finding in findings:
            print("- {} [{}] in {} at line {}".format(
                finding["type"], finding["severity"], finding["file"], finding["line"]
            ))
        print("Do not use this credential until it has been reviewed.")
        print("Recommended action: revoke or rotate it, remove it from the image, rebuild, and scan again.")
        print("Deployment should be rejected until the credential is rotated or this is confirmed as a false positive.")

    def print_misconfiguration_summary(self, findings):
        if not findings:
            print("No Docker misconfigurations were detected.")
            return
        print("\nTrivy found {} Docker misconfiguration{}:".format(len(findings), "" if len(findings) == 1 else "s"))
        for finding in findings:
            print("- {} [{}] in {}".format(finding["title"], finding["severity"], finding["target"]))
            print("  Recommended action: {}".format(finding["resolution"]))

    @staticmethod
    def _misconfiguration_executor(finding):
        text = " ".join(
            str(finding.get(field, ""))
            for field in ("id", "title", "description", "resolution")
        ).lower()
        matches = (
            ("docker socket", "remove_docker_socket_mount"),
            ("docker.sock", "remove_docker_socket_mount"),
            ("privileged", "remove_privileged_mode"),
            ("host network", "remove_host_network"),
            ("network_mode: host", "remove_host_network"),
            ("host pid", "remove_host_pid"),
            ("pidmode", "remove_host_pid"),
            ("host ipc", "remove_host_ipc"),
            ("ipcmode", "remove_host_ipc"),
            ("capabilit", "drop_unnecessary_capabilities"),
            ("setuid", "remove_setuid_setgid_permissions"),
            ("setgid", "remove_setuid_setgid_permissions"),
            ("read-only", "enable_read_only_root_filesystem"),
            ("readonly", "enable_read_only_root_filesystem"),
            ("host mount", "remove_or_narrow_host_mount"),
            ("bind mount", "remove_or_narrow_host_mount"),
            ("published port", "restrict_published_ports"),
        )
        for phrase, executor in matches:
            if phrase in text:
                return executor
        return "fix_misconfiguration_{}".format(finding["id"])

    def actions_for(self, vulnerabilities, secrets, misconfigurations, tracee_findings=None, source_path=None):
        actions = []
        for finding in vulnerabilities:
            executor = "update_image_package"
            actions.append({
                "id": finding["id"],
                "description": "Review {} in {}.".format(finding["id"], finding["package"]),
                "executor": executor,
                "parameters": {
                    "package": finding["package"],
                    "fixed_version": finding["fixed_version"],
                    "source_path": str(source_path) if source_path else None,
                },
                "status": "pending" if PlanExecutor.can_execute(executor) else "manual_review_required",
                "approved": False,
            })
        for finding in secrets:
            executor = "remove_secret_from_image"
            actions.append({
                "id": "secret-{}".format(finding["file"]),
                "description": "Review the possible secret in {}.".format(finding["file"]),
                "executor": executor,
                "parameters": {
                    "file": finding["file"],
                    "line": finding["line"],
                    "source_path": str(source_path) if source_path else None,
                },
                "status": "pending" if PlanExecutor.can_execute(executor) else "manual_review_required",
                "approved": False,
            })
        for finding in misconfigurations:
            executor = self._misconfiguration_executor(finding)
            actions.append({
                "id": finding["id"],
                "description": finding["title"],
                "executor": executor,
                "status": "pending" if PlanExecutor.can_execute(executor) else "manual_review_required",
                "approved": False,
            })
        for finding in tracee_findings or []:
            actions.append({
                "id": finding["id"],
                "description": finding["summary"],
                "executor": "apply_tracee_permission",
                "parameters": {
                    "category": finding["category"],
                    "destination": finding.get("destination", ""),
                    "resource": finding.get("resource", ""),
                },
                "status": "manual_review_required",
                "approved": False,
            })
        return actions
