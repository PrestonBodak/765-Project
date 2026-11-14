import json
import shutil
import subprocess
import tarfile
import uuid
from pathlib import Path


class PlanExecutor:
    """Apply approved plan actions and sanitize their generated reports."""

    HANDLERS = {}
    HANDLER_SPECS = {
        "update_image_package": "Update a vulnerable package and rebuild the image.",
        "update_base_image": "Replace the vulnerable base image and rebuild.",
        "update_language_dependency": "Update an application dependency and rebuild.",
        "replace_image": "Use a newer or alternative image.",
        "remove_secret_from_source": "Remove a secret from the image source.",
        "replace_secret_with_runtime_value": "Move a secret to runtime configuration.",
        "remove_secret_from_image": "Rebuild the image without the secret.",
        "verify_secret_removed": "Confirm the secret is absent after rebuilding.",
        "set_non_root_user": "Configure the image to run as a non-root user.",
        "remove_privileged_mode": "Remove privileged container execution.",
        "drop_unnecessary_capabilities": "Remove unnecessary Linux capabilities.",
        "enable_no_new_privileges": "Enable no-new-privileges.",
        "enable_read_only_root_filesystem": "Use a read-only root filesystem.",
        "remove_setuid_setgid_permissions": "Remove unnecessary setuid/setgid permissions.",
        "pin_base_image_version": "Pin the base image to a known version or digest.",
        "remove_remote_download": "Remove unsafe remote downloads from the build.",
        "replace_unsafe_add_instruction": "Replace unsafe ADD usage with a safer instruction.",
        "add_healthcheck": "Add a container health check.",
        "remove_docker_socket_mount": "Remove access to the Docker socket.",
        "remove_or_narrow_host_mount": "Remove or narrow a host filesystem mount.",
        "remove_host_network": "Replace host networking with a restricted network.",
        "remove_host_pid": "Remove host PID namespace access.",
        "remove_host_ipc": "Remove host IPC namespace access.",
        "restrict_published_ports": "Restrict published ports to required services.",
        "add_cpu_limit": "Add a CPU resource limit.",
        "add_memory_limit": "Add a memory resource limit.",
        "add_process_limit": "Add a process limit.",
        "create_candidate_image": "Build a candidate image without changing the original.",
        "validate_candidate_configuration": "Validate the candidate configuration.",
        "start_candidate_container": "Start the candidate in the isolated environment.",
        "run_health_check": "Verify that the candidate service starts and responds.",
        "rerun_security_scan": "Run all security scanners against the candidate.",
        "compare_before_after_results": "Compare original and candidate scan results.",
        "rollback_candidate": "Discard the candidate and restore the original image.",
        "promote_candidate_image": "Promote a verified candidate image.",
    }

    @classmethod
    def register_handler(cls, name, handler):
        cls.HANDLERS[name] = handler

    @classmethod
    def handler_for(cls, name):
        return cls.HANDLERS.get(name)

    @classmethod
    def handler_spec(cls, name):
        return cls.HANDLER_SPECS.get(name)

    @classmethod
    def can_execute(cls, name):
        return cls.handler_for(name) is not None

    def execute(self, action, **kwargs):
        handler = self.handler_for(action.get("executor"))
        if handler is None:
            return {
                "status": "manual_review_required",
                "action": action.get("id"),
                "reason": self.handler_spec(action.get("executor")) or "No handler is registered.",
            }
        return handler(**kwargs)

    def execute_plan(self, plan, image, run_dir, verify=None):
        """Apply approved actions to a candidate and verify each one."""
        actions = [action for action in plan.get("actions", []) if action.get("approved")]
        if not actions:
            plan["decision"] = "no_changes_requested"
            return {"status": "no_changes_requested", "actions": []}

        for action in actions:
            if not self.can_execute(action.get("executor")):
                action["status"] = "manual_review_required"
                action["execution"] = self.execute(action)
                plan["decision"] = "manual_review_required"
                return {"status": "manual_review_required", "action": action["id"]}

        if verify is None:
            plan["decision"] = "verification_required"
            return {"status": "verification_required", "actions": []}

        candidate = self.create_candidate(image, run_dir, actions)
        if candidate is None:
            plan["decision"] = "candidate_creation_failed"
            return {"status": "candidate_creation_failed", "actions": []}

        plan["candidate_image"] = candidate["image"]
        for action in actions:
            result = self.execute(
                action,
                image=image,
                candidate_container=candidate["container"],
                candidate_image=candidate["image"],
                run_dir=run_dir,
                plan=plan,
            )
            action["execution"] = result
            if result.get("status") != "applied":
                action["status"] = result.get("status", "failed")
                self.rollback_candidate(candidate)
                plan["decision"] = "rolled_back"
                return {"status": "rolled_back", "action": action["id"]}

            if not self.commit_candidate(candidate):
                action["status"] = "candidate_commit_failed"
                self.rollback_candidate(candidate)
                plan["decision"] = "rolled_back"
                return {"status": "rolled_back", "action": action["id"]}

            verification = verify(candidate["image"], action, plan)
            action["verification"] = verification
            if verification.get("status") != "passed":
                action["status"] = "verification_failed"
                self.rollback_candidate(candidate)
                plan["decision"] = "rolled_back"
                return {"status": "rolled_back", "action": action["id"]}

            action["status"] = "completed"

        promoted = self.promote_candidate(candidate)
        if promoted.get("status") != "promoted":
            self.rollback_candidate(candidate)
            plan["decision"] = "rolled_back"
            return {"status": "rolled_back", "actions": actions}

        plan["decision"] = "changes_applied"
        return {"status": "changes_applied", "actions": actions}

    def create_candidate(self, image, run_dir, actions=None):
        """Create an isolated candidate container and image tag."""
        run_name = "{}_{}".format(Path(run_dir).name, uuid.uuid4().hex[:6])
        name = "securityscan-{}-candidate".format(run_name)
        image_tag = "securityscan/{}:candidate".format(run_name)
        command = ["sudo", "docker", "create", "--name", name]
        executors = {action.get("executor") for action in actions or []}
        if "drop_unnecessary_capabilities" in executors:
            command.extend(["--cap-drop", "ALL"])
        if "enable_no_new_privileges" in executors:
            command.extend(["--security-opt", "no-new-privileges"])
        if "enable_read_only_root_filesystem" in executors:
            command.append("--read-only")
        # Docker uses private namespaces and no host mounts/ports by default.
        # These options deliberately stay absent for the corresponding fixes.
        command.append(image)
        create = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )
        if create.returncode != 0:
            return None

        start = subprocess.run(
            ["sudo", "docker", "start", name],
            capture_output=True,
            text=True,
        )
        if start.returncode != 0:
            subprocess.run(
                ["sudo", "docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return None

        return {"container": name, "image": image_tag}

    def commit_candidate(self, candidate):
        result = subprocess.run(
            ["sudo", "docker", "commit", candidate["container"], candidate["image"]],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def rollback_candidate(self, candidate):
        subprocess.run(
            ["sudo", "docker", "rm", "-f", candidate["container"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["sudo", "docker", "rmi", "-f", candidate["image"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def promote_candidate(self, candidate):
        if not self.commit_candidate(candidate):
            return {"status": "promotion_failed"}
        subprocess.run(
            ["sudo", "docker", "rm", "-f", candidate["container"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {"status": "promoted", "image": candidate["image"]}

    def image_id(self, image):
        result = subprocess.run(
            ["sudo", "docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def export_filesystem(self, image, run_dir):
        export_dir = Path("containers") / ".securityscan" / Path(run_dir).name
        export_dir.mkdir(parents=True, exist_ok=True)
        archive_path = export_dir / "filesystem.tar"

        create = subprocess.run(
            ["sudo", "docker", "create", image],
            capture_output=True,
            text=True,
        )
        if create.returncode != 0:
            return None

        container_id = create.stdout.strip()
        try:
            with open(archive_path, "wb") as archive_file:
                export = subprocess.run(
                    ["sudo", "docker", "export", container_id],
                    stdout=archive_file,
                    stderr=subprocess.PIPE,
                )
            if export.returncode != 0:
                return None

            filesystem_dir = export_dir / "filesystem"
            filesystem_dir.mkdir()
            with tarfile.open(archive_path) as archive:
                archive.extractall(filesystem_dir, filter=self._extract_filter)
            return filesystem_dir
        except (OSError, tarfile.TarError):
            self.remove_export(run_dir)
            return None
        finally:
            subprocess.run(
                ["sudo", "docker", "rm", container_id],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    @staticmethod
    def _extract_filter(member, destination):
        if (member.issym() or member.islnk()) and member.linkname.startswith("/"):
            return None
        return tarfile.data_filter(member, destination)

    def remove_export(self, run_dir):
        export_dir = Path("containers") / ".securityscan" / Path(run_dir).name
        if export_dir.exists():
            shutil.rmtree(export_dir)

    def redact_secret_values(self, report_path="scan_outputs/trivy_out.json"):
        """Remove secret contents before a report is copied or shared."""
        try:
            with open(report_path, "r") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError):
            return False

        sensitive_fields = {"match", "secret", "plaintext", "value"}
        for result in report.get("Results", []):
            for secret in result.get("Secrets", []) or []:
                for field in list(secret):
                    if field.lower() in sensitive_fields:
                        secret[field] = "[REDACTED]"

        try:
            with open(report_path, "w") as report_file:
                json.dump(report, report_file, indent=2)
        except OSError:
            return False

        return True


# These functions define the remediation API. They are intentionally not
# registered until they can safely edit the user's source configuration,
# build a candidate image, and verify or roll back that candidate.
def _unimplemented_handler(name, **kwargs):
    return {
        "status": "manual_review_required",
        "handler": name,
        "reason": "Handler requires an input configuration and verification workflow.",
    }


def update_image_package(**kwargs): return _unimplemented_handler("update_image_package", **kwargs)
def update_base_image(**kwargs): return _unimplemented_handler("update_base_image", **kwargs)
def update_language_dependency(**kwargs): return _unimplemented_handler("update_language_dependency", **kwargs)
def replace_image(**kwargs): return _unimplemented_handler("replace_image", **kwargs)
def remove_secret_from_source(**kwargs): return _unimplemented_handler("remove_secret_from_source", **kwargs)
def replace_secret_with_runtime_value(**kwargs): return _unimplemented_handler("replace_secret_with_runtime_value", **kwargs)
def remove_secret_from_image(**kwargs): return _unimplemented_handler("remove_secret_from_image", **kwargs)
def verify_secret_removed(**kwargs): return _unimplemented_handler("verify_secret_removed", **kwargs)
def set_non_root_user(**kwargs): return _unimplemented_handler("set_non_root_user", **kwargs)
def _inspect_candidate(candidate_container, field):
    result = subprocess.run(
        ["sudo", "docker", "inspect", "--format", field, candidate_container],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _verified_runtime_handler(name, candidate_container, expected, field):
    if not candidate_container:
        return _unimplemented_handler(name)
    actual = _inspect_candidate(candidate_container, field)
    if actual is None:
        return {"status": "failed", "handler": name, "reason": "Could not inspect the candidate."}
    if actual != expected:
        return {
            "status": "failed",
            "handler": name,
            "reason": "Candidate setting did not match the requested value.",
            "expected": expected,
            "actual": actual,
        }
    return {"status": "applied", "handler": name, "candidate_container": candidate_container}


def remove_privileged_mode(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "remove_privileged_mode", candidate_container, "false", "{{.HostConfig.Privileged}}"
    )


def drop_unnecessary_capabilities(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "drop_unnecessary_capabilities", candidate_container, '["ALL"]', "{{json .HostConfig.CapDrop}}"
    )


def enable_no_new_privileges(candidate_container=None, **kwargs):
    security_opt = _inspect_candidate(candidate_container, "{{json .HostConfig.SecurityOpt}}")
    if security_opt is None:
        return {"status": "failed", "handler": "enable_no_new_privileges", "reason": "Could not inspect the candidate."}
    if "no-new-privileges" not in security_opt:
        return {"status": "failed", "handler": "enable_no_new_privileges", "reason": "Candidate does not enable no-new-privileges."}
    return {"status": "applied", "handler": "enable_no_new_privileges", "candidate_container": candidate_container}


def enable_read_only_root_filesystem(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "enable_read_only_root_filesystem", candidate_container, "true", "{{.HostConfig.ReadonlyRootfs}}"
    )


def remove_host_network(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "remove_host_network", candidate_container, "default", "{{.HostConfig.NetworkMode}}"
    )


def remove_host_pid(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "remove_host_pid", candidate_container, "", "{{.HostConfig.PidMode}}"
    )


def remove_host_ipc(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "remove_host_ipc", candidate_container, "", "{{.HostConfig.IpcMode}}"
    )
def remove_setuid_setgid_permissions(**kwargs): return _unimplemented_handler("remove_setuid_setgid_permissions", **kwargs)
def pin_base_image_version(**kwargs): return _unimplemented_handler("pin_base_image_version", **kwargs)
def remove_remote_download(**kwargs): return _unimplemented_handler("remove_remote_download", **kwargs)
def replace_unsafe_add_instruction(**kwargs): return _unimplemented_handler("replace_unsafe_add_instruction", **kwargs)
def add_healthcheck(**kwargs): return _unimplemented_handler("add_healthcheck", **kwargs)
def remove_docker_socket_mount(**kwargs): return _unimplemented_handler("remove_docker_socket_mount", **kwargs)
def remove_or_narrow_host_mount(**kwargs): return _unimplemented_handler("remove_or_narrow_host_mount", **kwargs)
def restrict_published_ports(**kwargs): return _unimplemented_handler("restrict_published_ports", **kwargs)
def add_cpu_limit(**kwargs): return _unimplemented_handler("add_cpu_limit", **kwargs)
def add_memory_limit(**kwargs): return _unimplemented_handler("add_memory_limit", **kwargs)
def add_process_limit(**kwargs): return _unimplemented_handler("add_process_limit", **kwargs)
def create_candidate_image(**kwargs): return _unimplemented_handler("create_candidate_image", **kwargs)
def validate_candidate_configuration(**kwargs): return _unimplemented_handler("validate_candidate_configuration", **kwargs)
def start_candidate_container(**kwargs): return _unimplemented_handler("start_candidate_container", **kwargs)
def run_health_check(**kwargs): return _unimplemented_handler("run_health_check", **kwargs)
def rerun_security_scan(**kwargs): return _unimplemented_handler("rerun_security_scan", **kwargs)
def compare_before_after_results(**kwargs): return _unimplemented_handler("compare_before_after_results", **kwargs)
def rollback_candidate(**kwargs): return _unimplemented_handler("rollback_candidate", **kwargs)
def promote_candidate_image(**kwargs): return _unimplemented_handler("promote_candidate_image", **kwargs)


PlanExecutor.register_handler("remove_privileged_mode", remove_privileged_mode)
PlanExecutor.register_handler("drop_unnecessary_capabilities", drop_unnecessary_capabilities)
PlanExecutor.register_handler("enable_no_new_privileges", enable_no_new_privileges)
PlanExecutor.register_handler("enable_read_only_root_filesystem", enable_read_only_root_filesystem)
PlanExecutor.register_handler("remove_host_network", remove_host_network)
PlanExecutor.register_handler("remove_host_pid", remove_host_pid)
PlanExecutor.register_handler("remove_host_ipc", remove_host_ipc)
