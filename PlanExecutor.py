import json
import re
import shlex
import shutil
import subprocess
import tarfile
import uuid
from pathlib import Path
from ScanPaths import FIXED_DIR, SCAN_DIR


class PlanExecutor:
    """Apply approved plan actions and sanitize their generated reports."""

    HANDLERS = {}
    DEFAULT_RUNTIME_LIMITS = {
        "cpu": "1.0",
        "memory": "512m",
        "pids": "256",
    }
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
        "apply_tracee_permission": "Apply a narrowly scoped permission for an approved runtime behavior.",
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

    @staticmethod
    def _source_action(name):
        return name in {
            "update_image_package",
            "remove_secret_from_image",
        }

    def execute(self, action, **kwargs):
        handler = self.handler_for(action.get("executor"))
        if handler is None:
            return {
                "status": "manual_review_required",
                "action": action.get("id"),
                "reason": self.handler_spec(action.get("executor")) or "No handler is registered.",
            }
        handler_kwargs = dict(action.get("parameters", {}))
        handler_kwargs.update(kwargs)
        return handler(**handler_kwargs)

    def execute_plan(self, plan, image, run_dir, verify=None, source_path=None, compose_service=None):
        """Apply approved actions to a candidate and verify each one."""
        actions = [action for action in plan.get("actions", []) if action.get("approved")]
        if not actions:
            plan["decision"] = "no_changes_requested"
            return {"status": "no_changes_requested", "actions": []}

        for action in actions:
            if self._source_action(action.get("executor")):
                if source_path is None:
                    action["status"] = "manual_review_required"
                    action["execution"] = {
                        "status": "manual_review_required",
                        "reason": "A Dockerfile or Compose source path is required for this change.",
                    }
                    plan["decision"] = "manual_review_required"
                    return {"status": "manual_review_required", "action": action["id"]}
                continue
            if not self.can_execute(action.get("executor")):
                action["status"] = "manual_review_required"
                action["execution"] = self.execute(action)
                plan["decision"] = "manual_review_required"
                return {"status": "manual_review_required", "action": action["id"]}

        if verify is None:
            plan["decision"] = "verification_required"
            return {"status": "verification_required", "actions": []}

        source_actions = [action for action in actions if self._source_action(action.get("executor"))]
        candidate_base = image
        source_result = None
        if source_actions:
            source_result = self.prepare_source_image(
                source_path, run_dir, source_actions, compose_service
            )
            if source_result.get("status") != "applied":
                for action in source_actions:
                    action["status"] = source_result.get("status", "failed")
                    action["execution"] = source_result
                plan["decision"] = source_result.get("status", "failed")
                return {"status": plan["decision"], "actions": source_actions}
            candidate_base = source_result["image"]

        candidate = self.create_candidate(candidate_base, run_dir, actions)
        if candidate is None:
            plan["decision"] = "candidate_creation_failed"
            return {"status": "candidate_creation_failed", "actions": []}

        plan["candidate_image"] = candidate["image"]
        for action in actions:
            if self._source_action(action.get("executor")):
                result = {
                    "status": "applied",
                    "handler": action.get("executor"),
                    "source_context": source_result.get("context"),
                }
            else:
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

        promoted = self.promote_candidate(candidate, run_dir)
        if promoted.get("status") != "promoted":
            self.rollback_candidate(candidate)
            plan["decision"] = "rolled_back"
            return {"status": "rolled_back", "actions": actions}

        plan["decision"] = "changes_applied"
        plan["candidate_archive"] = promoted["archive"]
        return {"status": "changes_applied", "actions": actions}

    def create_candidate(self, image, run_dir, actions=None):
        """Create a candidate with deny-by-default Docker settings."""
        run_name = "{}_{}".format(Path(run_dir).name, uuid.uuid4().hex[:6])
        name = "securityscan-{}-candidate".format(run_name)
        image_tag = "securityscan/{}:candidate".format(run_name)
        command = ["sudo", "docker", "create", "--name", name]
        executors = {action.get("executor") for action in actions or []}
        # Every candidate starts from the strict MVP policy. An approved finding
        # can document why a setting is needed, but never weakens these defaults.
        command.extend([
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--pids-limit", self.DEFAULT_RUNTIME_LIMITS["pids"],
        ])
        if "set_non_root_user" in executors:
            command.extend(["--user", "65532:65532"])
        if "add_cpu_limit" in executors:
            command.extend(["--cpus", self.DEFAULT_RUNTIME_LIMITS["cpu"]])
        if "add_memory_limit" in executors:
            command.extend(["--memory", self.DEFAULT_RUNTIME_LIMITS["memory"]])
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

        state = subprocess.run(
            ["sudo", "docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", name],
            capture_output=True,
            text=True,
        )
        if state.returncode != 0:
            self.rollback_candidate({"container": name, "image": image_tag})
            return None
        status, _, exit_code = state.stdout.strip().partition(" ")
        if status == "exited" and exit_code != "0":
            self.rollback_candidate({"container": name, "image": image_tag})
            return None

        return {"container": name, "image": image_tag}

    def prepare_source_image(self, source_path, run_dir, actions, compose_service=None):
        """Patch a copied Dockerfile, then build one candidate image."""
        source = Path(source_path).expanduser().resolve()
        if not source.exists():
            return {"status": "manual_review_required", "reason": "Source path does not exist."}

        context = Path(run_dir) / "build_context"
        if context.exists():
            shutil.rmtree(context)
        context.mkdir(parents=True)
        compose_file = None
        if source.is_dir():
            for item in source.iterdir():
                destination = context / item.name
                if item.is_dir():
                    shutil.copytree(item, destination)
                else:
                    shutil.copy2(item, destination)
            for name in ("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"):
                possible = context / name
                if possible.exists():
                    compose_file = possible
                    break
        else:
            if source.name.lower() not in {"dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}:
                return {"status": "manual_review_required", "reason": "Source must be a Dockerfile or Compose project."}
            if source.name.lower().startswith("dockerfile"):
                shutil.copy2(source, context / "Dockerfile")
            else:
                shutil.copy2(source, context / source.name)
                compose_file = context / source.name

        if compose_file:
            return self._prepare_compose_image(
                context, compose_file, actions, compose_service, run_dir
            )

        dockerfile = context / "Dockerfile"
        if not dockerfile.exists():
            return {"status": "manual_review_required", "reason": "No Dockerfile was found in the source path."}

        for action in actions:
            result = self.apply_source_action(context, dockerfile, action)
            if result.get("status") != "applied":
                return result

        tag = "securityscan/{}:source-candidate".format(Path(run_dir).name)
        build = subprocess.run(
            ["sudo", "docker", "build", "--pull", "-t", tag, "-f", str(dockerfile), str(context)],
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            return {"status": "failed", "reason": "The patched source could not be rebuilt.", "output": build.stderr[-2000:]}
        return {"status": "applied", "image": tag, "context": str(context)}

    def _prepare_compose_image(self, context, compose_file, actions, service, run_dir):
        services = subprocess.run(
            ["sudo", "docker", "compose", "-f", str(compose_file), "config", "--services"],
            cwd=context,
            capture_output=True,
            text=True,
        )
        if services.returncode != 0:
            return {"status": "failed", "reason": "Compose configuration could not be validated."}
        service_names = [line.strip() for line in services.stdout.splitlines() if line.strip()]
        if service is None and len(service_names) == 1:
            service = service_names[0]
        if service not in service_names:
            return {
                "status": "manual_review_required",
                "reason": "A valid Compose service name is required when the project has multiple services.",
                "services": service_names,
            }

        dockerfile = context / "Dockerfile"
        if any(action.get("executor") in {"update_image_package", "remove_secret_from_image"} for action in actions):
            if not dockerfile.exists():
                return {"status": "manual_review_required", "reason": "The Compose service has no local Dockerfile to rebuild."}
            for action in actions:
                result = self.apply_source_action(context, dockerfile, action)
                if result.get("status") != "applied":
                    return result

        override = context / ".securityscan.override.yml"
        override_lines = [
            "services:",
            "  {}:".format(service),
            "    network_mode: none",
            "    cap_drop:",
            "      - ALL",
            "    security_opt:",
            "      - no-new-privileges:true",
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp:rw,noexec,nosuid,size=64m",
            "    pids_limit: 256",
        ]
        executors = {action.get("executor") for action in actions}
        if "add_cpu_limit" in executors:
            override_lines.append("    cpus: 1.0")
        if "add_memory_limit" in executors:
            override_lines.append("    mem_limit: 512m")
        if "set_non_root_user" in executors:
            override_lines.append("    user: \"65532:65532\"")
        override.write_text("\n".join(override_lines) + "\n")
        files = ["-f", str(compose_file), "-f", str(override)]
        build = subprocess.run(
            ["sudo", "docker", "compose"] + files + ["build", "--pull", service],
            cwd=context,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            return {"status": "failed", "reason": "The hardened Compose service could not be rebuilt.", "output": build.stderr[-2000:]}
        images = subprocess.run(
            ["sudo", "docker", "compose"] + files + ["images", "-q", service],
            cwd=context,
            capture_output=True,
            text=True,
        )
        image_id = images.stdout.strip().splitlines()[0] if images.returncode == 0 and images.stdout.strip() else ""
        if not image_id:
            return {"status": "failed", "reason": "Compose did not produce an image for the selected service."}
        tag = "securityscan/{}:compose-candidate".format(Path(run_dir).name)
        tagged = subprocess.run(
            ["sudo", "docker", "tag", image_id, tag],
            capture_output=True,
            text=True,
        )
        if tagged.returncode != 0:
            return {"status": "failed", "reason": "The Compose candidate could not be tagged."}
        return {
            "status": "applied",
            "image": tag,
            "context": str(context),
            "compose_override": str(override),
            "service": service,
        }

    def apply_source_action(self, context, dockerfile, action):
        executor = action.get("executor")
        parameters = action.get("parameters", {})
        if executor == "update_image_package":
            return self._patch_package_update(
                dockerfile, parameters.get("package"), parameters.get("fixed_version")
            )
        if executor == "remove_secret_from_image":
            return self._remove_secret_source(
                context, parameters.get("file"), parameters.get("line")
            )
        if executor == "update_base_image":
            return self._replace_base_image(dockerfile, parameters.get("new_base_image"))
        return {"status": "manual_review_required", "reason": "Unsupported source action."}

    @staticmethod
    def _dockerfile_lines(path):
        try:
            return path.read_text().splitlines()
        except OSError:
            return None

    def _patch_package_update(self, dockerfile, package, fixed_version):
        if not package or not fixed_version:
            return {"status": "manual_review_required", "reason": "Trivy did not provide a fixed package version."}
        if not re.fullmatch(r"[A-Za-z0-9.+_:@=-]+", package) or not re.fullmatch(r"[A-Za-z0-9.+_:@=-]+", fixed_version):
            return {"status": "manual_review_required", "reason": "Package values contain unsupported characters."}
        lines = self._dockerfile_lines(dockerfile)
        if lines is None:
            return {"status": "failed", "reason": "Could not read the Dockerfile."}
        text = "\n".join(lines).lower()
        if "apt-get" in text or "debian" in text or "ubuntu" in text:
            command = "RUN apt-get update && apt-get install -y --only-upgrade {}={} && rm -rf /var/lib/apt/lists/*".format(package, fixed_version)
        elif "apk" in text or "alpine" in text:
            command = "RUN apk add --no-cache {}={}".format(package, fixed_version)
        elif "pip" in text or "python" in text:
            command = "RUN python -m pip install --no-cache-dir {}=={}".format(package, fixed_version)
        elif "npm" in text or "node" in text:
            command = "RUN npm install --omit=dev {}@{}".format(package, fixed_version)
        else:
            return {"status": "manual_review_required", "reason": "The Dockerfile package manager was not recognized."}
        insert_at = len(lines)
        for index, line in enumerate(lines):
            if re.match(r"\s*(USER|CMD|ENTRYPOINT|HEALTHCHECK)\b", line, re.IGNORECASE):
                insert_at = index
                break
        lines.insert(insert_at, command)
        dockerfile.write_text("\n".join(lines) + "\n")
        return {"status": "applied", "handler": "update_image_package", "package": package, "fixed_version": fixed_version}

    def _remove_secret_source(self, context, file, line):
        if not file or line in (None, "unknown"):
            return {"status": "manual_review_required", "reason": "The secret location is incomplete."}
        try:
            line_number = int(line)
        except (TypeError, ValueError):
            return {"status": "manual_review_required", "reason": "The secret line number is invalid."}
        relative = Path(file)
        if relative.is_absolute() or ".." in relative.parts or line_number < 1:
            return {"status": "manual_review_required", "reason": "The secret path is not safe to edit automatically."}
        target = (context / relative).resolve()
        if context.resolve() not in target.parents or not target.is_file():
            return {"status": "manual_review_required", "reason": "The secret file is not inside the build context."}
        lines = target.read_text().splitlines()
        if line_number > len(lines):
            return {"status": "manual_review_required", "reason": "The secret line is no longer present."}
        del lines[line_number - 1]
        target.write_text("\n".join(lines) + ("\n" if lines else ""))
        return {"status": "applied", "handler": "remove_secret_from_image", "file": file, "line": line_number}

    def _replace_base_image(self, dockerfile, new_base_image):
        if not new_base_image or not re.fullmatch(r"[A-Za-z0-9./:@_-]+", new_base_image):
            return {"status": "manual_review_required", "reason": "A safe replacement base image was not provided."}
        lines = self._dockerfile_lines(dockerfile)
        if lines is None:
            return {"status": "failed", "reason": "Could not read the Dockerfile."}
        for index, line in enumerate(lines):
            match = re.match(r"(\s*FROM\s+)([^\s]+)(.*)", line, re.IGNORECASE)
            if not match:
                continue
            old = match.group(2).split("@")[0].split(":")[0]
            new = new_base_image.split("@")[0].split(":")[0]
            if old != new:
                return {"status": "manual_review_required", "reason": "Replacement base image is outside the original image family."}
            lines[index] = match.group(1) + new_base_image + match.group(3)
            dockerfile.write_text("\n".join(lines) + "\n")
            return {"status": "applied", "handler": "update_base_image", "image": new_base_image}
        return {"status": "manual_review_required", "reason": "No base image instruction was found."}

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

    def promote_candidate(self, candidate, run_dir):
        if not self.commit_candidate(candidate):
            return {"status": "promotion_failed"}
        archive_dir = FIXED_DIR
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_path = (archive_dir / "{}-fixed.tar".format(Path(run_dir).name)).resolve()
        saved = subprocess.run(
            ["sudo", "docker", "save", "--output", str(archive_path), candidate["image"]],
            capture_output=True,
            text=True,
        )
        if saved.returncode != 0:
            return {"status": "promotion_failed", "reason": "Could not save the candidate archive."}
        subprocess.run(
            ["sudo", "docker", "rm", "-f", candidate["container"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {
            "status": "promoted",
            "image": candidate["image"],
            "archive": str(archive_path),
        }

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
        export_dir = Path(run_dir) / "container"
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
        export_dir = Path(run_dir) / "container"
        if export_dir.exists():
            shutil.rmtree(export_dir)

    def redact_secret_values(self, report_path=None):
        """Remove secret contents before a report is copied or shared."""
        report_path = SCAN_DIR / "trivy_out.json" if report_path is None else report_path
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


def update_base_image(**kwargs): return _unimplemented_handler("update_base_image", **kwargs)
def update_language_dependency(**kwargs): return _unimplemented_handler("update_language_dependency", **kwargs)
def replace_image(**kwargs): return _unimplemented_handler("replace_image", **kwargs)
def remove_secret_from_source(**kwargs): return _unimplemented_handler("remove_secret_from_source", **kwargs)
def replace_secret_with_runtime_value(**kwargs): return _unimplemented_handler("replace_secret_with_runtime_value", **kwargs)
def verify_secret_removed(**kwargs): return _unimplemented_handler("verify_secret_removed", **kwargs)
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
        "remove_host_network", candidate_container, "none", "{{.HostConfig.NetworkMode}}"
    )


def remove_host_pid(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "remove_host_pid", candidate_container, "", "{{.HostConfig.PidMode}}"
    )


def remove_host_ipc(candidate_container=None, **kwargs):
    return _verified_runtime_handler(
        "remove_host_ipc", candidate_container, "", "{{.HostConfig.IpcMode}}"
    )


def _candidate_json(candidate_container, field):
    value = _inspect_candidate(candidate_container, field)
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _run_in_candidate(candidate_container, command):
    return subprocess.run(
        ["sudo", "docker", "exec", candidate_container] + command,
        capture_output=True,
        text=True,
    )


def update_image_package(candidate_container=None, package=None, fixed_version=None, **kwargs):
    """Update one Trivy package inside the isolated candidate container."""
    if not candidate_container or not package or not fixed_version:
        return _unimplemented_handler("update_image_package", **kwargs)
    safe_value = re.compile(r"^[A-Za-z0-9.+_:@=-]+$")
    if not safe_value.fullmatch(package) or not safe_value.fullmatch(fixed_version):
        return {
            "status": "manual_review_required",
            "handler": "update_image_package",
            "reason": "Package values contain unsupported characters.",
        }

    managers = [
        (
            ["apt-get", "--version"],
            ["apt-get", "update"],
            ["apt-get", "install", "-y", "{}={}".format(package, fixed_version)],
        ),
        (
            ["apk", "--version"],
            ["apk", "update"],
            ["apk", "add", "{}={}".format(package, fixed_version)],
        ),
    ]
    for probe, update, install in managers:
        if _run_in_candidate(candidate_container, probe).returncode != 0:
            continue
        if _run_in_candidate(candidate_container, update).returncode != 0:
            return {"status": "failed", "handler": "update_image_package", "reason": "Package index update failed."}
        if _run_in_candidate(candidate_container, install).returncode != 0:
            return {"status": "failed", "handler": "update_image_package", "reason": "Package update failed."}
        return {
            "status": "applied",
            "handler": "update_image_package",
            "package": package,
            "fixed_version": fixed_version,
        }

    return {
        "status": "manual_review_required",
        "handler": "update_image_package",
        "reason": "The candidate does not provide a supported package manager.",
    }


def remove_secret_from_image(candidate_container=None, file=None, line=None, **kwargs):
    """Remove the reported secret line from the isolated candidate filesystem."""
    if not candidate_container or not file or line in (None, "unknown"):
        return _unimplemented_handler("remove_secret_from_image", **kwargs)
    try:
        line_number = int(line)
    except (TypeError, ValueError):
        return _unimplemented_handler("remove_secret_from_image", **kwargs)
    if line_number < 1 or file.startswith("/") or ".." in Path(file).parts:
        return {
            "status": "manual_review_required",
            "handler": "remove_secret_from_image",
            "reason": "The reported secret path is not safe to edit automatically.",
        }

    target = "/" + file
    command = ["sh", "-c", "sed -i '{}d' -- {}".format(line_number, shlex.quote(target))]
    if _run_in_candidate(candidate_container, command).returncode != 0:
        return {
            "status": "failed",
            "handler": "remove_secret_from_image",
            "reason": "Could not remove the reported secret line.",
        }
    return {
        "status": "applied",
        "handler": "remove_secret_from_image",
        "file": file,
        "line": line_number,
    }


def remove_docker_socket_mount(candidate_container=None, **kwargs):
    mounts = _candidate_json(candidate_container, "{{json .Mounts}}")
    if mounts is None:
        return {"status": "failed", "handler": "remove_docker_socket_mount", "reason": "Could not inspect candidate mounts."}
    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")
        if "docker.sock" in source or "docker.sock" in destination:
            return {"status": "failed", "handler": "remove_docker_socket_mount", "reason": "Candidate still exposes the Docker socket."}
    return {"status": "applied", "handler": "remove_docker_socket_mount", "candidate_container": candidate_container}


def remove_or_narrow_host_mount(candidate_container=None, **kwargs):
    mounts = _candidate_json(candidate_container, "{{json .Mounts}}")
    if mounts is None:
        return {"status": "failed", "handler": "remove_or_narrow_host_mount", "reason": "Could not inspect candidate mounts."}
    if any(mount.get("Type") == "bind" for mount in mounts):
        return {"status": "failed", "handler": "remove_or_narrow_host_mount", "reason": "Candidate still has a host bind mount."}
    return {"status": "applied", "handler": "remove_or_narrow_host_mount", "candidate_container": candidate_container}


def restrict_published_ports(candidate_container=None, **kwargs):
    bindings = _candidate_json(candidate_container, "{{json .HostConfig.PortBindings}}")
    if bindings is None:
        return {"status": "failed", "handler": "restrict_published_ports", "reason": "Could not inspect candidate ports."}
    if any(bindings.values()):
        return {"status": "failed", "handler": "restrict_published_ports", "reason": "Candidate still publishes a port."}
    return {"status": "applied", "handler": "restrict_published_ports", "candidate_container": candidate_container}


def remove_setuid_setgid_permissions(candidate_container=None, **kwargs):
    if not candidate_container:
        return _unimplemented_handler("remove_setuid_setgid_permissions", **kwargs)
    result = _run_in_candidate(
        candidate_container,
        [
            "sh",
            "-c",
            "find / -xdev -type f -perm /6000 -exec chmod a-s {} +",
        ],
    )
    if result.returncode != 0:
        return {
            "status": "failed",
            "handler": "remove_setuid_setgid_permissions",
            "reason": "Could not remove setuid/setgid permissions.",
        }
    return {
        "status": "applied",
        "handler": "remove_setuid_setgid_permissions",
        "candidate_container": candidate_container,
    }


def set_non_root_user(candidate_container=None, **kwargs):
    user = _inspect_candidate(candidate_container, "{{.Config.User}}")
    if user is None:
        return {"status": "failed", "handler": "set_non_root_user", "reason": "Could not inspect the candidate user."}
    if user not in {"65532", "65532:65532"}:
        return {"status": "failed", "handler": "set_non_root_user", "reason": "Candidate is not configured for the non-root runtime user."}
    return {"status": "applied", "handler": "set_non_root_user", "candidate_container": candidate_container}


def add_cpu_limit(candidate_container=None, **kwargs):
    value = _inspect_candidate(candidate_container, "{{.HostConfig.NanoCpus}}")
    if value is None:
        return {"status": "failed", "handler": "add_cpu_limit", "reason": "Could not inspect the candidate CPU limit."}
    if int(value or 0) <= 0:
        return {"status": "failed", "handler": "add_cpu_limit", "reason": "Candidate has no CPU limit."}
    return {"status": "applied", "handler": "add_cpu_limit", "candidate_container": candidate_container}


def add_memory_limit(candidate_container=None, **kwargs):
    value = _inspect_candidate(candidate_container, "{{.HostConfig.Memory}}")
    if value is None:
        return {"status": "failed", "handler": "add_memory_limit", "reason": "Could not inspect the candidate memory limit."}
    if int(value or 0) <= 0:
        return {"status": "failed", "handler": "add_memory_limit", "reason": "Candidate has no memory limit."}
    return {"status": "applied", "handler": "add_memory_limit", "candidate_container": candidate_container}


def add_process_limit(candidate_container=None, **kwargs):
    value = _inspect_candidate(candidate_container, "{{.HostConfig.PidsLimit}}")
    if value is None:
        return {"status": "failed", "handler": "add_process_limit", "reason": "Could not inspect the candidate process limit."}
    if int(value or 0) <= 0:
        return {"status": "failed", "handler": "add_process_limit", "reason": "Candidate has no process limit."}
    return {"status": "applied", "handler": "add_process_limit", "candidate_container": candidate_container}


def apply_tracee_permission(category=None, destination=None, resource=None, **kwargs):
    """Apply only runtime permissions that are safe within the MVP boundary."""
    if category == "network_activity":
        return {
            "status": "applied",
            "handler": "apply_tracee_permission",
            "permission": "report_only",
            "reason": "Firewall and per-IP network rules are outside this tool.",
            "destination": destination or "unknown destination",
        }
    return {
        "status": "manual_review_required",
        "handler": "apply_tracee_permission",
        "reason": "This runtime behavior has no safe Docker permission mapping and remains denied by the strict policy.",
        "category": category,
        "resource": resource,
    }


def pin_base_image_version(**kwargs): return _unimplemented_handler("pin_base_image_version", **kwargs)
def remove_remote_download(**kwargs): return _unimplemented_handler("remove_remote_download", **kwargs)
def replace_unsafe_add_instruction(**kwargs): return _unimplemented_handler("replace_unsafe_add_instruction", **kwargs)
def add_healthcheck(**kwargs): return _unimplemented_handler("add_healthcheck", **kwargs)
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
PlanExecutor.register_handler("remove_docker_socket_mount", remove_docker_socket_mount)
PlanExecutor.register_handler("remove_or_narrow_host_mount", remove_or_narrow_host_mount)
PlanExecutor.register_handler("restrict_published_ports", restrict_published_ports)
PlanExecutor.register_handler("remove_setuid_setgid_permissions", remove_setuid_setgid_permissions)
PlanExecutor.register_handler("set_non_root_user", set_non_root_user)
PlanExecutor.register_handler("add_cpu_limit", add_cpu_limit)
PlanExecutor.register_handler("add_memory_limit", add_memory_limit)
PlanExecutor.register_handler("add_process_limit", add_process_limit)
PlanExecutor.register_handler("apply_tracee_permission", apply_tracee_permission)
