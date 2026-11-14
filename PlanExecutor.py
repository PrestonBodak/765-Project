import json
import shutil
import subprocess
import tarfile
from pathlib import Path


class PlanExecutor:
    """Apply approved plan actions and sanitize their generated reports."""

    HANDLERS = {}

    @classmethod
    def register_handler(cls, name, handler):
        cls.HANDLERS[name] = handler

    @classmethod
    def handler_for(cls, name):
        return cls.HANDLERS.get(name)

    @classmethod
    def can_execute(cls, name):
        return cls.handler_for(name) is not None

    def execute(self, action, **kwargs):
        handler = self.handler_for(action.get("executor"))
        if handler is None:
            return {
                "status": "manual_review_required",
                "action": action.get("id"),
            }
        return handler(**kwargs)

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
