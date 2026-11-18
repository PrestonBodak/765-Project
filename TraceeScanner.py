import subprocess
import time
import uuid
from ScanPaths import SCAN_DIR


class TraceeScanner:

    OUTPUT_FILE = SCAN_DIR / "tracee_out.json"
    ERROR_FILE = SCAN_DIR / "tracee_err.txt"
    SCAN_CONFIGURATION = [
        "--network none",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--read-only",
        "--tmpfs /tmp:rw,noexec,nosuid,size=64m",
        "--pids-limit 256",
    ]

    def __init__(self):
        return

    def scan(self, silent, image):
        container_name = "security-scan-{}".format(uuid.uuid4().hex[:8])

        SCAN_DIR.mkdir(parents=True, exist_ok=True)
        self.OUTPUT_FILE.unlink(missing_ok=True)
        self.ERROR_FILE.unlink(missing_ok=True)

        # Tracee's JSON output is newline-delimited JSON: each event is one
        # complete JSON object, which can be streamed without buffering the
        # entire scan in memory.
        with (
            open(self.OUTPUT_FILE, "w") as output,
            open(self.ERROR_FILE, "w") as errors,
        ):
            tracee_process = subprocess.Popen(
                [
                    "sudo",
                    "tracee",
                    "--output",
                    "json",
                    "--scope",
                    "container=new",
                    "--containers=docker",
                    "--events",
                    "execve,execveat,openat,openat2,write,connect,setuid,setgid,capset,mount,umount,setns,unshare,ptrace,bpf",
                    "--log",
                    "warn",
                ],
                stdout=output,
                stderr=errors,
            )

            try:
                # Give Tracee time to initialize before creating the target.
                # container=new captures this container from its creation event
                # without requiring its cgroup to exist beforehand.
                time.sleep(10)

                if tracee_process.poll() is not None:
                    errors.write("Tracee exited before the container started.\n")
                    return {
                        "status": "error",
                        "output": str(self.OUTPUT_FILE),
                        "configuration": self.SCAN_CONFIGURATION,
                    }

                docker_create = subprocess.run(
                    [
                        "sudo",
                        "docker",
                        "create",
                        "--name",
                        container_name,
                        "--network",
                        "none",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "--read-only",
                        "--tmpfs",
                        "/tmp:rw,noexec,nosuid,size=64m",
                        "--pids-limit",
                        "256",
                        image,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=errors,
                    text=True,
                )

                if docker_create.returncode != 0:
                    errors.write("Docker failed to create the scan container.\n")
                    return {
                        "status": "error",
                        "output": str(self.OUTPUT_FILE),
                        "configuration": self.SCAN_CONFIGURATION,
                    }

                container_id = docker_create.stdout.strip()
                errors.write("Created scan container {}.\n".format(container_id))

                docker_process = subprocess.run(
                    ["sudo", "docker", "start", container_name],
                    stdout=errors,
                    stderr=errors,
                    text=True,
                )

                if docker_process.returncode != 0:
                    errors.write("Docker failed to start the scan container.\n")
                    return {
                        "status": "error",
                        "output": str(self.OUTPUT_FILE),
                        "configuration": self.SCAN_CONFIGURATION,
                    }

                errors.write(
                    "\nStarted scan container {} from {}.\n".format(
                        container_name, image
                    )
                )

                # Capture behavior for a ten-second window.
                count = 0
                while count < 20:
                    if not silent:
                        print(
                            "\rScanning"
                            + ("." * (count % 4))
                            + (" " * (4 - (count % 4))),
                            end="",
                        )
                    count += 1
                    time.sleep(0.5)

                if tracee_process.poll() not in (None, 0):
                    errors.write("Tracee exited while collecting runtime behavior.\n")
                    return {
                        "status": "error",
                        "output": str(self.OUTPUT_FILE),
                        "configuration": self.SCAN_CONFIGURATION,
                    }
            finally:
                # Always remove the temporary container, including on failure.
                subprocess.run(
                    ["sudo", "docker", "rm", "-f", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                if tracee_process is not None:
                    tracee_process.terminate()
                    tracee_process.wait()

        if not silent:
            print("\nTracee scan complete.")
        return {
            "status": "completed",
            "output": str(self.OUTPUT_FILE),
            "errors": str(self.ERROR_FILE),
            "configuration": self.SCAN_CONFIGURATION,
        }
