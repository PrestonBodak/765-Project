import subprocess
import time
import uuid
from ScanPaths import SCAN_DIR


class TraceeScanner:

    OUTPUT_FILE = SCAN_DIR / "tracee_out.json"
    ERROR_FILE = SCAN_DIR / "tracee_err.txt"

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
                ["sudo", "tracee", "--output", "json"],
                stdout=output,
                stderr=errors,
            )

            try:
                # Give Tracee time to initialize before starting the target.
                time.sleep(10)

                if tracee_process.poll() is not None:
                    errors.write("Tracee exited before the container started.\n")
                    return {"status": "error", "output": str(self.OUTPUT_FILE)}

                docker_process = subprocess.run(
                    [
                        "sudo",
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        container_name,
                        image,
                    ],
                    stdout=errors,
                    stderr=errors,
                    text=True,
                )

                if docker_process.returncode != 0:
                    errors.write("Docker failed to start the scan container.\n")
                    return {"status": "error", "output": str(self.OUTPUT_FILE)}

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
            finally:
                # Always remove the temporary container, including on failure.
                subprocess.run(
                    ["sudo", "docker", "rm", "-f", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                tracee_process.terminate()
                tracee_process.wait()

        if not silent:
            print("\nTracee scan complete.")
        return {
            "status": "completed",
            "output": str(self.OUTPUT_FILE),
            "errors": str(self.ERROR_FILE),
        }
