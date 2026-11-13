import os
import subprocess
import time
import uuid

class TraceeScanner:

    def __init__(self):
        return

    def scan(self, silent, image):
        container_name = "security-scan-{}".format(uuid.uuid4().hex[:8])

        if os.path.isfile("scan_outputs/tracee_out.txt"):
            #Previous output exists, delete to overwrite
            os.remove("scan_outputs/tracee_out.txt")

        with open("scan_outputs/tracee_out.txt", "a") as f:
            tracee_process = subprocess.Popen(
                ["sudo", "tracee"], stdout=f, stderr=f
            )

            try:
                # Give Tracee time to initialize before starting the target.
                time.sleep(10)

                if tracee_process.poll() is not None:
                    f.write("\nTracee exited before the container started.\n")
                    return

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
                    stdout=f,
                    stderr=f,
                    text=True,
                )

                if docker_process.returncode != 0:
                    f.write("\nDocker failed to start the scan container.\n")
                    return

                f.write(
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
            print("\nScan complete! Results can be found in scan_outputs/tracee_out.txt")
        return
