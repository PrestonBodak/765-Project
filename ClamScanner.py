import os
import subprocess
import time

class ClamScanner:
    def __init__(self):
        return

    def scan(self, silent, target):
        return self.scan_path(silent, os.path.join("containers", target))

    def scan_path(self, silent, target):
        try:
            process = subprocess.Popen(
                [
                    "clamscan",
                    "--log=scan_outputs/clam_out.txt",
                    "--recursive",
                    target,
                ],
                stdout=subprocess.DEVNULL,
            )
        except OSError as error:
            if not silent:
                print("\nClamAV could not start: {}".format(error))
            return {
                "status": "error",
                "exit_code": None,
                "target": target,
            }

        count = 0
        while process.poll() is None:
            if not silent:
                print("\rScanning {}".format(target) + ("." * count) + (" " * (3 - count)), end="")
            count = (count + 1) if count != 3 else 1
            time.sleep(0.5)

        if process.returncode == 0:
            status = "clean"
        elif process.returncode == 1:
            status = "malware"
        else:
            status = "error"

        if not silent:
            print("\nScan complete! Results can be found in scan_outputs/clam_out.txt")

        return {
            "status": status,
            "exit_code": process.returncode,
            "target": target,
        }
