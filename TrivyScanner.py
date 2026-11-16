import os
import subprocess
import time
from ScanPaths import SCAN_DIR


class TrivyScanner:
    def __init__(self):
        return

    def scan(self, silent, scanType, target):
        # scanType - 0 = File/Directory, 1 = Image, ...
        SCAN_DIR.mkdir(parents=True, exist_ok=True)
        output_path = SCAN_DIR / "trivy_out.json"
        error_path = SCAN_DIR / "trivy_err.txt"
        if output_path.exists():
            output_path.unlink()

        with open(output_path, "w") as output_file, open(error_path, "w") as error_file:
            # Trivy only runs the scan. Report parsing belongs to ReportPlanCreator.
            match scanType:
                case 0:
                    process = subprocess.Popen(
                        ["sudo", "trivy", "fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "./containers/" + target],
                        stdout=output_file,
                        stderr=error_file,
                    )
                case 1:
                    process = subprocess.Popen(
                        ["sudo", "trivy", "image", "--scanners", "vuln,secret,misconfig", "--format", "json", target],
                        stdout=output_file,
                        stderr=error_file,
                    )

            count = 0
            while process.poll() is None:
                if not silent:
                    print("\rScanning {}".format(target) + ("." * count) + (" " * (3 - count)), end="")
                count = (count + 1) if count != 3 else 1
                time.sleep(0.5)

            if not silent:
                print("\nTrivy scan complete.")
