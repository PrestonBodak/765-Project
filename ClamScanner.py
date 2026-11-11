import subprocess, time

class ClamScanner:
    def __init__(self):
        return

    def scan(self, silent, target):
        process = subprocess.Popen(["clamscan",  "--log=scan_outputs/clam_out.txt", "--recursive", "containers/{}".format(target)], stdout=subprocess.DEVNULL)

        count = 0
        while process.poll() is None:
            if not silent:
                print("\rScanning {}".format(target) + ("." * count) + (" " * (3 - count)), end="")
            count = (count + 1) if count != 3 else 1
            time.sleep(0.5)

        if not silent:
            print("\nScan complete! Results can be found in scan_outputs/clam_out.txt")