import subprocess, time

class ClamScanner:
    def __init__(self, target):
        self.target = target

    def scan(self):
        process = subprocess.Popen(["clamscan",  "--log=scan_outputs/clam_out.txt", "--recursive", "containers/{}".format(self.target)], stdout=subprocess.DEVNULL)

        count = 0
        while process.poll() is None:
            print("\rScanning {}".format(self.target) + ("." * count) + (" " * (3 - count)), end="")
            count = (count + 1) if count != 3 else 1
            time.sleep(0.5)

        print("\nScan complete! Results can be found in scan_outputs/clam_out.txt")