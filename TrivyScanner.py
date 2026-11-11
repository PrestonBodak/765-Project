import subprocess, time, os

class TrivyScanner:
    def __init__(self):
        return

    def scan(self, silent, scanType, target):
        #scanType - 0 = File/Directory, 1 = Image, ...

        if os.path.isfile("scan_outputs/trivy_out.txt"):
            #Previous output exists, delete to overwrite
            os.remove("scan_outputs/trivy_out.txt")

        with open("scan_outputs/trivy_out.txt", "a") as f:
            #Trivy has lots of features, so use switch/case for implementing future scan types.
            match scanType:
                case 0:
                    #Scan a target file/directory
                    process = subprocess.Popen(["sudo", "trivy", "fs", "--scanners", "vuln,secret,misconfig", "./containers/" + target], stdout=f, stderr=f)

                case 1:
                    #Scan a target Docker image
                    process = subprocess.Popen(["sudo", "trivy", "image", target], stdout=f, stderr=f)

            count = 0
            while process.poll() is None:
                if not silent:
                    print("\rScanning {}".format(target) + ("." * count) + (" " * (3 - count)), end="")
                count = (count + 1) if count != 3 else 1
                time.sleep(0.5)

            if not silent:
                print("\nScan complete! Results can be found in scan_outputs/trivy_out.txt")