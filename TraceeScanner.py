import subprocess, time, os

class TraceeScanner:

    def __init__(self):
        return

    def scan(self, silent):

        if os.path.isfile("scan_outputs/tracee_out.txt"):
            #Previous output exists, delete to overwrite
            os.remove("scan_outputs/tracee_out.txt")

        with open("scan_outputs/tracee_out.txt", "a") as f:
            #traceectl event can also be run here to filter the event output file
            process = subprocess.Popen(["sudo", "tracee"], stdout=f, stderr=f)

            #Use tracee to capture a 10 second sample of environment activity
            count = 0
            while count < 20:
                if not silent:
                    print("\rScanning" + ("." * (count % 4)) + (" " * (4 - (count % 4))), end="")
                count = count + 1
                time.sleep(0.5)

            process.terminate()
            process.wait()

        if not silent:
            print("\nScan complete! Results can be found in scan_outputs/tracee_out.txt")
        return