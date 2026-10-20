import subprocess, time, os

class TraceeScanner:

    def __init__(self):
        return

    def scan(self):
        tracee_process = subprocess.Popen(["sudo", "tracee", "--output", "none", "--server", "grpc-address=unix:/var/run/tracee.sock"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(3)

        if os.path.isfile("scan_outputs/tracee_out.txt"):
            #Previous output exists, delete to overwrite
            os.remove("scan_outputs/tracee_out.txt")

        with open("scan_outputs/tracee_out.txt", "a") as f:
            #traceectl event can also be run here to filter the event output file
            traceectl_process = subprocess.Popen(["sudo", "traceectl", "stream"], stdout=f, stderr=f)

            #Use tracee to capture a 10 second sample of environment activity
            count = 0
            while count < 20:
                print("\rScanning" + ("." * (count % 4)) + (" " * (4 - (count % 4))), end="")
                count = count + 1
                time.sleep(0.5)

            traceectl_process.terminate()
            traceectl_process.wait()

        tracee_process.terminate()
        tracee_process.wait()

        print("\nScan complete! Results can be found in scan_outputs/tracee_out.txt")
        return