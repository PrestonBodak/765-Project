# WARNING

This tool is intended to be run in an insolated test environment! For effective threat identification, some files may need to be decompressed or run within the `containers` folder. While this tool aims to be as user-friendly as possible, please ensure that it is only used within an isolated virtual machine or otherwise secure operating system before proceeding.

# Running the Tool

The tool can be run from within the main directory with: `python3 main.py`

# Installation prerequisites:

### ClamAV:
https://docs.clamav.net/manual/Installing/Packages.html/

For Ubuntu or Debian, run:
`sudo apt install clamav`

### Trivy:
http://trivy.dev/docs/latest/getting-started/installation/

For Ubuntu or Debian, run:
`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.76.2`

### Tracee:

Must be installed such that a valid symlink for `tracee` exists in /usr/local/bin/ (such that the command can be run from any directory). Due to the many required libraries to build Tracee, it is recommended to download the binary from GitHub.

The most recent Tracee binary can be found here: https://github.com/aquasecurity/tracee/releases

Once you have downloaded the binary for Tracee, link it to a global command with: `sudo ln -s [FULL PATH TO BINARY] /usr/local/bin/[COMMAND]`
