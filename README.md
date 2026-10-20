# Installation prerequisites:

### ClamAV:
docs.clamav.net/manual/Installing/Packages.html

For Ubuntu or Debian, run:
`sudo apt install clamav`

### Tracee:

Must be installed such that valid symlinks for `tracee` and `traceectl` exist in /usr/local/bin/ (such that the commands can be run from any directory). Due to the many required libraries to build Tracee but none for traceectl, it is recommended to download the binary for Tracee but to clone the repository and build traceectl from source.

The most recent Tracee binary can be found here: github.com/aquasecurity/tracee/releases

Instructions for building traceectl can be found here: aquasecurity.github.io/tracee/latest/traceectl/usage/

Once you have prepared binaries for Tracee and traceectl, link each to a global command with: `sudo ln -s [FULL PATH TO BINARY] /usr/local/bin/[COMMAND]`