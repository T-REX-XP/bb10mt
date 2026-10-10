"""Optional Windows `go test -exec` adapter for a configured WSL Linux distro.

Set GOOS=linux, CGO_ENABLED=0 and BB10MT_WSL_DISTRO to an existing distro, then
run: go test -exec "python D:/path/to/bb10mt/scripts/wsl_test_exec.py" ./...
This does not install tools, modify the distro, or access a handset.
"""
import os
import re
import subprocess
import sys


def linux_path(value, distro):
    if re.match(r"^[A-Za-z]:[/\\]", value):
        return subprocess.check_output(
            ["wsl", "-d", distro, "--exec", "wslpath", "-a", "-u", value],
            text=True,
        ).strip()
    return value


def main():
    distro = os.environ.get("BB10MT_WSL_DISTRO")
    if not distro:
        raise RuntimeError("set BB10MT_WSL_DISTRO to an existing Linux distro")
    args = []
    for arg in sys.argv[1:]:
        if "=" in arg and arg.startswith("-"):
            key, value = arg.split("=", 1)
            arg = key + "=" + linux_path(value, distro)
        else:
            arg = linux_path(arg, distro)
        args.append(arg)
    return subprocess.call(["wsl", "-d", distro, "--exec", *args])


if __name__ == "__main__":
    sys.exit(main())
