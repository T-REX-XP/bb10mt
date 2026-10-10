"""Exercise a delivered single-file runtime, without a handset or installed libusb."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import signal
import shutil
import subprocess
import tempfile
import time


def run(binary, *args, **kwargs):
    return subprocess.run([str(binary), *map(str, args)], check=True, text=True, capture_output=True, **kwargs).stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--fuse", action="store_true")
    parser.add_argument("--usb", action="store_true", help="Read-only host USB enumeration")
    parser.add_argument("--empty-root", action="store_true", help="Linux root: also run with no host user-space libraries")
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve()
    sums = binary.parent / "SHA256SUMS"
    if sums.exists():
        expected = dict(line.split("  ", 1)[::-1] for line in sums.read_text().splitlines())
        with binary.open("rb") as file:
            assert hashlib.file_digest(file, "sha256").hexdigest() == expected[binary.name]
    if os.name != "nt":
        binary.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="bb10mt-bundle-test-") as temp:
        root = pathlib.Path(temp)
        env = os.environ.copy()
        env.update({"LOCALAPPDATA": str(root), "XDG_CACHE_HOME": str(root), "HOME": str(root)})
        manifest = json.loads(run(binary, "--runtime-info", env=env))
        version = run(binary, "--version", env=env).strip()
        assert version.startswith("bb10mt v"), version
        exported = root / "exported"
        run(binary, "--extract-runtime", exported, env=env)
        for row in manifest["files"]:
            data = (exported / row["path"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == row["sha256"], row["path"]
        assert run(binary, "--runtime-dir", exported, "--version", env=env).strip() == version
        if args.usb:
            json.loads(run(binary, "usb", "list", env=env))
        image = root / "source.ufs"
        run(binary, "qnx6", "mkfs", "-i", image, "--blocks", 2048, "--inodes", 128, env=env)
        run(binary, "qnx6", "fsck", "-i", image, env=env)
        if platform.system() == "Linux":
            helper = exported / "bin/fusermount3"
            assert "fusermount3 version" in subprocess.check_output([str(helper), "--version"], text=True)
        if args.fuse:
            assert platform.system() == "Linux"
            mount = root / "mount"
            mount.mkdir()
            output = root / "edited.ufs"
            process = subprocess.Popen([str(binary), "qnx6", "mount", "-i", str(image), "-o", str(output), "-m", str(mount)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 20
                while not os.path.ismount(mount):
                    if process.poll() is not None:
                        raise AssertionError(process.communicate())
                    if time.monotonic() >= deadline:
                        raise TimeoutError("bundled FUSE mount did not become ready")
                    time.sleep(0.05)
                (mount / "payload").write_text("bundled runtime FUSE transaction\n")
                assert (mount / "payload").read_text() == "bundled runtime FUSE transaction\n"
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=20)
                assert process.returncode == 0, (stdout, stderr)
                run(binary, "qnx6", "fsck", "-i", output, env=env)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                    process.communicate(timeout=20)
        # A changed cache must fail, before any application code can run.
        caches = list(root.rglob("manifest.json"))
        caches = [p.parent for p in caches if p.parent != exported]
        assert len(caches) == 1, caches
        app = caches[0] / manifest["application"]
        data = bytearray(app.read_bytes())
        data[-1] ^= 1
        app.write_bytes(data)
        failed = subprocess.run([str(binary), "--version"], env=env, capture_output=True, text=True)
        assert failed.returncode != 0 and "SHA256 mismatch" in failed.stderr, failed
    if args.empty_root:
        assert platform.system() == "Linux" and os.geteuid() == 0
        empty_root(binary)
    print("PASS", platform.system(), platform.machine(), version, "USB=" + str(args.usb), "FUSE=" + str(args.fuse))


def empty_root(binary):
    # Only /proc is mounted. No /lib, /usr or installed native runtime is present.
    root = pathlib.Path(tempfile.mkdtemp(prefix="bb10mt-empty-root-"))
    (root / "proc").mkdir()
    (root / "app").mkdir()
    shutil.copy2(binary, root / "app/bb10mt")
    subprocess.run(["mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", str(root / "proc")], check=True)
    env = os.environ.copy()
    env.update({"HOME": "/cache", "XDG_CACHE_HOME": "/cache"})
    try:
        def command(*args):
            subprocess.run(["chroot", str(root), *args], env=env, check=True, capture_output=True, text=True)
        command("/app/bb10mt", "--version")
        command("/app/bb10mt", "usb", "list")
        command("/app/bb10mt", "qnx6", "mkfs", "-i", "/source.ufs", "--blocks", "2048", "--inodes", "128")
        command("/app/bb10mt", "qnx6", "fsck", "-i", "/source.ufs")
        command("/app/bb10mt", "--extract-runtime", "/runtime")
        command("/runtime/bin/fusermount3", "--version")
    finally:
        # Do not traverse a mounted /proc if cleanup cannot unmount it.
        subprocess.run(["umount", str(root / "proc")], check=True)
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
