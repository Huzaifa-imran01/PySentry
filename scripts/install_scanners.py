"""Install the verified x86-64 releases beside this interpreter (Windows and Linux)."""
import hashlib
import io
import os
from pathlib import Path
import platform
import sys
import tarfile
import tempfile
from urllib.request import urlopen
import zipfile

ASSETS = {
    "Windows": (
        ("gitleaks/gitleaks", "8.24.3", "gitleaks_8.24.3_windows_x64.zip", "gitleaks.exe", "3f1a35578631dbfe633cc5b49e6c906e55ff14a4bfd7336a10fb27fe33b6dcd2"),
        ("google/osv-scanner", "2.2.2", "osv-scanner_windows_amd64.exe", "osv-scanner.exe", "5cce6a9b96b88d0620bfdb22da72497c444948e56c64d3508f054cded13fb49f")),
    "Linux": (
        ("gitleaks/gitleaks", "8.24.3", "gitleaks_8.24.3_linux_x64.tar.gz", "gitleaks", "9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c"),
        ("google/osv-scanner", "2.2.2", "osv-scanner_linux_amd64", "osv-scanner", "c799274b682e0437c802d4714a136ad09b39c65547c460049ba5358d28afa576"))
}


def main():
    if platform.machine().lower() not in {"amd64","x86_64"} or platform.system() not in ASSETS:
        raise SystemExit("Provide the pinned tools manually on this platform")
    for repo, version, asset, name, digest in ASSETS[platform.system()]:
        with urlopen(f"https://github.com/{repo}/releases/download/v{version}/{asset}",timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"Checksum mismatch for {asset}")
        if asset.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                data = archive.read(name)
        elif asset.endswith(".tar.gz"):
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                data = archive.extractfile(name).read()
        dest = Path(sys.executable).parent / name
        with tempfile.NamedTemporaryFile(dir=dest.parent,delete=False) as tmp:
            tmp.write(data)
        try:
            os.chmod(tmp.name,0o755)
            os.replace(tmp.name,dest)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        print(f"Installed {name} {version}")


if __name__=="__main__":
    main()
