# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=43", "pyyaml>=6"]
# ///
"""Builds and signs Rookery's distro manifest.

The manifest lists official rootfs images by URL and SHA-256, never the images
themselves: Rookery downloads them from each distribution's own servers.

    uv run tools/manifest.py keygen  KEY       # once: new Ed25519 signing key
    uv run tools/manifest.py update            # refresh manifest.json from upstream
    uv run tools/manifest.py sign    KEY       # write manifest.json.sig
    uv run tools/manifest.py verify            # check the signature with the public key

KEY is a PEM file kept out of this repository.
"""
import base64
import datetime
import hashlib
import json
import pathlib
import re
import sys
import urllib.request

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifest.json"
SIGNATURE = ROOT / "manifest.json.sig"
PUBLIC_KEY = ROOT / "public-key.txt"

# Android ABI -> each distribution's name for it.
ALPINE_ARCH = {"armeabi-v7a": "armv7", "arm64-v8a": "aarch64", "x86_64": "x86_64"}
DEBIAN_ARCH = {"armeabi-v7a": "arm32v7", "arm64-v8a": "arm64v8", "x86_64": "amd64"}
UBUNTU_ARCH = {"armeabi-v7a": "armhf", "arm64-v8a": "arm64", "x86_64": "amd64"}

DEBIAN_SUITE = "trixie"
UBUNTU_RELEASE = "24.04"

# Rough disk use once set up with the desktop, shown before the download.
INSTALL_SIZE = {"alpine": 700 << 20, "debian": 1400 << 20, "ubuntu": 1600 << 20}


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "rookery-distros"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def head_size(url: str) -> int:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "rookery-distros"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return int(response.headers["Content-Length"])


def alpine() -> dict:
    images, version = {}, None
    for abi, arch in ALPINE_ARCH.items():
        base = f"https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/{arch}"
        releases = yaml.safe_load(get(f"{base}/latest-releases.yaml"))
        entry = next(r for r in releases if r["flavor"] == "alpine-minirootfs")
        version = entry["version"]
        branch = "v" + ".".join(version.split(".")[:2])
        images[abi] = {
            # The versioned directory, so the URL keeps pointing at this exact file.
            "url": f"https://dl-cdn.alpinelinux.org/alpine/{branch}/releases/{arch}/{entry['file']}",
            "sha256": entry["sha256"],
            "size": entry["size"],
        }
    return {
        "id": "alpine", "name": "Alpine Linux", "version": version, "family": "alpine",
        "description": "Small and quick. The best fit for TVs with little memory.",
        "recommended": True, "installSize": INSTALL_SIZE["alpine"], "images": images,
    }


def debian() -> dict:
    images, version = {}, None
    repo = "debuerreotype/docker-debian-artifacts"
    for abi, arch in DEBIAN_ARCH.items():
        branch = json.loads(get(f"https://api.github.com/repos/{repo}/branches/dist-{arch}"))
        commit = branch["commit"]["sha"]
        # Pinned to the commit: the branch moves with every rebuild.
        blobs = f"https://raw.githubusercontent.com/{repo}/{commit}/{DEBIAN_SUITE}/oci/blobs"
        layer = json.loads(get(f"{blobs}/image-manifest.json"))["layers"][0]
        assert layer["mediaType"].endswith("tar+gzip"), layer["mediaType"]
        version = get(f"https://raw.githubusercontent.com/{repo}/{commit}/{DEBIAN_SUITE}/rootfs.debian_version").decode().strip()
        images[abi] = {
            "url": f"{blobs}/rootfs.tar.gz",
            "sha256": layer["digest"].removeprefix("sha256:"),
            "size": layer["size"],
        }
    return {
        "id": "debian", "name": "Debian", "version": version, "family": "debian",
        "description": "Stable, with the most software. Needs more space and memory.",
        "recommended": False, "installSize": INSTALL_SIZE["debian"], "images": images,
    }


def ubuntu() -> dict:
    base = f"https://cdimage.ubuntu.com/ubuntu-base/releases/{UBUNTU_RELEASE}/release"
    sums = {}
    for line in get(f"{base}/SHA256SUMS").decode().splitlines():
        digest, name = line.split(maxsplit=1)
        sums[name.lstrip("*")] = digest
    images, version = {}, None
    for abi, arch in UBUNTU_ARCH.items():
        pattern = re.compile(rf"ubuntu-base-({re.escape(UBUNTU_RELEASE)}(?:\.\d+)?)-base-{arch}\.tar\.gz")
        found = sorted(
            ((m.group(1), name) for name in sums if (m := pattern.fullmatch(name))),
            key=lambda item: [int(p) for p in item[0].split(".")],
        )
        version, name = found[-1]
        url = f"{base}/{name}"
        images[abi] = {"url": url, "sha256": sums[name], "size": head_size(url)}
    return {
        "id": "ubuntu", "name": "Ubuntu", "version": f"{version} LTS", "family": "debian",
        "description": "Familiar and widely used. The largest of the three.",
        "recommended": False, "installSize": INSTALL_SIZE["ubuntu"], "images": images,
    }


def update() -> None:
    serial = json.loads(MANIFEST.read_text())["serial"] + 1 if MANIFEST.exists() else 1
    manifest = {
        "schema": 1,
        # Rookery refuses a manifest older than one it has already seen.
        "serial": serial,
        "generated": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "distros": [alpine(), debian(), ubuntu()],
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", newline="\n")
    SIGNATURE.unlink(missing_ok=True)
    for distro in manifest["distros"]:
        print(f"{distro['id']} {distro['version']}: {', '.join(distro['images'])}")
    print(f"serial {serial}; now sign it")


def keygen(path: str) -> None:
    key_file = pathlib.Path(path)
    if key_file.exists():
        sys.exit(f"{key_file} exists; not overwriting a signing key")
    key = Ed25519PrivateKey.generate()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_public(key.public_key())
    print(f"key in {key_file}; public key in {PUBLIC_KEY.name}")


def write_public(public: Ed25519PublicKey) -> None:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    PUBLIC_KEY.write_text(base64.b64encode(raw).decode() + "\n", newline="\n")


def sign(path: str) -> None:
    key = serialization.load_pem_private_key(pathlib.Path(path).read_bytes(), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    write_public(key.public_key())
    signature = key.sign(MANIFEST.read_bytes())
    SIGNATURE.write_text(base64.b64encode(signature).decode() + "\n", newline="\n")
    verify()


def verify() -> None:
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY.read_text()))
    public.verify(base64.b64decode(SIGNATURE.read_text()), MANIFEST.read_bytes())
    digest = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    print(f"signature OK (manifest sha256 {digest})")


if __name__ == "__main__":
    command, *args = sys.argv[1:] or ["help"]
    commands = {"update": update, "keygen": keygen, "sign": sign, "verify": verify}
    if command not in commands:
        sys.exit(__doc__)
    commands[command](*args)
