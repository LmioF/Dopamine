import argparse
import os
import pathlib
import shutil
import subprocess
import tempfile

from compat import patch_launchctl


VERSION = "1:1.1.1-2+dp3.1"
FILES = (
    "usr/bin/launchctl",
    "usr/share/doc/launchctl/LICENSE",
    "usr/share/man/man1/launchctl.1.zst",
)


def build(bootstrap: pathlib.Path, output: pathlib.Path) -> None:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="launchctl-", dir=output.parent) as directory:
        temporary = pathlib.Path(directory)
        source = temporary / "source"
        payload = temporary / "payload"
        source.mkdir()
        payload.mkdir()
        subprocess.run([
            "tar", "-xf", str(bootstrap.resolve()), "-C", str(source),
            *("./" + name for name in FILES), "./Library/dpkg/status",
        ], check=True)
        paragraphs = (source / "Library/dpkg/status").read_text().split("\n\n")
        records = [paragraph for paragraph in paragraphs if paragraph.startswith("Package: launchctl\n")]
        if len(records) != 1:
            raise ValueError("Missing or ambiguous bundled launchctl package metadata")
        metadata = dict(line.split(": ", 1) for line in records[0].splitlines() if ": " in line and not line.startswith(" "))
        if metadata.get("Architecture") != "iphoneos-arm64e" or metadata.get("Version") != "1:1.1.1-2":
            raise ValueError("The bundled roothide launchctl changed; reassess its compatibility patch")

        for name in FILES:
            destination = payload / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, destination)
        binary = payload / "usr/bin/launchctl"
        binary.write_bytes(patch_launchctl(binary.read_bytes()))
        binary.chmod(0o755)
        (payload / "bin").mkdir()
        (payload / "bin/launchctl").symlink_to("../usr/bin/launchctl")

        signer = os.environ.get("LDID", "ldid")
        entitlements = subprocess.check_output([signer, "-e", str(source / "usr/bin/launchctl")])
        signing_option = "-S"
        if entitlements.strip():
            entitlement_file = temporary / "entitlements.plist"
            entitlement_file.write_bytes(entitlements)
            signing_option += str(entitlement_file)
        subprocess.run([signer, "-Cadhoc", signing_option, str(binary)], check=True)

        metadata.pop("Status", None)
        metadata["Version"] = VERSION
        metadata["Installed-Size"] = str(sum((payload / name).stat().st_size for name in FILES) // 1024 + 1)
        metadata["Description"] = "Roothide launchctl with Dopamine 3 iOS 26 compatibility"
        control = payload / "DEBIAN"
        control.mkdir()
        (control / "control").write_text("".join(f"{key}: {value}\n" for key, value in metadata.items()))
        package = temporary / output.name
        subprocess.run([
            "dpkg-deb", "--root-owner-group", "-Zzstd", "-b", str(payload), str(package),
        ], check=True)
        package.replace(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Package the bundled roothide launchctl compatibility fix")
    parser.add_argument("--bootstrap", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    build(arguments.bootstrap, arguments.output)
