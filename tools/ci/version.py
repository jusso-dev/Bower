"""Computes the Bower build version from the VERSION file (docs/operations/release-versioning.md).

VERSION holds the next release as MAJOR.MINOR.PATCH and is the single source of truth.
A release tag must be v<VERSION> or v<VERSION>-rc.N; every other build is
<VERSION>-dev.<build number>. The build number is the CI run number (1-65535): it is
the third field of the MSI ProductVersion (MAJOR.MINOR.BUILD) and the fourth field of
the Windows file version, so every installable build has a distinct, increasing number.
Build number 0 is an unnumbered development build (<VERSION>-dev.0, as a local build).

The MSI orders builds by ProductVersion (build time); the version key gives Windows the same
semantic order as deb and rpm. It is fixed width, so text order is version order
(dev < rc < release): MMM.mmm.PPPPP.S.NNNNN.
"""

import argparse
import os
from pathlib import Path
import re
import subprocess


CORE = re.compile(r"^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$")
VERSION = re.compile(
    r"^(?P<core>(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4}))"
    r"(-(?P<label>dev|rc)\.(?P<number>0|[1-9][0-9]{0,4}))?$")
MAXIMUM_BUILD = 65535


class VersionError(ValueError):
    pass


def parse(version):
    """(major, minor, patch, stage, number); stage orders dev (0) < rc (1) < release (2)."""
    match = VERSION.match(version)
    if not match:
        raise VersionError(f"not a Bower version (MAJOR.MINOR.PATCH[-dev.N|-rc.N]): {version!r}")
    major, minor, patch = (int(part) for part in match["core"].split("."))
    if major > 255 or minor > 255 or patch > MAXIMUM_BUILD:
        raise VersionError(f"MAJOR and MINOR must be at most 255 and PATCH at most 65535: {version!r}")
    stage = {"dev": 0, "rc": 1, None: 2}[match["label"]]
    number = int(match["number"] or 0)
    if number > MAXIMUM_BUILD:
        raise VersionError(f"the pre-release number must be at most 65535: {version!r}")
    return major, minor, patch, stage, number


def key(version):
    """The fixed-width, text-sortable key of a version (build.ps1 computes the same)."""
    major, minor, patch, stage, number = parse(version)
    return f"{major:03d}.{minor:03d}.{patch:05d}.{stage}.{number:05d}"


def read_core(path):
    core = Path(path).read_text(encoding="utf-8").strip()
    if not CORE.match(core):
        raise VersionError(f"{path} must hold MAJOR.MINOR.PATCH, found {core!r}")
    parse(core)
    return core


def compute(core, ref_type, ref_name, build_number, released=False):
    """The version and build number for one CI run. released: tag v<core> already exists."""
    if released and ref_type != "tag":
        raise VersionError(
            f"v{core} is already released: bump VERSION (and rust/Cargo.toml) before building "
            f"more development builds, or they would sort before the release")
    if not 0 <= build_number <= MAXIMUM_BUILD:
        raise VersionError(f"the build number must be 0-{MAXIMUM_BUILD}, got {build_number}")
    if ref_type == "tag":
        if not ref_name.startswith("v"):
            raise VersionError(f"release tags start with v: {ref_name!r}")
        version = ref_name[1:]
        _, _, _, stage, _ = parse(version)
        if version.split("-")[0] != core or stage == 0:
            raise VersionError(
                f"tag {ref_name} does not match VERSION {core}: tag v{core} or v{core}-rc.N, "
                "or update VERSION first")
    else:
        version = f"{core}-dev.{build_number}"
        parse(version)
    major, minor, _, _, _ = parse(version)
    return {
        "version": version,
        "core": core,
        "build": str(build_number),
        "prerelease": str(version != core).lower(),
        # Only a final release tag moves the images' :latest tag (never an rc or a dev build).
        "latest": str(ref_type == "tag" and version == core).lower(),
        "msi_version": f"{major}.{minor}.{build_number}",
        "version_key": key(version),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version-file", default=Path(__file__).resolve().parents[2] / "VERSION")
    parser.add_argument("--ref-type", default="branch")
    parser.add_argument("--ref-name", default="")
    parser.add_argument("--build-number", type=int, required=True)
    parser.add_argument("--check-released", action="store_true",
                        help="fail a non-tag build when the tag v<VERSION> exists (needs fetched tags)")
    args = parser.parse_args()
    try:
        core = read_core(args.version_file)
        released = args.check_released and bool(subprocess.run(
            ["git", "tag", "--list", f"v{core}"], check=True, capture_output=True, text=True).stdout.strip())
        result = compute(core, args.ref_type, args.ref_name, args.build_number, released)
    except VersionError as error:
        parser.exit(2, f"error: {error}\n")
    output = "".join(f"{key}={value}\n" for key, value in result.items())
    print(output, end="")
    if target := os.environ.get("GITHUB_OUTPUT"):
        with Path(target).open("a", encoding="utf-8") as stream:
            stream.write(output)


if __name__ == "__main__":
    main()
