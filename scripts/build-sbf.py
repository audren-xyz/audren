#!/usr/bin/env python3
"""Build owned Solana programs with the repository's pinned sBPFv3 compiler."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:
    # A Python older than 3.11: run under a newer one on the PATH, or say what is missing. Never build half-way.
    import shutil

    for name in ("python3.14", "python3.13", "python3.12", "python3.11"):
        newer = shutil.which(name)
        if newer:
            os.execv(newer, [newer, *sys.argv])
    sys.exit(
        f"build-sbf.py needs Python 3.11 or newer (tomllib): this is {sys.version.split()[0]}, "
        "and no python3.11 to python3.14 is on the PATH"
    )


BUILDER_VERSION = "4.3.0"
TOOLS_VERSION = "v1.57"
HOST_VERSION = "1.97.1"
ARCH = "v3"
ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / ".scratch" / "sbf" / BUILDER_VERSION
BUILDER = INSTALL / "bin" / "cargo-build-sbf"


def check_elf(path):
    """Reject an artifact unless its actual ELF header specifies sBPFv3."""
    data = path.read_bytes()
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", data, 18)[0] != 247
            or struct.unpack_from("<I", data, 48)[0] != 3):
        raise ValueError(f"{path}: expected a little-endian ELF64 sBPFv3 program")
    return {
        "arch": ARCH,
        "elf_bytes": len(data),
        "elf_sha256": hashlib.sha256(data).hexdigest(),
    }


def check_build(path):
    details = check_elf(path)
    details.update(builder_version=BUILDER_VERSION, tools_version=TOOLS_VERSION)
    stamp = json.loads(path.with_suffix(".build.json").read_text())
    if stamp != details:
        raise ValueError(f"{path}: successful pinned build stamp does not match this artifact")
    return details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path)
    parser.add_argument("--sbf-out-dir", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--jobs", type=int)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--check", type=Path, metavar="ELF")
    parser.add_argument("--check-elf", type=Path, metavar="ELF")
    parser.add_argument("cargo_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.version:
        print(f"cargo-build-sbf {BUILDER_VERSION}\nplatform-tools {TOOLS_VERSION}\nsBPFv3")
        return
    if args.check:
        print(json.dumps(check_build(args.check), indent=2))
        return
    if args.check_elf:
        print(json.dumps(check_elf(args.check_elf), indent=2))
        return
    if not args.manifest_path or not args.sbf_out_dir:
        parser.error("--manifest-path and --sbf-out-dir are required")
    manifest = args.manifest_path.resolve()
    package = tomllib.loads(manifest.read_text())
    lib = package.get("lib", {})
    if "cdylib" not in lib.get("crate-type", []):
        parser.error("the manifest must identify one cdylib program")
    name = lib.get("name", package["package"]["name"].replace("-", "_"))
    output = args.sbf_out_dir.resolve()
    artifact = output / f"{name}.so"
    stamp = output / f"{name}.build.json"
    stamp.unlink(missing_ok=True)
    if not BUILDER.exists():
        if args.offline:
            parser.error("pinned builder is absent; run a build without --offline to install it")
        subprocess.run([
            "cargo", f"+{HOST_VERSION}", "install", "cargo-build-sbf",
            "--version", BUILDER_VERSION, "--locked", "--root", str(INSTALL),
        ], check=True)
    actual = subprocess.check_output([str(BUILDER), "--version"], text=True)
    if actual.splitlines()[0] != f"cargo-build-sbf {BUILDER_VERSION}":
        raise ValueError("pinned cargo-build-sbf version mismatch")
    cargo_args = args.cargo_args
    if cargo_args[:1] == ["--"]:
        cargo_args = cargo_args[1:]
    if any(arg != "--locked" for arg in cargo_args):
        parser.error("canonical builds accept only --locked; define features and release options in reviewed manifests")
    command = [str(BUILDER), "--arch", ARCH, "--tools-version", TOOLS_VERSION,
               "--manifest-path", str(manifest), "--sbf-out-dir", str(output)]
    if args.offline:
        tools = Path.home() / ".cache" / "solana" / TOOLS_VERSION / "platform-tools"
        if not (tools / "rust" / "bin" / "rustc").is_file():
            parser.error("pinned platform tools are absent; an offline build cannot install them")
        command += ["--offline", "--skip-tools-install"]
    if args.jobs:
        command += ["--jobs", str(args.jobs)]
    command += ["--", *([] if "--locked" in cargo_args else ["--locked"]), *cargo_args]
    env = os.environ.copy()
    # The compiler owns target selection and -z defs (unresolved symbols are fatal).
    # Ambient overrides must not silently change this build's architecture or linkage.
    for key in ("RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                "CARGO_TARGET_SBPFV3_SOLANA_SOLANA_RUSTFLAGS"):
        if env.get(key):
            parser.error(f"unset {key}; build the pinned target without ambient compiler overrides")
    if any(key.startswith("CARGO_PROFILE_") for key in env):
        parser.error("unset CARGO_PROFILE_*; release optimization is defined in the workspace manifest")
    env["CARGO_TARGET_SBPFV3_SOLANA_SOLANA_RUSTFLAGS"] = f"--remap-path-prefix={ROOT}=/audren-source"
    print(f"Building {name}: sBPFv3, builder {BUILDER_VERSION}, tools {TOOLS_VERSION}", flush=True)
    # cargo-build-sbf remaps its working directory into embedded source paths.
    # Use the Cargo workspace root regardless of the caller's current directory.
    workspace_manifest = subprocess.check_output([
        "cargo", f"+{HOST_VERSION}", "locate-project", "--workspace",
        "--message-format", "plain", "--manifest-path", str(manifest),
    ], text=True).strip()
    workspace = Path(workspace_manifest).parent
    lockfile = workspace / "Cargo.lock"
    locked_bytes = lockfile.read_bytes()
    # cargo-build-sbf performs its own metadata resolution before forwarding
    # --locked to compilation. Refuse stale resolution before that step and
    # verify that the builder did not change the reviewed dependency graph.
    subprocess.run([
        "cargo", f"+{HOST_VERSION}", "metadata", "--locked", "--format-version", "1",
        "--manifest-path", str(manifest), *(["--offline"] if args.offline else []),
    ], env=env, cwd=workspace, stdout=subprocess.DEVNULL, check=True)
    if env.get("CARGO_TARGET_DIR"):
        env["CARGO_TARGET_DIR"] = str(Path(env["CARGO_TARGET_DIR"]).resolve())
    process = subprocess.Popen(command, env=env, cwd=workspace, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    bad_diagnostic = False
    for line in process.stdout:
        print(line, end="", flush=True)
        if re.search(r"\bError:|stack (?:offset|frame).*exceed|undefined symbol", line, re.I):
            bad_diagnostic = True
    status = process.wait()
    if status or bad_diagnostic:
        raise ValueError(f"{name}: compiler failed or emitted a fatal stack/link diagnostic")
    if lockfile.read_bytes() != locked_bytes:
        raise ValueError(f"{name}: Cargo.lock changed during the build; review dependency resolution separately")
    details = check_elf(artifact)
    details.update(builder_version=BUILDER_VERSION, tools_version=TOOLS_VERSION)
    stamp.write_text(json.dumps(details, indent=2) + "\n")
    print(f"Verified {name}: {details['elf_bytes']} bytes, sha256 {details['elf_sha256']}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
