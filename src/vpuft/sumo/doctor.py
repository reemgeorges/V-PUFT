from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class DoctorReport:
    sumo_binary: str | None
    netconvert_binary: str | None
    traci_available: bool
    sumolib_available: bool
    sumo_version: str | None
    ready_for_sumo: bool
    notes: tuple[str, ...]


def resolve_binary(name: str, configured: str | None = None) -> str | None:
    candidates: list[str] = []
    if configured:
        candidates.append(configured)
    found = shutil.which(name)
    if found:
        candidates.append(found)
    sumo_home = os.environ.get("SUMO_HOME")
    if sumo_home:
        suffix = ".exe" if os.name == "nt" else ""
        candidates.append(str(Path(sumo_home) / "bin" / f"{name}{suffix}"))
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate).resolve())
    return None


def _version(binary: str | None) -> str | None:
    if not binary:
        return None
    try:
        completed = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15, check=False)
        text = (completed.stdout or completed.stderr).strip().splitlines()
        return text[0] if text else None
    except Exception:
        return None


def doctor_report(sumo_binary: str | None = None, netconvert_binary: str | None = None) -> DoctorReport:
    sumo = resolve_binary("sumo", sumo_binary)
    netconvert = resolve_binary("netconvert", netconvert_binary)
    traci_available = importlib.util.find_spec("traci") is not None
    sumolib_available = importlib.util.find_spec("sumolib") is not None
    notes: list[str] = []
    if not sumo:
        notes.append("SUMO binary was not found in PATH, configured path, or SUMO_HOME/bin.")
    if not netconvert:
        notes.append("netconvert was not found; the bundled plain network cannot be prepared.")
    if not traci_available:
        notes.append("Python package 'traci' is unavailable. Install the SUMO tools package or pip package.")
    if not sumolib_available:
        notes.append("Python package 'sumolib' is unavailable; it is optional for this runner but recommended.")
    ready = bool(sumo and netconvert and traci_available)
    return DoctorReport(
        sumo_binary=sumo,
        netconvert_binary=netconvert,
        traci_available=traci_available,
        sumolib_available=sumolib_available,
        sumo_version=_version(sumo),
        ready_for_sumo=ready,
        notes=tuple(notes),
    )


def report_as_dict(report: DoctorReport) -> dict:
    return asdict(report)
