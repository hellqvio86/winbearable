"""Fast deterministic mutation-testing gate for security- and transaction-critical modules."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MutantSpec:
    """Single deterministic mutant and the pytest node(s) that must kill it."""

    mutant_id: str
    rel_path: str
    target: str
    replacement: str
    test_target: str


MUTANTS: tuple[MutantSpec, ...] = (
    MutantSpec(
        "M1_path_policy_sys_root",
        "src/winbearable/operations/path_policy.py",
        "if resolved == sys_root or resolved.is_relative_to(sys_root):",
        "if False:",
        "tests/operations/test_compensation_reparse_and_ports.py",
    ),
    MutantSpec(
        "M3_uac_o_excl",
        "src/winbearable/uac/output.py",
        'flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)',
        'flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)',
        "tests/uac/test_uac_and_locale_security.py",
    ),
    MutantSpec(
        "M4_uac_prefix",
        "src/winbearable/uac/output.py",
        'if not out_path.parent.name.startswith("wb-uac-") or out_path.name != "uac-output.txt":',
        "if False:",
        "tests/uac/test_uac_and_locale_security.py",
    ),
    MutantSpec(
        "M6_rollback_incomplete",
        "src/winbearable/engine/rollback.py",
        "if incomplete:",
        "if False:",
        "tests/engine/test_recovery_and_concurrency.py",
    ),
    MutantSpec(
        "M7_wsl_distro_conflict",
        "src/winbearable/engine/compensation.py",
        "if cur_sha != d_snap.post_sha256:",
        "if False:",
        "tests/operations/test_compensation_reparse_and_ports.py",
    ),
    MutantSpec(
        "M10_wslconfig_conflict",
        "src/winbearable/engine/compensation.py",
        "if not matches_pre and cur_sha != run_record.wslconfig_post_sha256:",
        "if False:",
        "tests/operations/test_compensation_reparse_and_ports.py",
    ),
    MutantSpec(
        "M11_edition_fail_open",
        "src/winbearable/engine/params.py",
        'if not raw or raw == "unknown":\n        return allow_unknown_edition',
        'if not raw or raw == "unknown":\n        return True',
        "tests/operations/test_compensation_reparse_and_ports.py",
    ),
)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    killed = 0
    total = len(MUTANTS)

    with tempfile.TemporaryDirectory(prefix="wb-mut-") as tmp:
        work_root = Path(tmp) / "repo"
        shutil.copytree(repo_root / "src", work_root / "src")
        shutil.copytree(repo_root / "tests", work_root / "tests")
        shutil.copy2(repo_root / "pyproject.toml", work_root / "pyproject.toml")
        if (repo_root / "profiles").is_dir():
            shutil.copytree(repo_root / "profiles", work_root / "profiles")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(work_root / "src")

        for mutant in MUTANTS:
            target_file = work_root / mutant.rel_path
            orig_text = target_file.read_text(encoding="utf-8")
            if mutant.target not in orig_text:
                print(f"[SKIP/ERROR] Target snippet not found for {mutant.mutant_id} in {mutant.rel_path}")
                continue
            mutated_text = orig_text.replace(mutant.target, mutant.replacement, 1)
            target_file.write_text(mutated_text, encoding="utf-8")
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pytest", mutant.test_target, "-q", "--no-cov", "-x"],
                    cwd=work_root,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if proc.returncode != 0:
                    killed += 1
                    print(f"[KILLED]   {mutant.mutant_id}")
                else:
                    print(f"[SURVIVED] {mutant.mutant_id}")
            finally:
                target_file.write_text(orig_text, encoding="utf-8")

    rate = (killed / total) * 100.0 if total else 0.0
    print(f"Mutation score: {killed}/{total} ({rate:.1f}%)")
    return 0 if rate >= 90.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
