"""Tests for ENG-01..11, MGD-01..03, WSL-01..07, QA-01, QA-04, and TWK-A..J."""

import json
import random
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from winbearable.audit import build_doctor_blockers, run_security_audit
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend, NativeSystemBackend
from winbearable.const import (
    DEFENDER_FEATURES_KEY,
    HIVE_HKLM,
    REG_DWORD,
    REG_SZ,
)
from winbearable.engine import apply_profile, recover_incomplete_runs, rollback_runs
from winbearable.models import (
    ProfileSpec,
    TweakProvenance,
    WslConfigSpec,
)
from winbearable.packages import PACKAGE_CATALOG
from winbearable.profiles import ProfileValidationError, load_profile
from winbearable.state import StateStore
from winbearable.tweaks import TWEAK_CATALOG
from winbearable.wsl import (
    WslOperationError,
    build_distro_wsl_conf_sections,
    build_wslconfig_sections,
    deep_audit_wsl_distro,
    detect_default_wsl_distro,
    detect_wsl_policies,
    export_wsl_distro,
    is_wsl_version_outdated,
    set_wsl_distro_sparse,
    update_wsl,
)


def _dummy_prov() -> TweakProvenance:
    return TweakProvenance(
        rationale="test",
        authoritative_source="test",
        risk_rationale="test",
        impact="test",
        reversibility="reversible",
        verification_method="registry_value",
        review_evidence="test",
    )


def test_cli_selection_introspection_and_audit(cli_runner: Any) -> None:
    """ENG-05, ENG-06, ENG-11, MGD-01: --only/--skip/--category, list/show/schema, audit, and doctor blockers."""
    rc, out, _ = cli_runner(["plan", "--profile", "user-only", "--only", "explorer.show_file_extensions", "--json"])
    assert rc == 0
    plan_data = json.loads(out)
    assert len(plan_data["results"]) == 1
    assert plan_data["results"][0]["tweak_id"] == "explorer.show_file_extensions"

    rc_bad, _, err_bad = cli_runner(["plan", "--only", "explorer.show_file_extnsion"])
    assert rc_bad != 0
    assert "Did you mean: explorer.show_file_extensions" in err_bad

    rc_list, out_list, _ = cli_runner(["list", "--category", "input", "--no-admin", "--json"])
    assert rc_list == 0
    list_data = json.loads(out_list)
    assert list_data["count"] >= 4

    rc_show, out_show, _ = cli_runner(["show", "input.keyboard_repeat", "--json"])
    assert rc_show == 0
    show_data = json.loads(out_show)
    assert "dev-comfort" in show_data["profiles"]

    rc_schema, out_schema, _ = cli_runner(["schema", "doctor"])
    assert rc_schema == 0
    assert "blockers" in json.loads(out_schema)["required"]

    rc_audit, out_audit, _ = cli_runner(["audit", "--json"])
    assert rc_audit == 0
    audit_data = json.loads(out_audit)
    check_ids = {f["check_id"] for f in audit_data["findings"]}
    assert {"chk.autologon_secrets", "chk.firewall_default_actions", "chk.hyperv_firewall"} <= check_ids

    rc_doc, out_doc, _ = cli_runner(["doctor", "--json"])
    assert rc_doc == 0
    doc_data = json.loads(out_doc)
    assert "managed" in doc_data
    assert "blockers" in doc_data


def test_profile_schema_v2_and_unknown_key_line_number(tmp_path: Path) -> None:
    """ENG-10: Profile v2 supports [packages], [params], include, and reports unknown keys with line numbers."""
    good_toml = tmp_path / "v2.toml"
    good_toml.write_text(
        'name = "v2-test"\n'
        'include = ["edge-quiet"]\n'
        "[packages]\n"
        'presets = ["dev-core"]\n'
        'install = ["jq"]\n'
        '[params."input.keyboard_repeat"]\n'
        "keyboard_delay = 0\n",
        encoding="utf-8",
    )
    loaded = load_profile(str(good_toml))
    assert loaded.tweaks.get("edge.quieting_baseline") is True
    assert "jq" in loaded.packages
    assert "git" in loaded.packages
    assert loaded.params["input.keyboard_repeat"]["keyboard_delay"] == 0
    assert "jq" in PACKAGE_CATALOG

    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text('name = "bad"\nbogus_top = 123\n', encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="line 2"):
        load_profile(str(bad_toml))


def test_audit_autologon_redacted_and_blockers(registry: InMemoryRegistryBackend) -> None:
    """Section G & MGD-01: Autologon secret is never leaked; blockers report TAMPER_PROTECTION & WSL_POLICY_BLOCKED."""
    reg = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword"): (
                "SuperSecret123!",
                REG_SZ,
            ),
            (HIVE_HKLM, DEFENDER_FEATURES_KEY, "TamperProtection"): (5, REG_DWORD),
            (HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\WSL", "AllowWSL"): (0, REG_DWORD),
        }
    )
    sys_b = InMemorySystemBackend(is_admin=False)
    env = sys_b.detect_environment(reg)
    findings = run_security_audit(env, reg, sys_b)
    auto_f = next(f for f in findings if f.check_id == "chk.autologon_secrets")
    assert auto_f.severity == "critical"
    assert "SuperSecret123!" not in json.dumps(auto_f.to_dict())

    codes = {b["code"] for b in build_doctor_blockers(env, reg, findings)}
    assert {"NOT_ADMIN", "TAMPER_PROTECTION", "WSL_POLICY_BLOCKED"} <= codes


def test_wsl_extended_features_and_version_gating(tmp_path: Path) -> None:
    """WSL-01..07: Extended .wslconfig, /etc/wsl.conf root refusal, policy detection, deep audit, export sha256."""
    spec = WslConfigSpec(
        mode="strict",
        vm_idle_timeout=60000,
        host_address_loopback=True,
        default_user="alice",
        hostname="wslbox",
    )
    warn_list: list[str] = []
    sec_old = build_wslconfig_sections(spec, 32 * 1024**3, installed_wsl_version="1.2.0", warnings=warn_list)
    assert "hostAddressLoopback" not in sec_old["experimental"]
    assert warn_list

    conf_sec = build_distro_wsl_conf_sections(spec)
    assert conf_sec["user"]["default"] == "alice"
    assert conf_sec["network"]["hostname"] == "wslbox"

    with pytest.raises(WslOperationError):
        build_distro_wsl_conf_sections(WslConfigSpec(default_user="root"))

    reg = InMemoryRegistryBackend(
        initial_values={(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\WSL", "AllowWSL"): (0, REG_DWORD)}
    )
    assert detect_wsl_policies(reg)["blocked"] is True
    assert is_wsl_version_outdated("2.0.0") is True
    assert is_wsl_version_outdated("2.4.0") is False

    sys_b = InMemorySystemBackend(is_admin=True)
    deep = deep_audit_wsl_distro(sys_b, "Ubuntu")
    assert deep["distro"] == "Ubuntu"

    tar_out = tmp_path / "Ubuntu-2026.tar"
    tar_out.write_bytes(b"tar-payload")
    exp = export_wsl_distro(sys_b, "Ubuntu", tar_out, dry_run=False)
    assert exp["sha256"] is not None
    assert tar_out.with_suffix(".tar.sha256").is_file()
    assert update_wsl(sys_b, dry_run=True)["dry_run"] is True
    assert set_wsl_distro_sparse(sys_b, "Ubuntu", dry_run=True)["command"][-1] == "true"


def test_locale_independent_parsers_swedish_and_german(registry: InMemoryRegistryBackend) -> None:
    """QA-01: Non-English Swedish/German command outputs parse identically via exit codes, XML, /English, /r."""
    sys_b = NativeSystemBackend(platform_override="win32")

    # Swedish / German HRESULTs & exit codes
    assert sys_b._classify_cmd_failure(5, "", "Åtkomst nekad") == "access_denied"
    assert sys_b._classify_cmd_failure(1, "", "Zugriff verweigert 0x80070005") == "access_denied"
    assert sys_b._classify_cmd_failure(1, "", "Blockerad av princip") == "unknown"  # no English/localized text guessing

    # XML schtasks output (locale independent)
    with patch.object(
        sys_b,
        "_run_native_cmd",
        return_value=type(
            "R",
            (),
            {"returncode": 0, "stdout": "<Task><Settings><Enabled>false</Enabled></Settings></Task>", "stderr": ""},
        )(),
    ):
        assert sys_b.is_scheduled_task_enabled(r"\Microsoft\Windows\Task") is False

    # wevtutil XML
    xml_sec = '<channel name="Security" enabled="true"><logging><maxSize>134217728</maxSize></logging></channel>'
    with patch.object(
        sys_b,
        "_run_native_cmd",
        return_value=type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": xml_sec,
                "stderr": "",
            },
        )(),
    ):
        assert sys_b.get_event_log_config("Security") == (True, 134217728)

    # auditpol /r /v numeric SettingValue=3
    with patch.object(
        sys_b,
        "_run_native_cmd",
        return_value=type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": "HOST,System,Prozess-Erstellung,{0CCE922B-69AE-11D9-BED3-505054503030},Erfolg und Fehler,3\n",
                "stderr": "",
            },
        )(),
    ):
        assert sys_b.get_auditpol_subcategory("{0CCE922B-69AE-11D9-BED3-505054503030}") == "Success and Failure"

    # wsl --list --verbose with UTF-16 null bytes & localized header
    mem_sys = InMemorySystemBackend()
    with patch.object(
        mem_sys,
        "run_wsl_command",
        return_value=type(
            "R", (), {"returncode": 0, "stdout": "  NAMN  TILLSTÅND  VERSION\n* Ubuntu  Körs  2\n", "stderr": ""}
        )(),
    ):
        assert detect_default_wsl_distro(mem_sys, mem_sys.detect_environment(registry)) == "Ubuntu"

    # Swedish sc.exe query WinDefend ("TILLSTÅND : 4  KÖRS") -> numeric state 4 recognized without English words
    from winbearable.backends.system import _observe_defender
    from winbearable.const import DEFENDER_KEY, HIVE_HKLM, REG_DWORD
    from winbearable.models import ObservationState

    reg_def = InMemoryRegistryBackend(initial_values={(HIVE_HKLM, DEFENDER_KEY, "DisableAntiSpyware"): (1, REG_DWORD)})
    obs_sv, _ = _observe_defender(
        reg_def,
        lambda _args: type("R", (), {"returncode": 0, "stdout": "TILLSTÅND : 4  KÖRS\n", "stderr": ""})(),
    )
    assert obs_sv.state == ObservationState.UNKNOWN

    # German sc.exe query WinDefend ("ZUSTAND : 1  GESTOPPT") -> numeric state 1 recognized
    reg_def_ok = InMemoryRegistryBackend()
    obs_de, def_bool = _observe_defender(
        reg_def_ok,
        lambda _args: type("R", (), {"returncode": 0, "stdout": "ZUSTAND : 1  GESTOPPT\n", "stderr": ""})(),
    )
    assert def_bool is False
    assert obs_de.state == ObservationState.DISABLED

    # wsl --list --verbose with UTF-16LE null bytes & BOM & localized header
    with patch.object(
        mem_sys,
        "run_wsl_command",
        return_value=type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": (
                    "\ufeff  N\x00A\x00M\x00N\x00\n"
                    "*\x00 \x00U\x00b\x00u\x00n\x00t\x00u\x00  K\x00ö\x00r\x00s\x00  2\x00\n"
                ),
                "stderr": "",
            },
        )(),
    ):
        assert detect_default_wsl_distro(mem_sys, mem_sys.detect_environment(registry)) == "Ubuntu"


def test_randomized_apply_rollback_and_recover_property(tmp_path: Path) -> None:
    """QA-04: Random subsets: plan never mutates, apply+rollback restores state, recover cleans up."""
    rng = random.Random(26300)
    reversible_ids = [
        tid for tid, t in TWEAK_CATALOG.items() if not t.irreversible and not t.file_specs and not t.icacls_specs
    ]

    for trial in range(5):
        subset = rng.sample(reversible_ids, k=8)
        reg = InMemoryRegistryBackend()
        sys_b = InMemorySystemBackend(is_admin=True)
        store = StateStore(tmp_path / f"state_{trial}.json")
        prof = ProfileSpec(name=f"rand-{trial}", description="rand", tweaks=dict.fromkeys(subset, True))
        env = sys_b.detect_environment(reg)

        before_vals = dict(reg._values)
        apply_profile(prof, env, reg, sys_b, store, dry_run=True, allow_high_risk=True)
        assert dict(reg._values) == before_vals

        apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_high_risk=True, allow_simulated=True)
        rollback_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)
        assert dict(reg._values) == before_vals

    # Interrupted apply recovery
    reg_crash = InMemoryRegistryBackend()
    sys_crash = InMemorySystemBackend(is_admin=True)
    store_crash = StateStore(tmp_path / "crash.json")
    prof_crash = ProfileSpec(
        name="crash", description="crash", tweaks={"input.disable_beep": True, "dev.long_paths": True}
    )
    with patch.object(sys_crash, "set_service_start_type", side_effect=RuntimeError("boom")):
        apply_profile(
            prof_crash,
            sys_crash.detect_environment(reg_crash),
            reg_crash,
            sys_crash,
            store_crash,
            dry_run=False,
            allow_simulated=True,
        )
    recover_incomplete_runs(store_crash, reg_crash, sys_crash, dry_run=False, allow_simulated=True)
    assert store_crash.get_incomplete_runs() == []


def test_multidistro_wsl_failure_compensates_first_distro_and_wslconfig(
    state_store: StateStore,
    tmp_path: Path,
) -> None:
    """P0.2: Failure on second WSL distro restores .wslconfig and first distro's /etc/wsl.conf."""
    from winbearable.backends.system import CommandResult
    from winbearable.models import TransactionState, WslConfigSpec

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=True, wsl_distros=("Ubuntu", "Debian"))
    env = sys_b.detect_environment(reg)
    wslconfig = tmp_path / ".wslconfig"
    wslconfig.write_text("[wsl2]\nmemory=4GB\n", encoding="utf-8")

    distro_confs: dict[str, str] = {"Ubuntu": "[user]\ndefault=alice\n"}

    def _fake_wsl(args: list[str], input_text: str | None = None) -> CommandResult:
        distro = args[1] if len(args) > 1 and args[0] == "-d" else ""
        cmd = args[5] if len(args) > 5 else ""
        if cmd == "cat":
            if distro in distro_confs:
                return CommandResult(tuple(args), 0, distro_confs[distro], "")
            return CommandResult(tuple(args), 1, "", "No such file")
        if cmd == "tee":
            if distro == "Debian":
                return CommandResult(tuple(args), 1, "", "disk full")
            distro_confs[distro] = input_text or ""
            return CommandResult(tuple(args), 0, "", "")
        if cmd == "rm":
            distro_confs.pop(distro, None)
            return CommandResult(tuple(args), 0, "", "")
        return CommandResult(tuple(args), 0, "", "")

    prof = ProfileSpec(name="wsl-multi", description="wsl-multi", tweaks={}, wsl=WslConfigSpec(enabled=True))
    with patch.object(sys_b, "run_wsl_command", side_effect=_fake_wsl):
        summary = apply_profile(
            prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True, wslconfig_path=wslconfig
        )

    assert "wsl" in summary.failed_ids
    assert wslconfig.read_text(encoding="utf-8") == "[wsl2]\nmemory=4GB\n"
    assert distro_confs["Ubuntu"] == "[user]\ndefault=alice\n"
    runs = state_store.load_runs()
    assert runs[-1].state == TransactionState.ROLLED_BACK
    assert [snap.distro for snap in runs[-1].wsl_distro_snapshots] == ["Ubuntu", "Debian"]


def test_state_store_pruning_preserves_incomplete_and_credential_hygiene(tmp_path: Path) -> None:
    """Cover StateStore rotation bounds (P1.6) and _audit_credential_hygiene happy/error paths (P1-L.3)."""
    from winbearable.models import RunRecord, TransactionState
    from winbearable.state import DEFAULT_MAX_BACKUP_DIRS, DEFAULT_MAX_RUN_HISTORY
    from winbearable.wsl import _audit_credential_hygiene

    store = StateStore(tmp_path / "state.json")
    backups_root = tmp_path / "backups"
    backups_root.mkdir()
    runs: list[RunRecord] = [
        RunRecord(
            run_id="incomplete-keep",
            timestamp="2026-11-17T00:00:00Z",
            profile_name="owner",
            applied_tweaks=(),
            state=TransactionState.APPLYING,
        )
    ]
    (backups_root / "incomplete-keep").mkdir()
    for idx in range(DEFAULT_MAX_RUN_HISTORY + 5):
        rid = f"done-{idx:03d}"
        (backups_root / rid).mkdir()
        runs.append(
            RunRecord(
                run_id=rid,
                timestamp=f"2026-11-17T00:{idx:02d}:00Z",
                profile_name="user-only",
                applied_tweaks=(),
                state=TransactionState.COMMITTED,
            )
        )
    store.save_runs(runs)
    loaded = store.load_runs()
    assert len(loaded) == DEFAULT_MAX_RUN_HISTORY
    assert any(r.run_id == "incomplete-keep" for r in loaded)
    assert (backups_root / "incomplete-keep").is_dir()
    non_protected_dirs = [p for p in backups_root.iterdir() if p.name != "incomplete-keep"]
    assert len(non_protected_dirs) <= DEFAULT_MAX_BACKUP_DIRS

    # Credential hygiene: clean vs dirty
    clean_ssh = tmp_path / "ssh_clean"
    clean_ssh.mkdir(mode=0o700)
    clean_key = clean_ssh / "id_ed25519"
    clean_key.write_text("PRIVATE", encoding="utf-8")
    clean_key.chmod(0o600)
    import os

    clean_res = _audit_credential_hygiene(["store"], ssh_dir=clean_ssh, env_vars={})
    if os.name == "posix":
        assert clean_res["clean"] is True

    dirty_ssh = tmp_path / "ssh_dirty"
    dirty_ssh.mkdir(mode=0o755)
    dirty_key = dirty_ssh / "id_rsa"
    dirty_key.write_text("PRIVATE", encoding="utf-8")
    dirty_key.chmod(0o644)
    dirty_res = _audit_credential_hygiene(
        ["/mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe"],
        ssh_dir=dirty_ssh,
        env_vars={"SSH_AUTH_SOCK": "/mnt/c/Users/alice/agent.sock"},
    )
    assert dirty_res["clean"] is False
    assert dirty_res["ssh_agent_windows_leak"] is True
    assert len(dirty_res["windows_git_helpers"]) == 1
    assert len(dirty_res["ssh_insecure_keys"]) == 1


def test_wsl_write_ahead_journal_before_mutation_and_probe_error_refusal(
    state_store: StateStore,
    tmp_path: Path,
) -> None:
    """Cover write-ahead WSL snapshot persistence before mutation and probe error refusal."""
    from winbearable.backends.system import CommandResult
    from winbearable.engine import recover_incomplete_runs
    from winbearable.models import TransactionState, WslConfigSpec
    from winbearable.wsl import WslOperationError, plan_or_apply_wsl, probe_distro_wsl_conf

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=True, wsl_distros=("Ubuntu", "Debian"))
    env = sys_b.detect_environment(reg)
    wslconfig = tmp_path / ".wslconfig"
    wslconfig.write_text("[wsl2]\nmemory=4GB\n", encoding="utf-8")

    distro_confs: dict[str, str] = {"Ubuntu": "[user]\ndefault=alice\n"}
    saw_write_ahead_before_tee = False
    in_recovery = False

    def _wsl_with_crash_check(args: list[str], input_text: str | None = None) -> CommandResult:
        nonlocal saw_write_ahead_before_tee
        distro = args[1] if len(args) > 1 and args[0] == "-d" else ""
        cmd = args[5] if len(args) > 5 else ""
        if cmd == "test":
            return CommandResult(tuple(args), 0 if distro in distro_confs else 1, "", "")
        if cmd == "cat":
            if distro in distro_confs:
                return CommandResult(tuple(args), 0, distro_confs[distro], "")
            return CommandResult(tuple(args), 1, "", "No such file")
        if cmd == "tee":
            if not in_recovery:
                # Verify StateStore on disk ALREADY has APPLYING + backup + both distro snapshots before tee!
                fresh_runs = StateStore(state_store.state_path).load_runs()
                assert fresh_runs and fresh_runs[-1].state == TransactionState.APPLYING
                assert fresh_runs[-1].wsl_backup_path is not None
                assert [s.distro for s in fresh_runs[-1].wsl_distro_snapshots] == ["Ubuntu", "Debian"]
                saw_write_ahead_before_tee = True
                if distro != "Ubuntu":
                    raise RuntimeError("simulated crash before Debian tee")
            distro_confs[distro] = input_text or ""
            return CommandResult(tuple(args), 0, "", "")
        if cmd == "rm":
            distro_confs.pop(distro, None)
            return CommandResult(tuple(args), 0, "", "")
        return CommandResult(tuple(args), 0, "", "")

    prof = ProfileSpec(name="wsl-wa", description="wsl-wa", tweaks={}, wsl=WslConfigSpec(enabled=True))
    with (
        patch.object(sys_b, "run_wsl_command", side_effect=_wsl_with_crash_check),
        pytest.raises(RuntimeError, match="simulated crash"),
    ):
        apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True, wslconfig_path=wslconfig)

    assert saw_write_ahead_before_tee is True
    assert StateStore(state_store.state_path).load_runs()[-1].state == TransactionState.APPLYING

    # Fresh StateStore + recover_incomplete_runs restores .wslconfig and Ubuntu /etc/wsl.conf
    in_recovery = True
    with patch.object(sys_b, "run_wsl_command", side_effect=_wsl_with_crash_check):
        rec_runs = recover_incomplete_runs(
            StateStore(state_store.state_path), reg, sys_b, dry_run=False, allow_simulated=True
        )
    assert rec_runs and rec_runs[-1].state == TransactionState.ROLLED_BACK
    assert wslconfig.read_text(encoding="utf-8") == "[wsl2]\nmemory=4GB\n"
    assert distro_confs["Ubuntu"] == "[user]\ndefault=alice\n"

    # P0.3: Distinguish confirmed missing vs permission denied / distro error
    def _probe_errors(args: list[str], input_text: str | None = None) -> CommandResult:
        distro = args[1] if len(args) > 1 and args[0] == "-d" else ""
        cmd = args[5] if len(args) > 5 else ""
        if distro == "PermDenied":
            if cmd == "test":
                return CommandResult(tuple(args), 0, "", "")
            return CommandResult(tuple(args), 1, "", "cat: /etc/wsl.conf: Permission denied")
        if distro == "MissingDistro":
            return CommandResult(tuple(args), 1, "", "There is no distribution with the supplied name.")
        return CommandResult(tuple(args), 1, "", "")

    with patch.object(sys_b, "run_wsl_command", side_effect=_probe_errors):
        assert probe_distro_wsl_conf("ConfirmedAbsent", sys_b).status == "missing"
        assert probe_distro_wsl_conf("PermDenied", sys_b).status == "error"
        assert probe_distro_wsl_conf("MissingDistro", sys_b).status == "error"

        dry_res = plan_or_apply_wsl(WslConfigSpec(enabled=True), sys_b, wslconfig_path=wslconfig, distro="PermDenied")
        assert dry_res["distro_read_status"] == "error"
        assert "Permission denied" in dry_res["distro_read_evidence"]

        with pytest.raises(WslOperationError, match="Refusing to modify /etc/wsl.conf"):
            plan_or_apply_wsl(
                WslConfigSpec(enabled=True), sys_b, wslconfig_path=wslconfig, distro="PermDenied", dry_run=False
            )


def test_wsl_permission_error_with_zero_drifted_tweaks_does_not_strand_applying(
    state_store: StateStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-06: PermissionError in WSL step with zero drifted tweaks transitions to ROLLED_BACK, not stranded APPLYING."""
    from winbearable.models import TransactionState, WslConfigSpec

    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=True, wsl_distros=())
    env = sys_b.detect_environment(reg)
    prof = ProfileSpec(name="wsl-only", description="wsl-only", tweaks={}, wsl=WslConfigSpec(enabled=True))

    def _ro_applier(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("read-only .wslconfig")

    with patch("winbearable.wsl.get_default_wslconfig_path", return_value=tmp_path / ".wslconfig"):
        summary = apply_profile(
            prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True, wsl_applier=_ro_applier
        )

    assert summary.wsl_result is not None
    assert summary.wsl_result.get("skipped") is True
    assert state_store.get_incomplete_runs() == []
    runs = state_store.load_runs()
    assert runs and runs[-1].state == TransactionState.ROLLED_BACK

    # Subsequent apply succeeds without IncompleteJournalError
    with patch("winbearable.wsl.get_default_wslconfig_path", return_value=tmp_path / ".wslconfig"):
        summary2 = apply_profile(
            prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True, wsl_applier=lambda *_a, **_kw: None
        )
    assert summary2.failed_ids == ()
