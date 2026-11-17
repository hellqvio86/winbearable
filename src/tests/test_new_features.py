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
    ACTION_DELETE_KEY,
    DEFAULT_TESTED_BUILDS,
    DEFENDER_FEATURES_KEY,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
    REG_SZ,
)
from winbearable.engine import apply_profile, detect_tweak, recover_incomplete_runs, rollback_runs
from winbearable.models import (
    FileSpec,
    ProfileSpec,
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
    TweakStatus,
    WslConfigSpec,
)
from winbearable.operations import apply_file_spec, merge_file_content, snapshot_file_spec
from winbearable.packages import PACKAGE_CATALOG
from winbearable.profiles import ProfileValidationError, load_profile
from winbearable.state import StateStore
from winbearable.tweaks import TWEAK_CATALOG, get_tweak, validate_catalog
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


def test_registry_key_delete_and_glob_roundtrip(state_store: StateStore) -> None:
    """ENG-01: ACTION_DELETE_KEY and key_path_glob expand, apply, and roll back cleanly."""
    reg = InMemoryRegistryBackend(
        initial_values={
            (
                HIVE_HKLM,
                r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{AAA}",
                "NetbiosOptions",
            ): (0, REG_DWORD),
            (
                HIVE_HKLM,
                r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{BBB}",
                "NetbiosOptions",
            ): (1, REG_DWORD),
        }
    )
    sys_b = InMemorySystemBackend(is_admin=True)
    tweak = get_tweak("hardening.disable_netbios_tcp")
    prof = ProfileSpec(name="netbt", description="test", tweaks={"hardening.disable_netbios_tcp": True})

    res = detect_tweak(tweak, sys_b.detect_environment(reg), reg, sys_b)
    assert res.status == TweakStatus.DRIFTED
    assert len(res.registry_changes) == 2

    summary = apply_profile(
        prof, sys_b.detect_environment(reg), reg, sys_b, state_store, dry_run=False, allow_simulated=True
    )
    assert summary.applied_ids == ("hardening.disable_netbios_tcp",)
    assert reg.get_value(
        HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{AAA}", "NetbiosOptions"
    ) == (2, REG_DWORD)

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert reg.get_value(
        HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{AAA}", "NetbiosOptions"
    ) == (0, REG_DWORD)

    # Zero glob matches count as compliant
    empty_reg = InMemoryRegistryBackend()
    empty_res = detect_tweak(tweak, sys_b.detect_environment(empty_reg), empty_reg, sys_b)
    assert empty_res.status == TweakStatus.APPLIED
    assert "0 matching subkeys" in empty_res.detail

    # Key deletion roundtrip
    reg_del = InMemoryRegistryBackend(initial_values={(HIVE_HKCU, r"Software\TempDel\Sub", "Val"): ("x", REG_SZ)})
    del_tweak = TweakDefinition(
        tweak_id="test.del_key",
        category="explorer",
        title="Delete key",
        description="Delete key",
        source_url="https://learn.microsoft.com/",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(RegistrySpec(hive=HIVE_HKCU, key_path=r"Software\TempDel", action=ACTION_DELETE_KEY),),
        provenance=_dummy_prov(),
    )
    with patch.dict(TWEAK_CATALOG, {"test.del_key": del_tweak}):
        p2 = ProfileSpec(name="del", description="del", tweaks={"test.del_key": True})
        apply_profile(
            p2, sys_b.detect_environment(reg_del), reg_del, sys_b, state_store, dry_run=False, allow_simulated=True
        )
        assert not reg_del.key_exists(HIVE_HKCU, r"Software\TempDel")
        rollback_runs(state_store, reg_del, sys_b, dry_run=False, allow_simulated=True)
        assert reg_del.get_value(HIVE_HKCU, r"Software\TempDel\Sub", "Val") == ("x", REG_SZ)

    # Invalid glob rejected by validation
    bad_glob = TweakDefinition(
        tweak_id="test.bad_glob",
        category="explorer",
        title="Bad glob",
        description="Bad glob",
        source_url="https://learn.microsoft.com/",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(hive=HIVE_HKCU, key_path=r"Software", key_path_glob=r"*\*", value_name="X", value_data=1),
        ),
        provenance=_dummy_prov(),
    )
    errs = validate_catalog({"test.bad_glob": bad_glob})
    assert any("invalid key_path_glob" in e for e in errs)


def test_edition_gating_rejects_home_policy_and_all_iot_ltsc(
    registry: InMemoryRegistryBackend, state_store: StateStore
) -> None:
    """ENG-02: Home skips Pro-only policy tweaks; IoT/LTSC editions are rejected everywhere."""
    home_sys = InMemorySystemBackend(edition="Core", is_admin=True)
    pro_sys = InMemorySystemBackend(edition="Professional", is_admin=True)
    iot_sys = InMemorySystemBackend(edition="IoTEnterpriseS", is_admin=True)

    policy_tweak = get_tweak("onedrive.disable_policy")
    assert (
        detect_tweak(policy_tweak, home_sys.detect_environment(registry), registry, home_sys).status
        == TweakStatus.UNSUPPORTED_EDITION
    )
    assert (
        detect_tweak(policy_tweak, pro_sys.detect_environment(registry), registry, pro_sys).status
        == TweakStatus.DRIFTED
    )

    user_tweak = get_tweak("explorer.show_file_extensions")
    iot_res = detect_tweak(user_tweak, iot_sys.detect_environment(registry), registry, iot_sys)
    assert iot_res.status == TweakStatus.UNSUPPORTED_EDITION
    assert "IoT/LTSC" in iot_res.detail

    prof = ProfileSpec(name="ed", description="ed", tweaks={"onedrive.disable_policy": True})
    summary = apply_profile(
        prof,
        home_sys.detect_environment(registry),
        registry,
        home_sys,
        state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert summary.skipped_edition_ids == ("onedrive.disable_policy",)


def test_managed_device_guard_and_edr_detection(state_store: StateStore) -> None:
    """ENG-03 & ENG-04: Managed devices skip admin tweaks unless --allow-managed; EDR triggers doctor warning."""
    reg = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments\GUID-1", "UPN"): ("user@corp.example", REG_SZ),
            (HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\CSFalconService", "Start"): (2, REG_DWORD),
        }
    )
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)
    assert env.mdm_enrolled is True
    assert env.observations["edr"].state == "enabled"

    prof = ProfileSpec(
        name="m", description="m", tweaks={"onedrive.disable_policy": True, "explorer.show_file_extensions": True}
    )
    s_default = apply_profile(prof, env, reg, sys_b, state_store, dry_run=True, allow_managed=False)
    assert s_default.skipped_managed_ids == ("onedrive.disable_policy",)
    assert "explorer.show_file_extensions" in s_default.applied_ids

    s_override = apply_profile(prof, env, reg, sys_b, state_store, dry_run=True, allow_managed=True)
    assert "onedrive.disable_policy" in s_override.applied_ids


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


def test_file_config_adapter_json_jsonc_and_hash_guard(tmp_path: Path) -> None:
    """ENG-08: JSON/INI/TOML merge preserves keys, JSONC comments are rejected, hash drift is refused."""
    json_file = tmp_path / "settings.json"
    json_file.write_text('{"existing": true}\n', encoding="utf-8")
    spec = FileSpec(path_template=str(json_file), file_format="json", desired_keys={"copyOnSelect": True})
    snap = snapshot_file_spec(spec)
    apply_file_spec(spec, expected_sha256=snap.sha256)
    parsed = json.loads(json_file.read_text(encoding="utf-8"))
    assert parsed == {"existing": True, "copyOnSelect": True}

    # Hash drift refusal
    json_file.write_text('{"existing": false}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="hash changed"):
        apply_file_spec(spec, expected_sha256=snap.sha256)

    # JSONC comment refusal
    with pytest.raises(ValueError, match="comments"):
        merge_file_content('{\n  // user comment\n  "a": 1\n}\n', "jsonc", {"b": 2})


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


def test_new_tweaks_roundtrip_and_tamper_protection(state_store: StateStore) -> None:
    """TWK-A..J: Representative new tweaks roundtrip cleanly and TWK-H honours Tamper Protection."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)

    sample_ids = [
        "input.caps_to_ctrl",
        "terminal.default_host_windows_terminal",
        "privacy.disable_feedback_prompts",
        "edge.quieting_baseline",
        "services.disable_diagtrack",
        "hardening.firewall_disable_risky_groups",
        "hardening.audit_core_subcategories",
        "hardening.event_log_sizes",
        "dev.git_sane_defaults",
    ]
    prof = ProfileSpec(name="sample", description="sample", tweaks=dict.fromkeys(sample_ids, True))
    summary = apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert set(summary.applied_ids) == set(sample_ids)

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    for tid in sample_ids:
        assert detect_tweak(get_tweak(tid), env, reg, sys_b).status == TweakStatus.DRIFTED

    # Tamper Protection blocks TWK-H tweaks
    reg.set_value(HIVE_HKLM, DEFENDER_FEATURES_KEY, "TamperProtection", 5, REG_DWORD)
    asr_res = detect_tweak(get_tweak("hardening.defender_asr_audit"), env, reg, sys_b)
    assert asr_res.status == TweakStatus.BLOCKED_BY_POLICY
    assert "tamper_protection" in asr_res.detail


def test_bloat_remove_appx_opt_in_irreversible_guard(state_store: StateStore) -> None:
    """DEC-02: bloat.remove_* tweaks require allow_irreversible and uninstall via winget."""
    from winbearable.engine import IrreversibleActionError

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=False, installed_winget_packages={"9WZDNCRFHVFW"})
    env = sys_b.detect_environment(reg)
    prof = ProfileSpec(name="bloat", description="bloat", tweaks={"bloat.remove_bing_news": True})

    assert detect_tweak(get_tweak("bloat.remove_bing_news"), env, reg, sys_b).status == TweakStatus.DRIFTED

    with pytest.raises(IrreversibleActionError):
        apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)

    summary = apply_profile(
        prof, env, reg, sys_b, state_store, dry_run=False, allow_irreversible=True, allow_simulated=True
    )
    assert "bloat.remove_bing_news" in summary.applied_ids
    assert detect_tweak(get_tweak("bloat.remove_bing_news"), env, reg, sys_b).status == TweakStatus.APPLIED


def test_controlled_folder_access_audit_and_inactivity_lock_roundtrip(state_store: StateStore) -> None:
    """hardening.defender_controlled_folder_access_audit & inactivity_lock roundtrip and honour Tamper Protection."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)
    ids = ["hardening.defender_controlled_folder_access_audit", "hardening.inactivity_lock"]
    prof = ProfileSpec(name="h", description="h", tweaks=dict.fromkeys(ids, True))

    summary = apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert set(summary.applied_ids) == set(ids)
    for tid in ids:
        assert detect_tweak(get_tweak(tid), env, reg, sys_b).status == TweakStatus.APPLIED

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    for tid in ids:
        assert detect_tweak(get_tweak(tid), env, reg, sys_b).status == TweakStatus.DRIFTED

    reg.set_value(HIVE_HKLM, DEFENDER_FEATURES_KEY, "TamperProtection", 5, REG_DWORD)
    cfa_res = detect_tweak(get_tweak("hardening.defender_controlled_folder_access_audit"), env, reg, sys_b)
    assert cfa_res.status == TweakStatus.BLOCKED_BY_POLICY


def test_enable_windows_containers_roundtrip(state_store: StateStore) -> None:
    """dev.enable_windows_containers enables Containers optional feature and rolls back cleanly."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)
    prof = ProfileSpec(name="containers", description="containers", tweaks={"dev.enable_windows_containers": True})

    assert detect_tweak(get_tweak("dev.enable_windows_containers"), env, reg, sys_b).status == TweakStatus.DRIFTED
    summary = apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert "dev.enable_windows_containers" in summary.applied_ids
    assert detect_tweak(get_tweak("dev.enable_windows_containers"), env, reg, sys_b).status == TweakStatus.APPLIED

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert detect_tweak(get_tweak("dev.enable_windows_containers"), env, reg, sys_b).status == TweakStatus.DRIFTED


def test_vscode_settings_defaults_roundtrip_and_guards(
    state_store: StateStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dev.vscode_settings_defaults merges JSON settings, rolls back, refuses JSONC comments, and gates on build."""
    import json

    monkeypatch.setenv("APPDATA", str(tmp_path))
    settings_path = tmp_path / "Code" / "User" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"editor.fontSize": 14}\n', encoding="utf-8")
    monkeypatch.setattr("winbearable.engine.expand_file_spec_path", lambda _tpl: settings_path)
    monkeypatch.setattr("winbearable.operations.expand_file_spec_path", lambda _tpl: settings_path)

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=False)
    env = sys_b.detect_environment(reg)
    tweak = get_tweak("dev.vscode_settings_defaults")
    prof = ProfileSpec(name="vscode", description="vscode", tweaks={"dev.vscode_settings_defaults": True})

    assert detect_tweak(tweak, env, reg, sys_b).status == TweakStatus.DRIFTED
    summary = apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert "dev.vscode_settings_defaults" in summary.applied_ids
    assert detect_tweak(tweak, env, reg, sys_b).status == TweakStatus.APPLIED

    merged = json.loads(settings_path.read_text(encoding="utf-8"))
    assert merged["editor.fontSize"] == 14
    assert merged["telemetry.telemetryLevel"] == "off"
    assert merged["terminal.integrated.defaultProfile.windows"] == "Ubuntu (WSL)"
    assert merged["files.eol"] == "\n"

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert detect_tweak(tweak, env, reg, sys_b).status == TweakStatus.DRIFTED
    assert json.loads(settings_path.read_text(encoding="utf-8")) == {"editor.fontSize": 14}

    # JSONC comment refusal reports ERROR rather than overwriting comments
    settings_path.write_text('// user comment\n{"editor.fontSize": 14}\n', encoding="utf-8")
    comment_res = detect_tweak(tweak, env, reg, sys_b)
    assert comment_res.status == TweakStatus.ERROR

    # Unsupported build floor
    from dataclasses import replace

    old_env = replace(env, windows_build=22631)
    assert detect_tweak(tweak, old_env, reg, sys_b).status == TweakStatus.UNSUPPORTED_BUILD


def test_parameterized_tweaks_and_terminal_nerd_font_roundtrip(
    state_store: StateStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover dev.case_sensitive_dirs, hardening.update_active_hours, dev.terminal_settings_defaults, and nerd font."""
    import json

    from winbearable.engine import evaluate_profile

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)

    # Missing [params] reports ERROR
    missing_prof = ProfileSpec(
        name="missing",
        description="missing",
        tweaks={"dev.case_sensitive_dirs": True, "hardening.update_active_hours": True},
    )
    missing_eval = evaluate_profile(missing_prof, env, reg, sys_b)
    assert all(r.status == TweakStatus.ERROR for r in missing_eval)

    # With [params] populated
    cs_dir = tmp_path / "src_case"
    wt_path = tmp_path / "wt" / "settings.json"
    wt_path.parent.mkdir(parents=True)
    wt_path.write_text('{"theme": "dark"}\n', encoding="utf-8")
    monkeypatch.setattr("winbearable.engine.expand_file_spec_path", lambda _tpl: wt_path)
    monkeypatch.setattr("winbearable.operations.expand_file_spec_path", lambda _tpl: wt_path)

    prof = ProfileSpec(
        name="dev-params",
        description="dev-params",
        tweaks={
            "dev.case_sensitive_dirs": True,
            "hardening.update_active_hours": True,
            "dev.terminal_settings_defaults": True,
            "dev.install_nerd_font_user": True,
        },
        params={
            "dev.case_sensitive_dirs": {"directories": [str(cs_dir)]},
            "hardening.update_active_hours": {"active_hours_start": 8, "active_hours_end": 20},
            "dev.terminal_settings_defaults": {"font_face": "JetBrainsMono Nerd Font"},
        },
    )
    summary = apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert set(summary.applied_ids) == {
        "dev.case_sensitive_dirs",
        "hardening.update_active_hours",
        "dev.terminal_settings_defaults",
        "dev.install_nerd_font_user",
    }
    assert sys_b.case_sensitive_dirs[str(cs_dir)] is True
    assert reg.get_value("HKLM", r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "ActiveHoursStart") == (
        8,
        "REG_DWORD",
    )
    assert reg.get_value("HKLM", r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "ActiveHoursEnd") == (
        20,
        "REG_DWORD",
    )
    wt_data = json.loads(wt_path.read_text(encoding="utf-8"))
    assert wt_data["copyOnSelect"] is True
    assert wt_data["profiles"]["defaults"]["font"]["face"] == "JetBrainsMono Nerd Font"
    assert sys_b.is_winget_package_installed("DEVCOM.JetBrainsMonoNerdFont") is True

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert sys_b.case_sensitive_dirs[str(cs_dir)] is False
    assert reg.get_value("HKLM", r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "ActiveHoursStart") is None
    assert json.loads(wt_path.read_text(encoding="utf-8")) == {"theme": "dark"}
    assert sys_b.is_winget_package_installed("DEVCOM.JetBrainsMonoNerdFont") is False


def test_parameterized_tweaks_and_terminal_error_paths(
    state_store: StateStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover invalid [params], non-empty directory revert refusal, and malformed Windows Terminal JSON."""
    from typing import Any

    from winbearable.engine import evaluate_profile

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)

    # Out-of-range / boolean / non-int active hours and blank directories report ERROR
    bad_hours_cases: list[dict[str, Any]] = [
        {"active_hours_start": -1, "active_hours_end": 17},
        {"active_hours_start": 8, "active_hours_end": 24},
        {"active_hours_start": True, "active_hours_end": 17},
        {"active_hours_start": "8", "active_hours_end": 17},
    ]
    for bad_hours in bad_hours_cases:
        bad_prof = ProfileSpec(
            name="bad-hours",
            description="bad-hours",
            tweaks={"hardening.update_active_hours": True, "dev.case_sensitive_dirs": True},
            params={
                "hardening.update_active_hours": bad_hours,
                "dev.case_sensitive_dirs": {"directories": ["   "]},
            },
        )
        res = evaluate_profile(bad_prof, env, reg, sys_b)
        assert all(r.status == TweakStatus.ERROR for r in res)

    # Malformed Windows Terminal JSON reports ERROR instead of crashing
    bad_wt = tmp_path / "wt_bad" / "settings.json"
    bad_wt.parent.mkdir(parents=True)
    bad_wt.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setattr("winbearable.engine.expand_file_spec_path", lambda _tpl: bad_wt)
    monkeypatch.setattr("winbearable.operations.expand_file_spec_path", lambda _tpl: bad_wt)
    wt_eval = evaluate_profile(
        ProfileSpec(name="bad-wt", description="bad-wt", tweaks={"dev.terminal_settings_defaults": True}),
        env,
        reg,
        sys_b,
    )
    assert wt_eval[0].status == TweakStatus.ERROR

    # Non-empty case-sensitive directory refuses revert cleanly
    non_empty_dir = tmp_path / "non_empty_cs"
    non_empty_dir.mkdir()
    cs_prof = ProfileSpec(
        name="cs",
        description="cs",
        tweaks={"dev.case_sensitive_dirs": True},
        params={"dev.case_sensitive_dirs": {"directories": [str(non_empty_dir)]}},
    )
    apply_profile(cs_prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    (non_empty_dir / "keep.txt").write_text("data", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Rollback errors: fsutil"):
        rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert sys_b.case_sensitive_dirs[str(non_empty_dir)] is True


def test_ai_surface_tweaks_and_legacy_tls_audit_roundtrip_and_errors(state_store: StateStore) -> None:
    """Cover TWK-C AI tweaks (roundtrip + irreversible guard) and chk.legacy_tls (clean + re-enabled)."""
    from winbearable.engine import IrreversibleActionError
    from winbearable.models import ObservationState

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(
        is_admin=True,
        installed_winget_packages={"XP9CXNGPPJ97XX"},
        optional_features={"SMB1Protocol": True, "Recall": True},
    )
    env = sys_b.detect_environment(reg)

    rev_ids = ["ai.disable_recall_feature", "ai.disable_click_to_do", "ai.disable_notepad_paint_ai"]
    rev_prof = ProfileSpec(name="ai-rev", description="ai-rev", tweaks=dict.fromkeys(rev_ids, True))
    summary = apply_profile(rev_prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert set(summary.applied_ids) == set(rev_ids)
    for tid in rev_ids:
        assert detect_tweak(get_tweak(tid), env, reg, sys_b).status == TweakStatus.APPLIED

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    for tid in rev_ids:
        assert detect_tweak(get_tweak(tid), env, reg, sys_b).status == TweakStatus.DRIFTED

    # Error path: irreversible ai.remove_copilot_app requires --allow-irreversible
    copilot_prof = ProfileSpec(name="copilot", description="copilot", tweaks={"ai.remove_copilot_app": True})
    with pytest.raises(IrreversibleActionError):
        apply_profile(copilot_prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)

    apply_profile(
        copilot_prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True, allow_irreversible=True
    )
    assert detect_tweak(get_tweak("ai.remove_copilot_app"), env, reg, sys_b).status == TweakStatus.APPLIED

    # chk.legacy_tls: disabled by default, medium severity if explicitly enabled
    clean_findings = run_security_audit(env, reg, sys_b)
    tls_clean = next(f for f in clean_findings if f.check_id == "chk.legacy_tls")
    assert tls_clean.observation.state == ObservationState.DISABLED
    assert tls_clean.severity == "info"

    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
        "Enabled",
        1,
    )
    bad_findings = run_security_audit(env, reg, sys_b)
    tls_bad = next(f for f in bad_findings if f.check_id == "chk.legacy_tls")
    assert tls_bad.observation.state == ObservationState.ENABLED
    assert tls_bad.severity == "medium"


def test_defender_asr_mode_selection_block_and_invalid_param(state_store: StateStore) -> None:
    """hardening.defender_asr_audit supports [params].mode='block' (1) and rejects invalid modes with ERROR."""
    from winbearable.engine import evaluate_profile

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)

    # Error path: invalid mode reports ERROR
    bad_prof = ProfileSpec(
        name="asr-bad",
        description="asr-bad",
        tweaks={"hardening.defender_asr_audit": True},
        params={"hardening.defender_asr_audit": {"mode": "invalid"}},
    )
    assert evaluate_profile(bad_prof, env, reg, sys_b)[0].status == TweakStatus.ERROR

    # Happy path: block mode sets ASR GUIDs to 1 and rolls back cleanly
    block_prof = ProfileSpec(
        name="asr-block",
        description="asr-block",
        tweaks={"hardening.defender_asr_audit": True},
        params={"hardening.defender_asr_audit": {"mode": "block"}},
    )
    summary = apply_profile(block_prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert summary.applied_ids == ("hardening.defender_asr_audit",)
    assert reg.get_value(
        HIVE_HKLM,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    ) == (1, "REG_DWORD")

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert (
        reg.get_value(
            HIVE_HKLM,
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        )
        is None
    )


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
    assert runs[-1].state == TransactionState.FAILED
    assert len(runs[-1].wsl_distro_snapshots) == 1
    assert runs[-1].wsl_distro_snapshots[0].distro == "Ubuntu"


def test_operation_adapters_surface_structured_outcomes_on_failure(
    state_store: StateStore,
    tmp_path: Path,
) -> None:
    """P0.3: Adapter failures (TIMEOUT, ACCESS_DENIED, TOOL_MISSING) surface into failure_outcomes and FAILED run."""
    from winbearable.models import OperationOutcome, OperationStatus, TransactionState

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)

    cases = [
        ("services.disable_diagtrack", "set_service_start_type", OperationStatus.TIMEOUT, 124),
        ("hardening.audit_core_subcategories", "set_auditpol_subcategory", OperationStatus.ACCESS_DENIED, 5),
        ("dev.git_sane_defaults", "set_git_global_config", OperationStatus.TOOL_MISSING, 127),
    ]
    for tid, method_name, expected_status, rc in cases:
        prof = ProfileSpec(name=f"fail-{tid}", description="fail", tweaks={tid: True})
        sys_b.last_outcome = OperationOutcome(
            status=expected_status,
            message=f"{expected_status} simulated",
            returncode=rc,
            command=(tid,),
        )
        with patch.object(sys_b, method_name, return_value=False):
            summary = apply_profile(prof, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
        assert tid in summary.failed_ids
        runs = state_store.load_runs()
        assert runs[-1].state == TransactionState.FAILED
        assert runs[-1].failure_outcomes[-1]["status"] == str(expected_status)
        assert runs[-1].failure_outcomes[-1]["returncode"] == rc
        # Clear failed run so next iteration can proceed
        state_store.save_runs([])


def test_file_config_sha256_drift_refusal_and_managed_device_guard(
    state_store: StateStore,
    tmp_path: Path,
) -> None:
    """Cover FileSpec SHA-256 drift refusal (P1.3) and MDM/corp-safe managed guards (P1.2)."""
    from winbearable.models import FileSpec
    from winbearable.operations import apply_file_spec, snapshot_file_spec
    from winbearable.profiles import load_profile

    cfg = tmp_path / "settings.json"
    cfg.write_text('{"a": 1}\n', encoding="utf-8")
    spec = FileSpec(path_template=str(cfg), file_format="json", desired_keys={"b": 2})
    snap = snapshot_file_spec(spec)
    cfg.write_text('{"a": 99}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="file hash changed"):
        apply_file_spec(spec, expected_sha256=snap.sha256)

    from dataclasses import replace

    # Managed device (MDM) skips machine-scope tweaks unless --allow-managed
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = replace(sys_b.detect_environment(reg), mdm_enrolled=True)
    owner_prof = load_profile("owner")
    plan_default = apply_profile(owner_prof, env, reg, sys_b, state_store, dry_run=True, allow_managed=False)
    assert "hardening.disable_smbv1" in plan_default.skipped_managed_ids

    plan_override = apply_profile(owner_prof, env, reg, sys_b, state_store, dry_run=True, allow_managed=True)
    assert "hardening.disable_smbv1" not in plan_override.skipped_managed_ids

    # corp-safe never writes HKLM or Policies keys
    corp_prof = load_profile("corp-safe")
    for tid, enabled in corp_prof.tweaks.items():
        if enabled:
            tw = get_tweak(tid)
            assert not tw.requires_admin
            assert all("\\Policies\\" not in r.key_path for r in tw.registry_specs)
