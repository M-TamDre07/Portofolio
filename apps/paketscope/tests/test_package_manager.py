import pytest

from paketscope import __version__

from paketscope.commands import CommandResult
from paketscope.package_manager import (
    PackageOperationError,
    apply_apt_action,
    preview_apt_action,
    search_apt_packages,
    validate_apt_package_name,
)


def result(argv, stdout="", stderr="", returncode=0):
    return CommandResult(tuple(argv), returncode, stdout, stderr)


@pytest.mark.parametrize("name", ["firefox", "libfoo2", "libfoo:amd64", "python3-pyside6.qtwidgets"])
def test_valid_apt_package_names(name):
    assert validate_apt_package_name(name) == name


@pytest.mark.parametrize("name", ["", "-o", "hello;rm", "hello world", "../pkg", "pkg\nname", "--remove-essential"])
def test_invalid_apt_package_names_are_rejected(name):
    with pytest.raises(PackageOperationError):
        validate_apt_package_name(name)


def test_search_uses_local_apt_index_and_parses_results(monkeypatch):
    calls = []

    def fake_run(argv, timeout):
        calls.append((argv, timeout))
        return result(argv, "firefox - Mozilla Firefox web browser\nfirefox-esr - Extended Support Release\nnot a package line\n")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    found = search_apt_packages("firefox")

    assert [item.name for item in found] == ["firefox", "firefox-esr"]
    assert found[0].description == "Mozilla Firefox web browser"
    assert calls[0][0][:3] == ["apt-cache", "search", "--names-only"]


def test_search_rejects_option_like_query_before_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        pytest.fail("run_command must not be reached")

    monkeypatch.setattr("paketscope.package_manager.run_command", fail_if_called)
    with pytest.raises(PackageOperationError):
        search_apt_packages("--important")


def test_install_preview_blocks_removal_and_requires_requested_package(monkeypatch):
    def fake_run(argv, timeout):
        assert "install" in argv
        assert "--simulate" in argv
        assert "--no-remove" in argv
        return result(argv, "Inst firefox (1.0 repo [amd64])\n")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    plan = preview_apt_action("install", "firefox")
    assert plan.install == ("firefox",)
    assert plan.remove == ()


def test_install_preview_matches_architecture_qualified_name(monkeypatch):
    def fake_run(argv, timeout):
        return result(argv, "Inst firefox:amd64 (1.0 repo [amd64])\n")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    plan = preview_apt_action("install", "firefox")
    assert plan.install == ("firefox:amd64",)


def test_install_preview_refuses_remove_side_effects(monkeypatch):
    def fake_run(argv, timeout):
        return result(argv, "Inst firefox (1.0 repo [amd64])\nRemv unrelated-package [1.0]\n")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    with pytest.raises(PackageOperationError, match="menghapus paket lain"):
        preview_apt_action("install", "firefox")


def test_purge_preview_recognizes_purg_records(monkeypatch):
    def fake_run(argv, timeout):
        assert "purge" in argv
        return result(argv, "Purg sample-app [1.0]\n")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    plan = preview_apt_action("purge", "sample-app")
    assert plan.purge == ("sample-app",)


def test_preview_rejects_unknown_action_before_running_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        pytest.fail("run_command must not be reached")

    monkeypatch.setattr("paketscope.package_manager.run_command", fail_if_called)
    with pytest.raises(PackageOperationError, match="tidak didukung"):
        preview_apt_action("upgrade", "firefox")


def test_preview_rejects_failed_apt_simulation(monkeypatch):
    def fake_run(argv, timeout):
        return result(argv, stderr="E: Unable to locate package missing-app", returncode=100)

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    with pytest.raises(PackageOperationError, match="menyiapkan simulasi"):
        preview_apt_action("install", "missing-app")


def test_remove_preview_requires_the_requested_package(monkeypatch):
    def fake_run(argv, timeout):
        assert "remove" in argv
        return result(argv, "Remv different-package [1.0]\n")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    with pytest.raises(PackageOperationError, match="tidak merencanakan penghapusan"):
        preview_apt_action("remove", "firefox")


def test_mutation_uses_pkexec_and_never_a_shell(monkeypatch):
    seen = {}

    def fake_run(argv, timeout):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return result(argv, "done")

    monkeypatch.setattr("paketscope.package_manager.run_command", fake_run)
    apply_apt_action("install", "firefox")

    assert seen["argv"][0] == "pkexec"
    assert seen["argv"][1] == "/usr/bin/env"
    assert "/usr/bin/apt-get" in seen["argv"]
    assert "--no-remove" in seen["argv"]
    assert seen["timeout"] == 900.0
    assert not any("shell" in part.lower() for part in seen["argv"])


def test_apply_rejects_invalid_package_before_running_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        pytest.fail("run_command must not be reached")

    monkeypatch.setattr("paketscope.package_manager.run_command", fail_if_called)
    with pytest.raises(PackageOperationError, match="tidak valid"):
        apply_apt_action("install", "firefox; touch /tmp/not-allowed")


def test_app_version_matches_development_package_version():
    assert __version__ == "3.0.0.dev3"
