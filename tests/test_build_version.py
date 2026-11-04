"""The build label: what an operator quotes, and what a deploy is judged by."""

from __future__ import annotations

from app.api.v1.routers.system_info import build_label


def test_label_carries_release_and_build():
    assert build_label("0.2.0", "131113cf9a8b7c6d") == "0.2.0+131113cf"


def test_label_changes_when_the_commit_changes():
    """Two builds of the same release must not look identical."""
    first = build_label("0.2.0", "aaaaaaaa1111")
    second = build_label("0.2.0", "bbbbbbbb2222")

    assert first != second
    assert first.startswith("0.2.0+")
    assert second.startswith("0.2.0+")


def test_unversioned_build_says_so():
    """A hand-built image has no provenance; it must not imply one."""
    assert build_label("0.2.0", "") == "0.2.0 (unversioned build)"


def test_release_number_survives_an_unstamped_build():
    """A hand-built image still knows its release, even with no commit baked in."""
    from app import __version__

    assert __version__.count(".") == 2
    assert build_label(__version__, "") == f"{__version__} (unversioned build)"


def test_stamped_build_prefers_the_baked_version(monkeypatch):
    from app.api.v1.routers import system_info

    monkeypatch.setattr(system_info, "_BUILD_VERSION", "9.9.9")
    assert system_info.running_version() == "9.9.9"


def test_unstamped_build_falls_back_to_the_code_constant(monkeypatch):
    from app import __version__
    from app.api.v1.routers import system_info

    monkeypatch.setattr(system_info, "_BUILD_VERSION", "")
    assert system_info.running_version() == __version__
