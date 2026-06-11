from __future__ import annotations


def test_verify_dist_artifacts_accepts_matching_version(tmp_path) -> None:
    from scripts.verify_dist_artifacts import verify_dist_artifacts

    wheel = tmp_path / "vulnclaw-0.3.0-py3-none-any.whl"
    sdist = tmp_path / "vulnclaw-0.3.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")

    artifacts = verify_dist_artifacts(tmp_path, version="0.3.0")
    names = {path.name for path in artifacts}
    assert wheel.name in names
    assert sdist.name in names


def test_verify_dist_artifacts_rejects_missing_files(tmp_path) -> None:
    from scripts.verify_dist_artifacts import verify_dist_artifacts

    (tmp_path / "vulnclaw-0.3.0-py3-none-any.whl").write_bytes(b"wheel")

    try:
        verify_dist_artifacts(tmp_path, version="0.3.0")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError for missing sdist artifact")


def test_verify_dist_artifacts_rejects_empty_files(tmp_path) -> None:
    from scripts.verify_dist_artifacts import verify_dist_artifacts

    (tmp_path / "vulnclaw-0.3.0-py3-none-any.whl").write_bytes(b"")
    (tmp_path / "vulnclaw-0.3.0.tar.gz").write_bytes(b"sdist")

    try:
        verify_dist_artifacts(tmp_path, version="0.3.0")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for empty dist artifact")
