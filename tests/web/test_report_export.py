from datetime import datetime
from pathlib import Path

import pytest

from vulnclaw.agent.context import SessionState
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.report.generator import generate_report


@pytest.mark.parametrize('custom_path', [False, True])
@pytest.mark.parametrize('report_format,suffix', [('markdown', '.md'), ('html', '.html')])
async def test_web_exports_keep_artifacts_and_allow_repeated_exports(
    tmp_path, monkeypatch, custom_path, report_format, suffix,
):
    import vulnclaw.web.services.report_service as service

    config = VulnClawConfig()
    monkeypatch.setattr(service, 'SESSIONS_DIR', tmp_path)
    monkeypatch.setattr(service, 'load_config', lambda: config)
    monkeypatch.setattr(service, 'load_target_state', lambda target: {'target': target})

    class FixedClock:
        @staticmethod
        def now():
            return datetime(2026, 10, 14, 12, 0, 0)

    monkeypatch.setattr(service, 'datetime', FixedClock)

    async def render(target, *, report_format, output_path, config):
        return await generate_report(
            SessionState(target=target), output_path, report_format=report_format,
            llm_attack_summary='No candidates',
        )

    monkeypatch.setattr(service, 'generate_report_for_target', render)
    first = await service.generate_target_report(
        'https://lab.test', str(tmp_path / ('custom' + suffix)) if custom_path else None, report_format,
    )
    if custom_path:
        artifacts = Path(first).parent / 'custom.artifacts' / 'findings'
        assert (artifacts / 'findings.json').exists()
        assert (artifacts / 'findings.sarif').exists()
        original = Path(first).read_bytes()
        with pytest.raises(FileExistsError):
            await service.generate_target_report('https://lab.test', first, report_format)
        assert Path(first).read_bytes() == original
    else:
        second = await service.generate_target_report('https://lab.test', report_format=report_format)
        assert first != second
