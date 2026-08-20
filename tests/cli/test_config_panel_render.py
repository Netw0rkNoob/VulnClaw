"""Snapshot tests for the config panel renderer."""

import io

from rich.console import Console

from vulnclaw.cli.config_panel import ConfigPanelModel
from vulnclaw.cli.config_panel_render import render_panel
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.i18n import init_i18n


def _render(model):
    init_i18n("en")
    console = Console(
        file=io.StringIO(),
        record=True,
        width=120,
        height=40,
        force_terminal=True,
        color_system=None,
    )
    console.print(render_panel(model))
    return console.export_text(styles=False)


def test_collapsed_view_shows_one_line_per_section():
    config = VulnClawConfig()
    config.llm.provider = "openai"
    config.llm.model = "gpt-4o"
    model = ConfigPanelModel(config)

    output = _render(model)

    assert "LLM" in output
    assert "openai" in output
    assert "Session" in output
    assert "Base URL" not in output


def test_expanded_view_shows_fields_and_masks_the_key():
    config = VulnClawConfig()
    config.llm.api_key = "sk-abcdef123456"
    model = ConfigPanelModel(config)
    model.toggle_expand()

    output = _render(model)

    assert "Base URL" in output
    assert "sk-abcdef123456" not in output


def test_open_dropdown_lists_its_options():
    model = ConfigPanelModel(VulnClawConfig())
    model._expanded.add("session")
    model._focus_key = "session.report_format"
    model.activate()

    output = _render(model)

    assert "markdown" in output
    assert "html" in output


def test_expanded_llm_section_shows_the_idle_fetch_hint():
    model = ConfigPanelModel(VulnClawConfig())
    model.toggle_expand()  # focus starts on the llm group

    output = _render(model)

    assert "Press Fetch to load models" in output


def test_the_idle_hint_gives_way_to_the_fetch_outcome():
    model = ConfigPanelModel(VulnClawConfig())
    model.toggle_expand()
    generation = model.begin_fetch()
    model.apply_fetch_result(generation, ["a", "b"], None)

    output = _render(model)

    assert "Press Fetch to load models" not in output
    assert "2 models loaded." in output


def test_errors_render_inside_the_panel():
    model = ConfigPanelModel(VulnClawConfig())
    model.draft.llm.auth_mode = "static"
    model.draft.llm.api_key = ""
    model.draft.llm.api_keys = []
    model.request_save()

    output = _render(model)

    assert "API key" in output


def test_collapsed_mcp_server_shows_transport_and_enabled_summary():
    from vulnclaw.config.schema import MCPServerConfig, MCPTransportConfig

    config = VulnClawConfig()
    config.mcp.servers["demo"] = MCPServerConfig(
        name="demo",
        enabled=True,
        priority=1,
        transport=MCPTransportConfig(type="stdio", command="run-me"),
    )
    model = ConfigPanelModel(config)
    model._expanded.add("mcp")

    output = _render(model)

    assert "demo" in output
    assert "stdio" in output
    assert "enabled" in output
    # Nested fields stay hidden while the server group is collapsed.
    assert "Priority" not in output


def test_viewport_render_omits_rows_outside_the_window():
    model = ConfigPanelModel(VulnClawConfig())
    model.toggle_expand()  # expand llm
    model.set_viewport_height(4)
    # Leave focus near the top so only the first four logical rows are painted.
    model._focus_key = "llm"

    output = _render(model)

    assert "LLM" in output
    assert "Provider" in output
    # "Save" is the last logical row and should be scrolled out of view.
    assert "Save" not in output
    assert "Session" not in output
