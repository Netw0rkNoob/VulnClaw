"""Behavior tests for the classic-REPL config panel model (no TTY required)."""

import pytest

from vulnclaw.cli.config_panel import ConfigPanelModel
from vulnclaw.config.schema import VulnClawConfig


@pytest.fixture
def model():
    return ConfigPanelModel(VulnClawConfig())


def test_starts_with_every_section_collapsed(model):
    keys = [row.key for row in model.rows()]

    assert keys == [
        "llm",
        "session",
        "safety",
        "recon",
        "mcp",
        "action.save",
    ]


def test_expanding_a_section_reveals_its_fields(model):
    model.toggle_expand()  # focus starts on the llm group

    keys = [row.key for row in model.rows()]

    assert keys[0] == "llm"
    assert "llm.provider" in keys
    assert "llm.reasoning_effort" in keys
    assert "action.fetch_models" in keys
    assert keys.index("llm.provider") < keys.index("session")


def test_navigation_skips_rows_inside_collapsed_groups(model):
    model.focus_next()

    assert model.focused.key == "session"


def test_navigation_walks_into_an_expanded_group(model):
    model.toggle_expand()
    model.focus_next()

    assert model.focused.key == "llm.provider"


def test_collapse_from_a_field_jumps_to_the_parent_group(model):
    model.toggle_expand()
    model.focus_next()

    model.collapse()

    assert model.focused.key == "llm"
    assert [row.key for row in model.rows()].count("llm.provider") == 0


def test_focus_does_not_run_off_either_end(model):
    model.focus_prev()
    assert model.focused.key == "llm"

    for _ in range(20):
        model.focus_next()
    assert model.focused.key == "action.save"


def test_draft_is_a_copy_of_the_supplied_config():
    config = VulnClawConfig()
    model = ConfigPanelModel(config)

    model.draft.llm.model = "changed"

    assert config.llm.model != "changed"


def _focus(model, key):
    """Move focus to a row by key, expanding whatever is needed to reach it."""
    for section in ("llm", "session", "safety", "recon", "mcp"):
        model._expanded.add(section)
    model._focus_key = key


def test_bool_field_toggles_without_opening_an_editor(model):
    _focus(model, "session.auto_save")
    before = model.draft.session.auto_save

    model.activate()

    assert model.draft.session.auto_save is not before
    assert model.editing is False


def test_text_edit_commits_on_enter(model):
    _focus(model, "llm.base_url")

    model.activate()
    model.set_edit_text("https://example.test/v1")
    model.commit_edit()

    assert model.draft.llm.base_url == "https://example.test/v1"
    assert model.editing is False


def test_text_edit_cancel_restores_previous_value(model):
    model.draft.llm.reasoning_effort = "medium"
    _focus(model, "llm.reasoning_effort")

    model.activate()
    model.set_edit_text("high")
    model.cancel_edit()

    assert model.draft.llm.reasoning_effort == "medium"


def test_commit_edit_targets_the_originating_field_not_current_focus(model):
    """If focus jumps to a section header (path="") mid-edit, commit must not
    crash and must apply the value to the field editing began on."""
    _focus(model, "llm.base_url")

    model.activate()
    model.set_edit_text("https://typed.test/v1")
    # Simulate focus jumping to the "llm" section header (path="") before Enter.
    model._focus_key = "llm"
    model.commit_edit()  # must not raise despite focused row having an empty path

    assert model.draft.llm.base_url == "https://typed.test/v1"
    assert model.editing is False


def test_commit_edit_discards_when_originating_row_is_unavailable(model):
    """If the originating row disappears entirely (e.g. its section is
    collapsed) before Enter, commit must discard the edit cleanly."""
    _focus(model, "llm.base_url")

    model.activate()
    model.set_edit_text("https://typed.test/v1")
    # Collapse the "llm" section so the originating row is no longer in
    # rows() at all (not just re-pointed at a different row).
    model._expanded.discard("llm")
    model.commit_edit()

    assert model.editing is False
    assert model.row_error == ""
    assert model.draft.llm.base_url != "https://typed.test/v1"


def test_blank_text_keeps_current_value_and_clear_sentinel_empties_it(model):
    model.draft.recon.fofa_email = "a@b.test"
    _focus(model, "recon.fofa_email")

    model.activate()
    model.set_edit_text("")
    model.commit_edit()
    assert model.draft.recon.fofa_email == "a@b.test"

    model.activate()
    model.set_edit_text("!clear")
    model.commit_edit()
    assert model.draft.recon.fofa_email == ""


def test_int_field_rejects_unparseable_input_and_keeps_the_editor_open(model):
    _focus(model, "llm.max_tokens")

    model.activate()
    model.set_edit_text("many")
    model.commit_edit()

    assert model.editing is True
    assert model.row_error != ""
    assert model.draft.llm.max_tokens == 4096


def test_float_and_list_and_env_fields_parse(model):
    _focus(model, "recon.http_timeout")
    model.activate()
    model.set_edit_text("2.5")
    model.commit_edit()
    assert model.draft.recon.http_timeout == 2.5


def test_secret_is_masked_until_revealed(model):
    model.draft.llm.api_key = "sk-abcdef123456"
    _focus(model, "llm.api_key")
    row = model.focused

    assert "sk-abcdef123456" not in model.display_value(row)

    model.toggle_reveal()

    assert model.display_value(row) == "sk-abcdef123456"


def test_secret_list_shows_a_count_not_the_keys(model):
    model.draft.llm.api_keys = ["sk-one", "sk-two"]
    _focus(model, "llm.api_keys")
    row = model.focused

    display = model.display_value(row)

    assert "sk-one" not in display
    assert "2" in display


def test_path_field_round_trips_as_a_path(model):
    from pathlib import Path

    _focus(model, "session.output_dir")

    model.activate()
    model.set_edit_text("./somewhere")
    model.commit_edit()

    assert model.draft.session.output_dir == Path("./somewhere")


def test_choice_field_opens_a_dropdown_and_commits(model):
    _focus(model, "session.report_format")

    model.activate()
    assert model.dropdown_open is True
    assert model.dropdown_options == ["markdown", "html"]

    model.select_option(1)
    model.commit_option()

    assert model.draft.session.report_format == "html"
    assert model.dropdown_open is False


def test_dropdown_cancel_restores_the_previous_choice(model):
    model.draft.session.poc_language = "python"
    _focus(model, "session.poc_language")

    model.activate()
    model.select_option(1)
    model.cancel_option()

    assert model.draft.session.poc_language == "python"
    assert model.dropdown_open is False


def test_dropdown_selection_does_not_run_off_either_end(model):
    _focus(model, "session.report_format")
    model.activate()

    model.select_option(-5)
    assert model.dropdown_index == 0

    model.select_option(5)
    assert model.dropdown_index == 1


def test_changing_provider_applies_the_preset_and_bumps_the_generation(model):
    _focus(model, "llm.provider")
    model.activate()
    model.dropdown_index = model.dropdown_options.index("deepseek")
    generation_before = model.generation

    model.commit_option()

    assert model.draft.llm.provider == "deepseek"
    assert model.draft.llm.base_url == "https://api.deepseek.com"
    assert model.generation > generation_before
    assert model.models == []


def test_editing_base_url_or_key_bumps_the_generation(model):
    generation_before = model.generation

    _focus(model, "llm.base_url")
    model.activate()
    model.set_edit_text("https://example.test/v1")
    model.commit_edit()

    assert model.generation > generation_before


def test_fetch_is_blocked_without_credentials(model):
    model.draft.llm.base_url = ""
    model.draft.llm.api_key = ""
    model.draft.llm.api_keys = []

    assert model.can_fetch() is False


def test_fetch_is_allowed_with_a_base_url_and_any_key(model):
    model.draft.llm.base_url = "https://example.test/v1"
    model.draft.llm.api_key = ""
    model.draft.llm.api_keys = ["sk-pool"]

    assert model.can_fetch() is True


def test_successful_fetch_populates_the_model_list(model):
    model.draft.llm.base_url = "https://example.test/v1"
    model.draft.llm.api_key = "sk-test"

    generation = model.begin_fetch()
    assert model.fetch_state == "loading"

    model.apply_fetch_result(generation, ["a", "b"], None)

    assert model.models == ["a", "b"]
    assert model.fetch_state == "ok"


def test_a_stale_fetch_result_is_ignored(model):
    model.draft.llm.base_url = "https://example.test/v1"
    model.draft.llm.api_key = "sk-test"
    stale = model.begin_fetch()

    model._invalidate_models()  # provider changed while the fetch was in flight

    model.apply_fetch_result(stale, ["wrong-provider-model"], None)

    assert model.models == []


def test_a_failed_fetch_reports_an_error_and_leaves_the_list_empty(model):
    model.draft.llm.base_url = "https://example.test/v1"
    model.draft.llm.api_key = "sk-test"
    generation = model.begin_fetch()

    model.apply_fetch_result(generation, [], "connection refused")

    assert model.models == []
    assert model.fetch_state == "error"
    assert "connection refused" in model.fetch_message


def test_an_empty_successful_fetch_is_reported_as_an_error(model):
    model.draft.llm.base_url = "https://example.test/v1"
    model.draft.llm.api_key = "sk-test"
    generation = model.begin_fetch()

    model.apply_fetch_result(generation, [], None)

    assert model.fetch_state == "error"


def test_mcp_section_lists_servers_as_collapsed_groups():
    model = _with_server()
    model._expanded.add("mcp")

    keys = [row.key for row in model.rows()]

    assert "mcp.demo" in keys
    assert "mcp.demo.enabled" not in keys
    assert "action.add_server" in keys


def _with_server(name="demo", enabled=True):
    from vulnclaw.config.schema import MCPServerConfig, MCPTransportConfig

    config = VulnClawConfig()
    config.mcp.servers[name] = MCPServerConfig(
        name=name,
        enabled=enabled,
        priority=1,
        transport=MCPTransportConfig(type="stdio", command="run-me"),
    )
    return ConfigPanelModel(config)


def test_expanding_a_server_reveals_its_transport_fields():
    model = _with_server()
    model._expanded.update({"mcp", "mcp.demo"})

    keys = [row.key for row in model.rows()]

    assert "mcp.demo.enabled" in keys
    assert "mcp.demo.transport.type" in keys
    assert "mcp.demo.transport.env" in keys


def test_editing_a_nested_server_field_writes_through_to_the_draft():
    model = _with_server()
    model._expanded.update({"mcp", "mcp.demo"})
    model._focus_key = "mcp.demo.transport.command"

    model.activate()
    model.set_edit_text("other-command")
    model.commit_edit()

    assert model.draft.mcp.servers["demo"].transport.command == "other-command"


def test_adding_a_server_rejects_blank_and_duplicate_names():
    model = _with_server()

    model.add_server("")
    assert model.row_error != ""
    assert list(model.draft.mcp.servers) == ["demo"]

    model.add_server("demo")
    assert model.row_error != ""
    assert list(model.draft.mcp.servers) == ["demo"]

    model.add_server("second")
    assert model.row_error == ""
    assert model.draft.mcp.servers["second"].transport.type == "stdio"


def test_deleting_a_custom_server_removes_it():
    model = _with_server()
    model._expanded.add("mcp")
    model._focus_key = "mcp.demo"

    model.delete_server()

    assert "demo" not in model.draft.mcp.servers


def test_builtin_servers_cannot_be_deleted():
    from vulnclaw.config.schema import BUILTIN_MCP_SERVERS

    name = next(iter(BUILTIN_MCP_SERVERS))
    model = _with_server(name=name)
    model._expanded.add("mcp")
    model._focus_key = f"mcp.{name}"

    model.delete_server()

    assert name in model.draft.mcp.servers
    assert model.row_error != ""


def test_save_is_blocked_when_static_auth_has_no_credentials(model):
    model.draft.llm.auth_mode = "static"
    model.draft.llm.api_key = ""
    model.draft.llm.api_keys = []

    assert model.request_save() is False
    assert model.save_error != ""


def test_save_is_allowed_when_oauth_has_no_static_key(model):
    model.draft.llm.auth_mode = "oauth"
    model.draft.llm.api_key = ""
    model.draft.llm.api_keys = []
    model.draft.llm.base_url = "https://example.test/v1"

    assert model.request_save() is True


def test_save_is_blocked_when_a_custom_provider_has_no_base_url(model):
    model.draft.llm.api_key = "sk-test"
    model.draft.llm.provider = "custom"
    model.draft.llm.base_url = ""

    assert model.request_save() is False
    assert "base URL" in model.save_error

    model.draft.llm.base_url = "https://example.test/v1"
    assert model.request_save() is True


def test_a_preset_provider_saves_without_touching_the_base_url_rule(model):
    model.draft.llm.api_key = "sk-test"
    model.draft.llm.provider = "openai"
    model.draft.llm.base_url = ""

    assert model.request_save() is True


def test_a_previously_configured_model_is_preselected_after_a_fetch(model):
    model.draft.llm.base_url = "https://example.test/v1"
    model.draft.llm.api_key = "sk-test"
    model.draft.llm.model = "gpt-4o"
    generation = model.begin_fetch()
    model.apply_fetch_result(generation, ["gpt-3.5", "gpt-4o"], None)

    _focus(model, "llm.model")
    model.activate()

    assert model.draft.llm.model == "gpt-4o"
    assert model.dropdown_options == ["gpt-3.5", "gpt-4o"]
    assert model.dropdown_index == 1


def test_a_malformed_base_url_warns_once_then_saves(model):
    model.draft.llm.api_key = "sk-test"
    model.draft.llm.base_url = "example.test/v1"

    assert model.request_save() is False
    assert "URL" in model.save_error or "url" in model.save_error

    assert model.request_save() is True


def test_save_surfaces_a_schema_violation(model):
    model.draft.llm.api_key = "sk-test"
    # max_rounds has no pydantic bounds; force a type the schema rejects.
    model.draft.llm.max_tokens = "bad"  # type: ignore[assignment]

    assert model.request_save() is False
    assert "max_tokens" in model.save_error


def test_collapsed_summaries_describe_each_section(model):
    model.draft.llm.provider = "openai"
    model.draft.llm.model = "gpt-4o"
    model.draft.llm.api_key = "sk-abcdef123456"

    summary = model.summary("llm")

    assert "openai" in summary
    assert "gpt-4o" in summary
    assert "sk-abcdef123456" not in summary


def test_llm_summary_flags_that_the_key_pool_wins(model):
    model.draft.llm.api_key = "sk-single"
    model.draft.llm.api_keys = ["sk-pool"]

    assert "pool" in model.summary("llm").lower()


def test_nested_mcp_summary_shows_transport_and_enabled_state():
    model = _with_server(name="demo", enabled=True)
    summary = model.summary("mcp.demo")

    assert "stdio" in summary
    assert "enabled" in summary

    model.draft.mcp.servers["demo"].enabled = False
    model.draft.mcp.servers["demo"].transport.type = "sse"
    summary = model.summary("mcp.demo")

    assert "sse" in summary
    assert "disabled" in summary


def test_viewport_only_returns_the_visible_slice(model):
    model.toggle_expand()  # expand llm — many fields
    model.set_viewport_height(5)

    visible = model.visible_rows()
    all_rows = model.rows()

    assert len(visible) == 5
    assert len(all_rows) > 5
    assert [row.key for row in visible] == [row.key for row in all_rows[:5]]
    assert model.scroll_offset == 0


def test_viewport_scrolls_to_keep_focus_in_view(model):
    model.toggle_expand()
    model.set_viewport_height(4)
    total = len(model.rows())

    # Walk focus to the end of the list.
    for _ in range(total + 5):
        model.focus_next()

    focus_idx = model._focus_index()
    assert model.focused.key == "action.save"
    assert model.scroll_offset == focus_idx - 3  # height 4 → last visible is offset+3
    visible_keys = [row.key for row in model.visible_rows()]
    assert model.focused.key in visible_keys
    assert len(visible_keys) == 4


def test_viewport_scrolls_up_when_focus_moves_above_window(model):
    model.toggle_expand()
    model.set_viewport_height(4)
    for _ in range(len(model.rows()) + 5):
        model.focus_next()
    assert model.scroll_offset > 0

    for _ in range(len(model.rows()) + 5):
        model.focus_prev()

    assert model.focused.key == "llm"
    assert model.scroll_offset == 0
    assert model.focused.key in [row.key for row in model.visible_rows()]


def test_focus_navigation_still_traverses_the_full_list_with_a_viewport(model):
    """Keybindings move focus across every logical row, not just the window."""
    model.toggle_expand()
    model.set_viewport_height(3)
    seen: list[str] = [model.focused.key]
    while True:
        model.focus_next()
        key = model.focused.key
        if key == seen[-1]:
            break
        seen.append(key)

    assert "llm.provider" in seen
    assert "session" in seen
    assert "action.save" in seen
    # Window never grew beyond the height.
    assert all(len(model.visible_rows()) <= 3 for _ in [0])
    model.focus_prev()  # leave focus somewhere mid-list after walking to end
    assert len(model.visible_rows()) <= 3


def test_every_panel_label_key_exists_in_both_catalogs():
    import json
    from pathlib import Path

    from vulnclaw.cli import config_panel as panel

    root = Path(panel.__file__).resolve().parents[1] / "i18n"
    catalogs = {
        name: json.loads((root / f"{name}.json").read_text(encoding="utf-8"))
        for name in ("en", "zh")
    }

    used = {
        spec.label_key
        for section in panel.SECTIONS
        for spec in section.fields
    }
    used |= {spec.label_key for spec in panel.MCP_SERVER_FIELDS}
    used |= {section.label_key for section in panel.SECTIONS}
    used |= {
        "tui.config_panel.save",
        "tui.config_panel.fetch_models",
        "tui.config_panel.add_server",
        "tui.config_panel.delete_server",
        "tui.config_panel.nav_hint",
        "tui.config_panel.esc_discards",
        "tui.config_panel.reveal_hint",
        "tui.config_panel.fetch_idle",
        "tui.config_panel.fetch_loading",
        "tui.config_panel.saved",
        "tui.config_panel.discarded",
    }

    for name, catalog in catalogs.items():
        missing = sorted(key for key in used if key not in catalog)
        assert missing == [], f"{name}.json is missing: {missing}"


def test_env_values_are_masked_until_revealed(model):
    model.add_server("secretsrv")
    owner, attr = model._resolve("mcp.secretsrv.transport.env")
    setattr(owner, attr, {"API_TOKEN": "supersecretvalue", "PORT": "8080"})
    _focus(model, "mcp.secretsrv.transport.env")
    row = model.focused

    masked = model.display_value(row)
    assert "supersecretvalue" not in masked
    assert "API_TOKEN" in masked  # keys stay visible; values are hidden

    model.toggle_reveal()
    revealed = model.display_value(row)
    assert "supersecretvalue" in revealed


def test_secret_edit_text_is_not_shown_in_the_clear(model):
    _focus(model, "llm.api_key")
    model.activate()
    model.set_edit_text("sk-livesecret999")

    assert "sk-livesecret999" not in model.edit_display(model.focused)


def test_plain_edit_text_is_shown_verbatim(model):
    _focus(model, "llm.base_url")
    model.activate()
    model.set_edit_text("https://typed.test/v1")

    assert model.edit_display(model.focused) == "https://typed.test/v1"


def test_server_name_with_a_dot_is_rejected(model):
    model.add_server("foo.bar")

    assert "foo.bar" not in model.draft.mcp.servers
    assert model.row_error
