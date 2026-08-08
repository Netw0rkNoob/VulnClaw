"""Internationalization support for VulnClaw."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional


class I18nLoader:
    """Load and manage translations."""

    def __init__(self, lang: str = "zh") -> None:
        self.lang = lang
        self.translations: dict[str, str] = {}
        self.logger = logging.getLogger(__name__)
        self._load_translations()

    def _get_lang_dir(self) -> str:
        """Get the directory containing language files."""
        return os.path.join(os.path.dirname(__file__))

    def _load_translations(self) -> None:
        """Load translations from JSON file."""
        lang_file = os.path.join(self._get_lang_dir(), f"{self.lang}.json")
        fallback_file = os.path.join(self._get_lang_dir(), "en.json")

        try:
            with open(lang_file, "r", encoding="utf-8") as f:
                self.translations = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            try:
                with open(fallback_file, "r", encoding="utf-8") as f:
                    self.translations = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError) as e:
                self.logger.warning(
                    "Failed to load fallback translation file '%s': %s. "
                    "Translations will be empty.",
                    fallback_file, type(e).__name__,
                )
                self.translations = {}

    def t(self, key: str, **kwargs: Any) -> str:
        """Translate a key to current language.

        Args:
            key: Translation key
            **kwargs: Placeholder values for template strings

        Returns:
            Translated string with placeholders replaced
        """
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except KeyError:
                pass
        return text

    @staticmethod
    def detect_language() -> str:
        """Detect language from environment or config.

        Priority:
        1. VULNCLAW_LANG environment variable
        2. LANG environment variable
        3. Default to 'zh'
        """
        # Check VulnClaw specific env var
        lang_env = os.environ.get("VULNCLAW_LANG", "").lower()
        if lang_env in ("zh", "en"):
            return lang_env

        # Check system LANG
        system_lang = os.environ.get("LANG", "").lower()
        if system_lang.startswith("zh"):
            return "zh"
        elif system_lang.startswith("en"):
            return "en"

        # Default to English when no environment signal is present so new
        # users do not land in a language they cannot read.
        return "en"


# Global translator instance
_translator: Optional[I18nLoader] = None


def init_i18n(lang: Optional[str] = None, config: Any = None) -> I18nLoader:
    """Initialize the global translator.

    Args:
        lang: Explicit language override (zh/en)
        config: VulnClaw config object with session.language setting
    """
    global _translator
    if lang is None:
        # Try config first
        if config is not None and hasattr(config, "session"):
            session_lang = getattr(config.session, "language", "auto")
            if session_lang and session_lang != "auto":
                lang = session_lang
        # Fall back to auto-detection
        if lang is None or lang == "auto":
            lang = I18nLoader.detect_language()
    _translator = I18nLoader(lang)
    return _translator


def _(key: str, **kwargs: Any) -> str:
    """Translate a key using the global translator."""
    if _translator is None:
        init_i18n()
    return _translator.t(key, **kwargs)


def current_lang() -> str:
    """Return the active UI language code ('zh' or 'en').

    Initializes the global translator via auto-detection if it has not been
    set up yet, so callers outside the CLI (report generation, prompt
    assembly) get a sensible language without an explicit init.
    """
    if _translator is None:
        init_i18n()
    return _translator.lang

