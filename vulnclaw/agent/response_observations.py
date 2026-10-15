"""Conversational observations and assumptions, separate from finding intake."""

from __future__ import annotations

import re

from vulnclaw.agent.think_filter import strip_think_tags


class ResponseObservationParser:
    def __init__(self, context, runtime) -> None:
        self.context = context
        self.runtime = runtime

    def parse(self, response: str) -> None:
        response = strip_think_tags(response)
        for pattern in (
            r"\[\+\]\s*(.+?)(?:\n|$)", r"发现[：: ]\s*(.+?)(?:\n|$)",
            r"(flag\{[^}]+\})", r"(NSSCTF\{[^}]+\})", r"(CTF\{[^}]+\})",
        ):
            for match in re.findall(pattern, response, re.IGNORECASE):
                note = match.strip()[:200]
                if note and note not in self.context.state.notes:
                    self.context.state.add_note(note)
        for pattern in (r"已确认[：: ]\s*(.+?)(?:\n|$)", r"确认[：: ]\s*(.+?)(?:\n|$)"):
            for match in re.findall(pattern, response, re.IGNORECASE):
                self.context.state.add_confirmed_fact(match.strip()[:200])
        for pattern in (r"假设[：: ]\s*(.+?)(?:\n|$)", r"推测[：: ]\s*(.+?)(?:\n|$)"):
            for match in re.findall(pattern, response, re.IGNORECASE):
                assumption = match.strip()[:200]
                if assumption and assumption not in self.runtime.unverified_assumptions:
                    self.runtime.unverified_assumptions.append(assumption)
