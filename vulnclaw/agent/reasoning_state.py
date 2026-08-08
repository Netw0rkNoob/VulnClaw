from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from vulnclaw.i18n import _


class ConstraintCategory(str, Enum):
    WAF = "waf"
    AUTH = "auth"
    FILTER = "filter"
    SANDBOX = "sandbox"
    NETWORK = "network"
    RATE_LIMIT = "rate_limit"
    OTHER = "other"


class ConstraintSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKING = "blocking"


class PathStatus(str, Enum):
    PLANNED = "planned"
    ACTIVE = "active"
    SUCCESS = "success"
    FAILED = "failed"
    ABANDONED = "abandoned"


class StepStatus(str, Enum):
    PLANNED = "planned"
    ACTIVE = "active"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class KnownFact(BaseModel):
    key: str
    value: str
    source: str = ""
    confidence: float = 1.0

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, value: float) -> float:
        return max(0.0, min(1.0, value))


class ReasoningConstraint(BaseModel):
    description: str
    category: ConstraintCategory = ConstraintCategory.OTHER
    severity: ConstraintSeverity = ConstraintSeverity.MEDIUM
    source: str = ""

    @property
    def is_blocking(self) -> bool:
        return self.severity == ConstraintSeverity.BLOCKING


class PathStep(BaseModel):
    action: str
    target: str = ""
    vuln_type: str = ""
    status: StepStatus = StepStatus.PLANNED
    result: str = ""


class AttackPath(BaseModel):
    name: str
    steps: list[PathStep] = Field(default_factory=list)
    priority: int = 0
    status: PathStatus = PathStatus.PLANNED
    result: str = ""
    base_priority: int | None = None

    def effective_base_priority(self) -> int:
        return self.priority if self.base_priority is None else self.base_priority


class ReasoningState(BaseModel):
    facts: list[KnownFact] = Field(default_factory=list)
    constraints: list[ReasoningConstraint] = Field(default_factory=list)
    paths: list[AttackPath] = Field(default_factory=list)
    active_path_index: int = -1

    def add_fact(
        self,
        key: str,
        value: str,
        source: str = "",
        confidence: float = 1.0,
    ) -> KnownFact:
        confidence = max(0.0, min(1.0, confidence))
        for fact in self.facts:
            if fact.key == key and fact.value == value:
                fact.confidence = self._combine_confidence(fact.confidence, confidence)
                if source and source not in self._split_sources(fact.source):
                    fact.source = self._join_sources(fact.source, source)
                return fact

        for fact in self.facts:
            if fact.key == key and fact.value != value:
                fact.confidence = round(max(0.0, fact.confidence * (1.0 - confidence * 0.5)), 4)

        new_fact = KnownFact(key=key, value=value, source=source, confidence=confidence)
        self.facts.append(new_fact)
        return new_fact

    def add_constraint(
        self,
        description: str,
        category: ConstraintCategory | str = ConstraintCategory.OTHER,
        severity: ConstraintSeverity | str = ConstraintSeverity.MEDIUM,
        source: str = "",
    ) -> ReasoningConstraint:
        for constraint in self.constraints:
            if (
                constraint.description == description
                and constraint.category == category
                and constraint.severity == severity
            ):
                if source and source not in self._split_sources(constraint.source):
                    constraint.source = self._join_sources(constraint.source, source)
                return constraint
        constraint = ReasoningConstraint(
            description=description,
            category=category,
            severity=severity,
            source=source,
        )
        self.constraints.append(constraint)
        return constraint

    def get_blocking_constraints(self) -> list[ReasoningConstraint]:
        return [constraint for constraint in self.constraints if constraint.is_blocking]

    def add_path(
        self,
        name: str | AttackPath,
        steps: list[PathStep | dict[str, Any]] | None = None,
        priority: int = 0,
        status: PathStatus | str = PathStatus.PLANNED,
    ) -> AttackPath:
        if isinstance(name, AttackPath):
            path = name
        else:
            path_steps = [step if isinstance(step, PathStep) else PathStep(**step) for step in steps or []]
            path = AttackPath(
                name=name,
                steps=path_steps,
                priority=priority,
                base_priority=priority,
                status=status,
            )
        self.paths.append(path)
        if self.active_path_index < 0 and path.status == PathStatus.ACTIVE:
            self.active_path_index = len(self.paths) - 1
        return path

    def set_active_path(self, path: int | str) -> AttackPath:
        idx = self._path_index(path)
        for current in self.paths:
            if current.status == PathStatus.ACTIVE:
                current.status = PathStatus.PLANNED
        self.paths[idx].status = PathStatus.ACTIVE
        self.active_path_index = idx
        return self.paths[idx]

    def set_path(self, path: int | str) -> AttackPath:
        return self.set_active_path(path)

    def update_path(
        self,
        path: int | str,
        status: PathStatus | str | None = None,
        result: str | None = None,
        priority: int | None = None,
    ) -> AttackPath:
        idx = self._path_index(path)
        item = self.paths[idx]
        if status is not None:
            item.status = PathStatus(status)
        if result is not None:
            item.result = result
        if priority is not None:
            item.priority = priority
            item.base_priority = priority
        if item.status == PathStatus.ACTIVE:
            self.active_path_index = idx
        elif self.active_path_index == idx and item.status != PathStatus.ACTIVE:
            self.active_path_index = -1
        return item

    def update_step(
        self,
        path: int | str,
        step: int,
        status: StepStatus | str,
        result: str = "",
    ) -> PathStep:
        path_item = self.paths[self._path_index(path)]
        step_item = path_item.steps[step]
        step_item.status = StepStatus(status)
        if result:
            step_item.result = result
        if step_item.status == StepStatus.SUCCESS and path_item.steps and all(
            item.status in {StepStatus.SUCCESS, StepStatus.SKIPPED} for item in path_item.steps
        ):
            path_item.status = PathStatus.SUCCESS
        elif step_item.status in {StepStatus.FAILED, StepStatus.BLOCKED}:
            path_item.status = PathStatus.FAILED
        return step_item

    def abandon_path(self, path: int | str, reason: str = "") -> AttackPath:
        idx = self._path_index(path)
        item = self.paths[idx]
        item.status = PathStatus.ABANDONED
        if reason:
            item.result = reason
        if self.active_path_index == idx:
            self.active_path_index = -1
        return item

    def auto_prioritize(self, success_history: dict[str, float] | None = None) -> None:
        history = success_history or {}
        blocking_penalty = len(self.get_blocking_constraints()) * 2
        for path in self.paths:
            base = path.effective_base_priority()
            success_rate = max(0.0, min(1.0, history.get(path.name, 0.0)))
            score = round(base * (1.0 + success_rate))
            if path.status == PathStatus.SUCCESS:
                score += 5
            elif path.status == PathStatus.ACTIVE:
                score += 2
            elif path.status == PathStatus.FAILED:
                score -= 3
            elif path.status == PathStatus.ABANDONED:
                score -= 10
            path.priority = int(score - blocking_penalty)
        active_name = self.paths[self.active_path_index].name if self._has_active_index() else None
        self.paths.sort(key=lambda item: item.priority, reverse=True)
        if active_name is None:
            self.active_path_index = -1
        else:
            self.active_path_index = next(
                (idx for idx, path in enumerate(self.paths) if path.name == active_name),
                -1,
            )

    def to_prompt_block(self, max_facts: int = 8, max_paths: int = 5) -> str:
        if not self.facts and not self.constraints and not self.paths:
            return ""
        lines = [_("agent.reasoning.current")]
        if self.facts:
            lines.append(_("agent.reasoning.facts"))
            for fact in sorted(self.facts, key=lambda item: item.confidence, reverse=True)[:max_facts]:
                source = f", source={fact.source}" if fact.source else ""
                lines.append(f"- {fact.key}={fact.value} (confidence={fact.confidence:.2f}{source})")
        if self.constraints:
            lines.append(_("agent.reasoning.constraints"))
            severity_order = {
                ConstraintSeverity.BLOCKING: 0,
                ConstraintSeverity.HIGH: 1,
                ConstraintSeverity.MEDIUM: 2,
                ConstraintSeverity.LOW: 3,
            }
            ordered_constraints = sorted(
                self.constraints,
                key=lambda item: severity_order[item.severity],
            )
            for constraint in ordered_constraints:
                lines.append(
                    f"- [{constraint.category.value}/{constraint.severity.value}] {constraint.description}"
                )
        if self.paths:
            lines.append(_("agent.reasoning.paths"))
            for idx, path in enumerate(sorted(self.paths, key=lambda item: item.priority, reverse=True)[:max_paths]):
                original_idx = next(
                    (path_idx for path_idx, item in enumerate(self.paths) if item is path),
                    -1,
                )
                marker = "*" if original_idx == self.active_path_index else "-"
                done = sum(1 for step in path.steps if step.status == StepStatus.SUCCESS)
                total = len(path.steps)
                progress = f", steps={done}/{total}" if total else ""
                result = f", result={path.result}" if path.result else ""
                lines.append(
                    f"{marker} {idx + 1}. [{path.status.value}] {path.name} "
                    f"(priority={path.priority}{progress}{result})"
                )
        return "\n".join(lines)

    def get_summary(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for path in self.paths:
            status_counts[path.status.value] = status_counts.get(path.status.value, 0) + 1
        return {
            "facts": len(self.facts),
            "constraints": len(self.constraints),
            "blocking_constraints": len(self.get_blocking_constraints()),
            "paths": len(self.paths),
            "active_path": self.paths[self.active_path_index].name if self._has_active_index() else None,
            "path_status_counts": status_counts,
            "top_facts": [
                {"key": fact.key, "value": fact.value, "confidence": fact.confidence}
                for fact in sorted(self.facts, key=lambda item: item.confidence, reverse=True)[:5]
            ],
            "top_paths": [
                {"name": path.name, "priority": path.priority, "status": path.status.value}
                for path in sorted(self.paths, key=lambda item: item.priority, reverse=True)[:5]
            ],
        }

    @staticmethod
    def _combine_confidence(current: float, incoming: float) -> float:
        return round(max(current, current + (1.0 - current) * incoming), 4)

    @staticmethod
    def _split_sources(source: str) -> set[str]:
        return {part.strip() for part in source.split(",") if part.strip()}

    @staticmethod
    def _join_sources(current: str, incoming: str) -> str:
        parts = [part for part in [current, incoming] if part]
        return ", ".join(parts)

    def _path_index(self, path: int | str) -> int:
        if isinstance(path, int):
            if path < 0 or path >= len(self.paths):
                raise IndexError("path index out of range")
            return path
        for idx, item in enumerate(self.paths):
            if item.name == path:
                return idx
        raise KeyError(f"unknown path: {path}")

    def _has_active_index(self) -> bool:
        return 0 <= self.active_path_index < len(self.paths)
