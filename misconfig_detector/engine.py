from __future__ import annotations

from typing import List

from .domain import ResourceConfig, Finding
from .rules import Rule


class RuleEngine:
    """
    Appendix X RuleEngine:
    - deterministic rule execution order
    - isolates rule failures
    - aggregates findings
    """

    def __init__(self) -> None:
        self._rules: List[Rule] = []

    def registerRule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def evaluateResource(self, resource: ResourceConfig) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self._rules:  # deterministic: registration order
            try:
                f = rule.evaluate(resource)
                if f is not None:
                    findings.append(f)
            except Exception:
                # Engine-level isolation: swallow rule exception and continue
                # (Optional: log to a higher layer; not this module's job)
                continue
        return findings

    def evaluateAll(self, resources: List[ResourceConfig]) -> List[Finding]:
        all_findings: List[Finding] = []
        for r in resources:
            all_findings.extend(self.evaluateResource(r))
        return all_findings

