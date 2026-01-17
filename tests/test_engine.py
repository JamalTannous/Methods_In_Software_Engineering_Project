from misconfig_detector.domain import ResourceConfig
from misconfig_detector.engine import RuleEngine
from misconfig_detector.rules import PublicAccessRule, EncryptionRule, LoggingRule


class ExplodingRule:
    def getRuleId(self): return "RULE_EXPLODE"
    def getDescription(self): return "Always throws."
    def getDefaultSeverity(self): return None
    def evaluate(self, resource):  # noqa
        raise RuntimeError("boom")


def test_engine_isolates_rule_failures():
    eng = RuleEngine()
    eng.registerRule(ExplodingRule())      # should be isolated
    eng.registerRule(PublicAccessRule())   # should still run

    r = ResourceConfig(
        resource_id="acc1:bucketA",
        provider="AWS",
        resource_type="bucket",
        public_access=True,
    )
    findings = eng.evaluateResource(r)
    assert any(f.rule_id == "RULE_PUBLIC_ACCESS" for f in findings)


def test_engine_empty_inputs():
    eng = RuleEngine()
    assert eng.evaluateAll([]) == []


def test_engine_deterministic_order_registration():
    eng = RuleEngine()
    eng.registerRule(LoggingRule())
    eng.registerRule(EncryptionRule())

    r = ResourceConfig(
        resource_id="acc1:bucketX",
        provider="AWS",
        resource_type="bucket",
        logging_enabled=False,
        encryption_enabled=False,
    )
    findings = eng.evaluateResource(r)
    assert [f.rule_id for f in findings] == [
        "RULE_LOGGING_DISABLED",
        "RULE_ENCRYPTION_MISSING",
    ]

def test_evaluate_all_with_empty_resource_list():
    engine = RuleEngine()
    results = engine.evaluateAll([])
    assert results == []
def test_evaluate_with_no_registered_rules():
    engine = RuleEngine()

    resource = ResourceConfig(
        resource_id="acc1:bucket-empty-rules",
        provider="AWS",
        resource_type="bucket",
        public_access=True,
        encryption_enabled=True,
        logging_enabled=True,
        policy_summary={},
        metadata={}
    )

    results = engine.evaluateResource(resource)
    assert results == []

class FailingRule:
    def getRuleId(self):
        return "RULE_FAILING"

    def getDescription(self):
        return "This rule always fails"

    def getDefaultSeverity(self):
        return Severity.LOW

    def evaluate(self, resource):
        raise RuntimeError("Intentional failure")


def test_rule_failure_does_not_interrupt_engine():
    engine = RuleEngine()

    engine.registerRule(FailingRule())
    engine.registerRule(PublicAccessRule())

    resource = ResourceConfig(
        resource_id="acc1:bucket-fault-isolation",
        provider="AWS",
        resource_type="bucket",
        public_access=True,
        encryption_enabled=True,
        logging_enabled=True,
        policy_summary={},
        metadata={}
    )

    results = engine.evaluateResource(resource)

    assert len(results) == 1
    assert results[0].rule_id == "RULE_PUBLIC_ACCESS"

def test_deterministic_results_order():
    engine = RuleEngine()
    engine.registerRule(PublicAccessRule())
    engine.registerRule(EncryptionRule())
    engine.registerRule(LoggingRule())

    resource = ResourceConfig(
        resource_id="acc1:bucket-deterministic",
        provider="AWS",
        resource_type="bucket",
        public_access=True,
        encryption_enabled=False,
        logging_enabled=False,
        policy_summary={},
        metadata={}
    )

    first_run = engine.evaluateResource(resource)
    second_run = engine.evaluateResource(resource)

    assert first_run == second_run

