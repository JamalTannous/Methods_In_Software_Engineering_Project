# Automated Misconfiguration & Threat Detection in Public Cloud Storage
# Rule-Based Cloud Storage Misconfiguration Detection System

This repository contains the implementation of a rule-based system for detecting security misconfigurations in cloud storage resources.

The system evaluates normalized, provider-agnostic storage configurations against predefined best-practice rules and produces structured, explainable findings with severity and remediation guidance.

The project was developed as part of an academic Software Engineering project and demonstrates requirements analysis, architectural design, low-level design, implementation, and validation.

# Requirements
	Software Requirements
	- Python 3.10+ (Tested with Python 3.13)
	- pip (Python package manager)

	Python Dependencies
		 The only external dependency is:
		 pytest — used for automated validation
		 Install it using:
		 pip install pytest			 
No cloud SDKs, databases, credentials, or external services are required.

# Project Structure
	.
	├── misconfig_detector/
	│   ├── __init__.py
	│   ├── domain.py        # Data contracts (ResourceConfig, Finding, Severity)
	│   ├── rules.py         # Misconfiguration detection rules
	│   └── engine.py        # Rule engine and aggregation logic
	│
	├── demo/
	│   └── run_rules_demo.py  # End-to-end demo script
	│
	├── tests/
	│   ├── test_engine.py     # Rule engine and robustness tests
	│   └── test_rules.py      # Individual rule tests
	│
	├── README.md

# Running the Demo
The demo simulates a cloud storage resource with multiple misconfigurations and demonstrates end-to-end system execution.

From the project root directory, run:

	python -m demo.run_rules_demo

# Demo Output
The demo prints detected misconfigurations, including:

	-affected resource identifier
	-rule ID
	-severity (LOW / MEDIUM / HIGH)
	-description
	-remediation guidance
	-supporting, non-sensitive evidence

# Running Automated Tests
Automated validation is performed using pytest.

From the project root directory, run:

		pytest

# Test Coverage
The tests validate:

	-individual misconfiguration detection rules
	-aggregation and rule independence
	-deterministic execution
	-fault isolation (rule failures do not interrupt evaluation)
	-graceful handling of empty or incomplete input data
All tests should complete successfully.

# Notes
	-The system operates on synthetic, in-memory configuration data only.
	-No real cloud configurations, credentials, or secrets are used.
	-All processing is performed locally and in memory.
	-The design is modular and extensible; new rules can be added without modifying the engine.

# Academic Context
This project was developed as part of an academic software engineering assignment and is accompanied by a full project report covering:

	-problem definition
	-requirements
	-architecture and design
	-implementation
	-validation
	-appendix-level low-level design documentation
