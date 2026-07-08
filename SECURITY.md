# Security Policy

## Scope

PromptShield is an academic security research tool. This document covers:

- Vulnerabilities in PromptShield's own code (runner.py, classifier.py, dashboard.html)
- Payload library issues (payloads that unintentionally facilitate harm)
- Classifier false negatives/positives that could mislead research results

## Reporting a Vulnerability

If you discover a security issue in PromptShield itself, please open a GitHub issue with the label `security`. For sensitive disclosures, contact the author directly via the email on their GitHub profile.

## Responsible Use

PromptShield is designed for testing LLMs **you have authorization to test** using **your own API keys**. Users are responsible for complying with each provider's terms of service and applicable laws.

The authors are not responsible for misuse of this tool against systems without authorization.
