# Security Policy

## Important Notice

**Zivis Sim is an intentionally vulnerable application designed for security training and research.** The vulnerabilities in this project are deliberate and meant for educational purposes.

## Scope

### What to Report

Please report security issues if you find:

1. **Unintentional vulnerabilities** - Security flaws that were not deliberately introduced as part of the training scenarios
2. **Secrets or credentials** - Any real API keys, passwords, or credentials accidentally committed to the repository
3. **Supply chain issues** - Vulnerabilities in dependencies that could affect users running the simulation
4. **Infrastructure misconfigurations** - Issues with Docker configuration that could expose users' systems

### What NOT to Report

Please do **not** report:

- The intentional vulnerabilities documented in [DOCS.md](../DOCS.md) - these are features, not bugs
- Prompt injection vulnerabilities in the AI endpoints - these are intentional
- Authentication/authorization bypasses in the vulnerable endpoints - these are intentional
- SSRF, XSS, or injection flaws in the designated vulnerable endpoints - these are intentional

## Reporting a Vulnerability

If you discover an **unintentional** security vulnerability:

1. **Do not** open a public issue
2. Email us at: security@zivis.ai
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to understand and address the issue.

## Safe Usage Guidelines

When using Zivis Sim:

1. **Network Isolation**: Run in an isolated network or VPC
2. **No Production Data**: Never use real customer data or credentials
3. **Access Control**: Limit access to authorized security researchers
4. **API Key Management**: Use dedicated OpenAI API keys with spending limits
5. **Monitoring**: Log all access for training purposes

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Acknowledgments

We appreciate the security research community's efforts in making AI systems safer. Contributors who report valid unintentional vulnerabilities will be acknowledged (with permission) in our documentation.
