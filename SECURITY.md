# Security Policy — Nexsiz

**Nexsiz** is an offensive security tool intended exclusively for authorised security testing, research, and red-team / APT simulation exercises.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

Only the latest tagged release on the `main` branch receives security attention.

## Authorised Use Only

Nexsiz must be used **only** against systems and networks for which the operator has explicit, written authorisation.

Unauthorised use against third-party systems, production environments without approval, or any activity that violates applicable law is strictly prohibited.

The authors and maintainers accept **no liability** for misuse.

## Reporting a Vulnerability

If you discover a security issue **in Nexsiz itself** (crash in the fuzzer, privilege escalation in a helper, unsafe handling of untrusted input inside the tool, etc.):

1. **Do not** open a public GitHub issue.
2. Contact the maintainer privately via the preferred channel listed in the repository (or via the GitHub security advisory feature if enabled).
3. Include:
   - Nexsiz version / commit SHA
   - Clear reproduction steps
   - Impact assessment (local DoS, information leak, RCE in the fuzzer process, etc.)
   - Any suggested mitigation

We aim to acknowledge reports within a reasonable timeframe and will coordinate disclosure once a fix is available.

## Scope

**In scope**
- Vulnerabilities in the Nexsiz binary, NXS scripts, Python client, or build scripts that can be triggered by a malicious target or crafted corpus.
- Issues that allow a target under test to compromise the fuzzer host.

**Out of scope**
- Crashes or hangs discovered *by* Nexsiz in a target (those are the intended output).
- Missing features, performance issues, or documentation gaps.
- Issues that require the operator to deliberately disable safety mechanisms or run with elevated privileges in an unsafe manner.

## Operational Hardening Recommendations

Operators are expected to:

- Run campaigns only inside isolated networks / VMs / containers.
- Prefer non-root execution.
- Clean residual shared-memory maps after campaigns (`make clean-shm`).
- Treat all crash artefacts and NXS output as potentially sensitive.
- Keep the tool and its dependencies updated.

## Cryptography & Key Material

When using encryptor plugins (`-e chacha20`, `-e tls-record`, etc.):

- Supply keys via environment variables (`NEXSIZ_ENC_KEY` / `NEXSIZ_ENC_NONCE`) or the `-k` flag.
- Never commit real keys or nonces into configuration files that are tracked by git.
- Rotate keys between campaigns when operationally required.

## Third-Party Components

Optional features pull in:
- LibAFL (when built with `--features libafl`)
- CRIU (external binary, when using `--snapshot-backend criu`)
- Frida (external agent for coverage)

Operators are responsible for the security posture of any external tooling they enable.

---

*This policy may be updated as the project evolves. Continued use of Nexsiz constitutes acceptance of the current policy.*
