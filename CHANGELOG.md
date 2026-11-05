# Changelog

## 0.2.0

Reliability release, 5 November 2026.

- Retain all candidate evidence, file-access and output-limit improvements.
- Compare stream evidence with type-sensitive canonical JSON.
- Validate standalone and collected manifests before probe side effects.
- Classify I/O errors after marker creation as inconclusive rather than denied access.
- Add 49 separately authored review checks, including descriptor-relative parent replacement and an owned Unix socket with no protocol data.
- Verify public PyPI and GitHub downloads against the exact reviewed distributions.


## 0.2.0rc1

Unpublished reliability candidate, 5 November 2026.

- Reject ambiguous, nonfinite, oversized and excessively nested evidence.
- Bound captured process output and invalidate truncated measurements.
- Reject mandatory skipped probes and retain incomplete-report diagnostics.
- Refuse redirected, hard-linked and nonregular evidence/canary reads; keep marker creation exclusive.
- Add no-sockets controls and make the account-free demo fully offline with respect to probe services.
- Distinguish unsupported Docker transports from absent Unix sockets.
- Add an eight-case offline showcase, clean installed-package verification and exact-commit release gates.
- Preserve the zero-dependency runtime and configured agent permissions.

Independent review is required before final version, merge or publication.
