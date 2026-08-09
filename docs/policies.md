# Policies

Policies let teams turn an observed boundary into a reproducible gate. They use TOML so the core CLI remains dependency-free on Python 3.11+.

```toml
version = 1

allow = ["workspace_read", "workspace_write", "child_process"]
deny = [
  "outside_read",
  "outside_write",
  "home_read",
  "home_write",
  "environment_canary",
  "network_egress",
]
```

`allow` means the capability is required for the tested workflow. `deny` means the capability must not be available. A capability should not appear in both lists, and unknown capability names are rejected instead of being silently ignored.

Policy evaluation is fail-closed:

- an `allow` requirement passes only on `ALLOW`;
- a `deny` requirement passes only on `DENY` or `N/A`;
- `SKIP`, `UNKNOWN` and `ERROR` do not satisfy either requirement.

This prevents missing or inconclusive evidence from being mistaken for a secure boundary.

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | probe completed and policy passed, or no policy was supplied |
| `1` | one or more policy requirements failed |
| `2` | invalid input, runner failure, timeout or insufficient probe evidence |

Keep policies small and tied to real deployment requirements. A stricter policy is not automatically a better policy if it makes the intended workflow impossible.
