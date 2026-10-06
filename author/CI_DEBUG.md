# CI Investigation

Failed run:
37472366475

Observed:
- Reviewed and remote main HEAD: `7cd0862e98aacdcd80065a5b50009110d3bb2ee0`.
- Workflow: `Windows PDB and Ghidra proof`, push event, attempt 1.
- Run conclusion: failure; created 2026-10-06 13:38:11 UTC and updated
  13:38:16 UTC.
- Host job `112298868027` and Windows job `112298867800`: failure,
  `runner_id = 0`, empty runner name, `steps = []`.
- Both job annotations on the public run summary report:
  "The job was not started because your account is locked due to a billing issue."
- No verification artifacts were produced (`total_count = 0`).

Root cause:
GitHub refused to start either hosted job because the repository owner's
account is billing-locked. This is an explicit GitHub annotation, not an
inference from empty steps. Checkout, compilation, tests and Ghidra never ran.
The diagnostic does not disclose the underlying payment/account details.

Fix:
The account owner must resolve the billing lock with GitHub and restore Actions
eligibility. Changing workflow syntax, action pins, runner labels or challenge
mechanics cannot resolve this account-level restriction. No speculative code
or workflow changes were made.

After GitHub clears the lock, rerun the unchanged reviewed commit:

```sh
gh run rerun 37472366475 --failed --repo greedoor/reverse
gh run watch 37472366475 --repo greedoor/reverse --exit-status
gh run view 37472366475 --repo greedoor/reverse \
  --json status,conclusion,jobs,headSha,url
```

If execution then exposes a real failing step, inspect its logs and fix that
failure. Do not declare release readiness until both jobs succeed and the
uploaded PE/PDB/runtime/Ghidra reports and hashes have been inspected.

Evidence:
- [Run summary and its two billing-lock annotations](https://github.com/greedoor/reverse/actions/runs/37472366475).
- [Run metadata](https://api.github.com/repos/greedoor/reverse/actions/runs/37472366475).
- [Job metadata](https://api.github.com/repos/greedoor/reverse/actions/runs/37472366475/jobs).
- Check suite ID: `101501274639`.
- [Artifact metadata](https://api.github.com/repos/greedoor/reverse/actions/runs/37472366475/artifacts).
- Investigation date: 2026-10-06. The public run page was retrieved through the
  web connector; its annotations provided the decisive evidence.

## Independent Checks

Local `make test` completed successfully on the reviewed commit:

```text
PASS: static checks and synthetic PE32/PE32+ fragment transport
PASS: every builder transform restored by production C++; malformed RLE and validation bounds (ASan/UBSan)
```

Fresh official tag-ref queries confirmed all immutable action pins. No pin
replacement is needed; old and retained SHAs are identical:

| Official action/tag | Existing and retained commit |
| --- | --- |
| [actions/checkout v4](https://api.github.com/repos/actions/checkout/git/ref/tags/v4) | `11d5960a326750d5838078e36cf38b85af677262` |
| [actions/setup-python v5](https://api.github.com/repos/actions/setup-python/git/ref/tags/v5) | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| [actions/upload-artifact v4](https://api.github.com/repos/actions/upload-artifact/git/ref/tags/v4) | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

The [official Ghidra release metadata](https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_11.4.2_build)
confirms the workflow's asset URL and SHA256:

```text
ghidra_11.4.2_PUBLIC_20250826.zip
795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6
```

Independent PyYAML BaseLoader parsing succeeded, including explicit assertions
for push/pull_request/workflow_dispatch, read-only contents permissions, and
Ubuntu 24.04 / Windows 2022 job labels. BaseLoader preserves the YAML `on` key.
Actionlint and PowerShell are not installed locally, so this is syntax and
selected structure validation, not full workflow/PowerShell execution proof.

## Access Limits And Remaining Gates

- The GitHub read connector rejects check-suite/check-run annotation,
  Actions-permissions and runner-settings endpoints. These settings were not
  inspected. The public summary independently exposes the billing annotation.
- The host shell cannot resolve GitHub; `gh run view` cannot connect and
  `git push origin main` fails with `Could not resolve host: github.com`.
- The GitHub failed-job rerun tool was attempted, but execution was denied:
  `MCP tool call requires approval, but approval policy is never`.
  No rerun was dispatched by this investigation.
- Real Windows build, PE32 architecture, original/reconstructed PDB hashes,
  identity matching, llvm readers, runtime, player ZIP and Ghidra before/after
  checks remain unexecuted in CI. Local synthetic tests do not satisfy them.
- No final PASS report or blind-solve guide is produced: those remain gated on
  actual green execution and inspection of its evidence.

Status: externally blocked by GitHub's billing lock; not release-ready.
