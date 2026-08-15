# cspm-scan

A local, read-only AWS CSPM (Cloud Security Posture Management) scanner. Runs a set of
security checks against a single AWS account/profile and reports misconfigurations as a
CLI table, JSON, and a self-contained HTML report. 47 checks, most mapped to a CIS AWS
Foundations Benchmark v3.0.0 control.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure an AWS named profile (in `~/.aws/config` / `~/.aws/credentials`) with read-only
access. `iam/scanner-readonly-policy.json` is a generated least-privilege policy containing
exactly the actions the checks use, plus the small set of engine-level actions needed
regardless of which checks run (auth/region-discovery, and `bedrock:InvokeModel` for the
optional `--ai-summary` feature below) — attach it to a dedicated scanner IAM user if you want
tighter permissions than whatever profile you're currently using.

## Usage

```bash
python -m cspm_scan --profile <profile> [--regions us-east-1,eu-west-1] \
    --output-dir ./output --formats table,json,html

# Regenerate the least-privilege IAM policy from the current check catalog
python -m cspm_scan --print-iam-policy --output iam/scanner-readonly-policy.json
```

Findings use a 4-state status — `PASS`, `FAIL`, `ERROR`, `NOT_APPLICABLE` — instead of a plain
pass/fail boolean. A missing IAM permission produces an `ERROR` finding (with the AWS error
code attached), never a silent pass.

## AI-powered priority summary (AWS Bedrock)

```bash
python -m cspm_scan --profile <profile> --formats table,json,html --ai-summary \
    [--bedrock-model us.anthropic.claude-haiku-4-5-20251001-v1:0] [--bedrock-region us-east-1]
```

`--ai-summary` sends the scan's `FAIL` findings to an AWS Bedrock model (Claude Haiku by
default, via `--bedrock-model`) and asks it to identify the single most urgent fix, a short
executive summary, and a ranked list of the next-most-important fixes. The result is embedded
as a new section in `report.html` only — there's no standalone summary file and it isn't printed
to the console — so `--ai-summary` requires `html` to be one of the enabled `--formats` (the CLI
errors out otherwise, rather than silently spending a Bedrock call on output nobody will see).

This is a best-effort, opt-in layer, not part of the core scan: a Bedrock failure (no model
access, wrong region, throttling, malformed response) prints a warning and the rest of the
scan/reports complete normally. Before using it, the target account needs model access enabled
for the chosen model in the Bedrock console for `--bedrock-region` — that's a one-time,
per-account/region setting unrelated to IAM. Bedrock model availability is region-specific and
generally unrelated to which AWS regions are being scanned, hence the separate
`--bedrock-region` flag (default `us-east-1`).

Deliberate scope choices, so the prompt stays small and the output stays trustworthy:
- Only `FAIL` findings are sent, ranked by severity and capped at 60 (`MAX_FINDINGS_IN_PROMPT` in
  `core/bedrock_summary.py`); if more exist, the prompt says so explicitly rather than silently
  dropping the lowest-severity ones.
- `ERROR` findings (checks that couldn't be evaluated, e.g. missing permissions) are surfaced
  only as a count for context — never treated as confirmed issues to prioritize.
- Each finding's free-form `evidence` dict is excluded from the prompt (no fixed schema across
  checks; the `title`/`description`/`remediation` text already carries the signal).
- The model's output is rendered through the same HTML-escaping as every other field in the
  report — it's untrusted-ish generated text, never inserted as raw/`| safe` HTML.

## CIS AWS Foundations Benchmark v3.0.0 mapping

Every `Finding` (and every `CheckMeta`) carries a `cis_benchmarks: list[str]` field — the CIS
v3.0.0 control ID(s) that check corresponds to, plus a constant `cis_benchmark_version` field.
Surfaced in `findings.json` and as a column in the HTML report (not in the terse CLI table).
Where a check has no clean 1:1 CIS v3.0.0 match, `cis_benchmarks` is `[]` rather than a forced
approximate mapping — this is deliberate, not an oversight, for checks like `s3_002` (default
encryption) and `s3_003` (versioning), which audit real misconfigurations that simply aren't in
this particular benchmark version. `cis_benchmarks` is a **required** field on `CheckMeta` (no
default) specifically so a new check without an explicit mapped-or-`[]` decision fails loudly
(`TypeError`) at import time rather than silently defaulting to unmapped.

## Check catalog (47 checks)

- **IAM** (18): root MFA/access keys (`iam_001`, `iam_002`), console MFA (`iam_003`), admin-equivalent
  policies (`iam_006`), password policy min length/reuse prevention (`iam_007`, `iam_008`), unused
  keys/console access 45d (`iam_009`, `iam_010`), key rotation 90d (`iam_011`), multiple active keys
  (`iam_012`), initial key never rotated (`iam_013`, heuristic), permissions via groups only
  (`iam_014`), AWS Support role exists (`iam_015`), expired server certs (`iam_016`), root hardware
  vs virtual MFA (`iam_017`), root used recently (`iam_018`), CloudShell full access attached (`iam_020`)
- **S3** (6): public access (`s3_001`), default encryption (`s3_002`, non-CIS), versioning
  (`s3_003`, non-CIS), access logging on every bucket (`s3_004`, non-CIS), secure-transport-only
  bucket policy (`s3_005`), MFA Delete (`s3_006`)
- **EC2** (7): security groups open to the world (`ec2_001`), unencrypted EBS (`ec2_002`), IMDSv2
  required (`ec2_003`), default SG not restricted (`ec2_004`), NACLs open to the world on admin
  ports (`ec2_005`), VPC flow logs (`ec2_006`), instance IAM profile presence (`ec2_007`)
- **CloudTrail** (6): multi-region trail logging (`cloudtrail_001`), CloudTrail delivery bucket
  access logging (`cloudtrail_002`), log file validation (`cloudtrail_003`), KMS encryption
  (`cloudtrail_004`), S3 data events write/read (`cloudtrail_005`, `cloudtrail_006`)
- **RDS** (3): storage encryption (`rds_001`), auto minor version upgrade (`rds_002`), publicly
  accessible (`rds_003`)
- **GuardDuty** (1): detector enabled (`guardduty_001`, non-CIS — GuardDuty isn't in this benchmark)
- **IAM Access Analyzer** (1): analyzer enabled (`accessanalyzer_001`)
- **EFS** (1): filesystem encryption (`efs_001`)
- **Security Hub** (1): enabled in-region (`securityhub_001`)
- **AWS Config** (1): recorder enabled and recording (`config_001`)
- **KMS** (1): customer-managed key rotation (`kms_001`)
- **Macie** (1): enabled in-region (`macie_001`)
- **Account** (1): Security alternate contact configured (`account_001`)

### Deferred (not implemented)

The CIS 4.1–4.15 CloudWatch-alarm-on-metric-filter family (15 controls sharing one mechanism —
deferred as its own future pass due to filter-pattern-matching fragility against hand-written
filters), plus a handful of CIS controls judged impractical for a read-only point-in-time scanner
(root security questions, "contact details are current," SAML/OIDC federation posture, VPC peering
route "least access" — all organizational/manual-judgment controls with no meaningful API-checkable
pass/fail).

## Adding a new check

Add a class to the relevant file in `cspm_scan/checks/` (or a new file for a new service),
decorated with `@register_check(CheckMeta(...))`. No changes to `core/engine.py` are needed —
`checks/__init__.py` auto-imports every module in the package. List every AWS API action the
check calls in `CheckMeta.required_actions`; re-run `--print-iam-policy` afterward to pick it up.
`CheckMeta.cis_benchmarks` is required — set it to the correct CIS v3.0.0 control ID(s) (verify
against at least two independent sources, e.g. AWS Security Hub's CIS-version table and Prowler's
`cis_3.0_aws.json` — watch for controls renumbered/removed between CIS versions) or `[]` if there's
genuinely no clean match; never leave a placeholder.

## Validation

Run `pytest` for the full test suite. After any real scan, or any change to a file under
`cspm_scan/checks/`, run:
- **`cspm-validator`** (`.claude/agents/cspm-validator.md`) against `output/findings.json` and
  `output/report.html` — audits that FAIL findings are backed by real evidence, that no ERROR
  finding is a disguised real finding, that every registered check produced output, that the HTML
  report matches the JSON, and that the IAM policy hasn't drifted from `required_actions`.
- **`cis-batch-reviewer`** (`.claude/agents/cis-batch-reviewer.md`) after adding/changing any
  CIS-mapped check — independently re-verifies the CIS control number against two sources, audits
  the check logic against what the control actually requires, and scores the change 0–100 (approved
  above 85). Both agents are read-only: they report, they never edit code or output.
