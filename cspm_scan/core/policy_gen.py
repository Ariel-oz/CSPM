"""Derives the least-privilege scanner IAM policy from CHECK_REGISTRY.required_actions
so the policy can never drift from what the checks actually call."""

import json
from pathlib import Path

from .registry import CHECK_REGISTRY

# Needed by the engine itself (preflight auth check, region discovery), not tied to
# any single check, so they're not expressed via a CheckMeta.required_actions list.
BASELINE_ACTIONS = ["sts:GetCallerIdentity", "ec2:DescribeRegions"]

# Needed only by the optional --ai-summary feature (core/bedrock_summary.py), which isn't a
# check either — it's a post-scan analysis step over the findings the checks already produced.
AI_SUMMARY_ACTIONS = ["bedrock:InvokeModel"]


def build_policy() -> dict:
    by_service: dict[str, set[str]] = {}
    for action in BASELINE_ACTIONS + AI_SUMMARY_ACTIONS:
        prefix = action.split(":")[0]
        by_service.setdefault(prefix, set()).add(action)
    for check in CHECK_REGISTRY.values():
        for action in check.meta.required_actions:
            prefix = action.split(":")[0]
            by_service.setdefault(prefix, set()).add(action)

    statements = [
        {
            "Sid": f"{service.upper()}READONLY",
            "Effect": "Allow",
            "Action": sorted(actions),
            "Resource": "*",
        }
        for service, actions in sorted(by_service.items())
    ]
    return {"Version": "2012-10-17", "Statement": statements}


def write_policy(policy: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(policy, f, indent=2)
        f.write("\n")
