"""Optional post-scan step: ask an AWS Bedrock model to read the FAIL findings and produce a
prioritized "what's most urgent" summary, embedded into the HTML report. Best-effort — callers
should catch BedrockSummaryError and continue without a summary rather than fail the scan."""

from .models import Finding, Status

MAX_FINDINGS_IN_PROMPT = 60

SUMMARY_TOOL_NAME = "submit_priority_summary"

SUMMARY_TOOL = {
    "toolSpec": {
        "name": SUMMARY_TOOL_NAME,
        "description": "Submit the prioritized security-fix summary for this scan.",
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "most_urgent_fix": {
                        "type": "object",
                        "description": "The single FAIL finding that should be fixed first.",
                        "properties": {
                            "check_id": {"type": "string"},
                            "title": {"type": "string"},
                            "severity": {"type": "string"},
                            "reason": {"type": "string", "description": "Why this is the top priority."},
                            "remediation": {"type": "string"},
                        },
                        "required": ["check_id", "title", "severity", "reason", "remediation"],
                    },
                    "executive_summary": {
                        "type": "string",
                        "description": "A short plain-language paragraph summarizing the account's overall security posture.",
                    },
                    "prioritized_fixes": {
                        "type": "array",
                        "description": "Ranked list of the next-most-important fixes after most_urgent_fix.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "check_id": {"type": "string"},
                                "title": {"type": "string"},
                                "severity": {"type": "string"},
                                "reason": {"type": "string"},
                            },
                            "required": ["check_id", "title", "severity", "reason"],
                        },
                    },
                },
                "required": ["most_urgent_fix", "executive_summary", "prioritized_fixes"],
            }
        },
    }
}


class BedrockSummaryError(Exception):
    """Raised when the Bedrock call fails or returns a response we can't use. Callers should
    treat this as non-fatal to the overall scan."""


def _finding_line(f: Finding) -> str:
    cis = ", ".join(f.cis_benchmarks) if f.cis_benchmarks else "none"
    return (
        f"- check_id={f.check_id} severity={f.severity.name} service={f.service} "
        f"region={f.region} resource={f.resource_id} cis={cis}\n"
        f"  title: {f.title}\n"
        f"  description: {f.description}\n"
        f"  remediation: {f.remediation}"
    )


def build_messages(findings: list[Finding]) -> list[dict]:
    """Build the Bedrock Converse API `messages` list from the scan's findings. Includes only
    FAIL findings (ranked by severity), capped at MAX_FINDINGS_IN_PROMPT with an explicit
    truncation note — never a silent cap. ERROR findings are surfaced only as a count, since
    they represent checks that couldn't be evaluated, not confirmed misconfigurations."""
    fails = sorted(
        (f for f in findings if f.status == Status.FAIL),
        key=lambda f: -f.severity.value,
    )
    errors = [f for f in findings if f.status == Status.ERROR]

    shown = fails[:MAX_FINDINGS_IN_PROMPT]
    omitted = len(fails) - len(shown)

    lines = [
        "You are analyzing the results of a read-only AWS CSPM security scan. Below is the "
        "list of FAILING checks (confirmed misconfigurations), most severe first.",
        "",
        f"Total FAIL findings: {len(fails)}.",
    ]
    if omitted > 0:
        lines.append(
            f"Showing the {len(shown)} highest-severity FAIL findings; {omitted} lower-severity "
            "FAIL findings are omitted from this prompt for brevity."
        )
    if errors:
        lines.append(
            f"Additionally, {len(errors)} checks could not be evaluated (ERROR status, e.g. "
            "missing permissions) and are excluded below — do not treat these as confirmed issues."
        )
    lines.append("")
    lines.extend(_finding_line(f) for f in shown)
    lines.append("")
    lines.append(
        "Call the submit_priority_summary tool with: the single most urgent fix to prioritize "
        "first, a short executive summary of the account's overall posture, and a ranked list "
        "of the next-most-important fixes."
    )

    return [{"role": "user", "content": [{"text": "\n".join(lines)}]}]


def generate_ai_summary(findings: list[Finding], client, model_id: str) -> dict | None:
    """Call Bedrock to generate the prioritized summary. Returns None (without calling Bedrock)
    when there are no FAIL findings to summarize. Raises BedrockSummaryError on any failure —
    callers should catch this and continue without a summary."""
    if not any(f.status == Status.FAIL for f in findings):
        return None

    messages = build_messages(findings)
    try:
        response = client.converse(
            modelId=model_id,
            messages=messages,
            toolConfig={
                "tools": [SUMMARY_TOOL],
                "toolChoice": {"tool": {"name": SUMMARY_TOOL_NAME}},
            },
        )
    except Exception as e:
        raise BedrockSummaryError(f"Bedrock converse() call failed: {e}") from e

    try:
        content_blocks = response["output"]["message"]["content"]
        tool_use = next(b["toolUse"] for b in content_blocks if "toolUse" in b)
        return tool_use["input"]
    except (KeyError, StopIteration) as e:
        raise BedrockSummaryError(
            f"Bedrock response did not contain the expected {SUMMARY_TOOL_NAME} tool call: {e}"
        ) from e
