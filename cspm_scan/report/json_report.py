import json
from pathlib import Path

from cspm_scan.core.models import Finding


def write_json_report(findings: list[Finding], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2, default=str)
