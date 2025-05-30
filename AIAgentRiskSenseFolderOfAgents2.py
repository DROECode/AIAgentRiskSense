import os
import ast
import argparse
import csv
import logging
import re
from collections import defaultdict
from typing import List, Dict

"""
Enhanced version of the AI‑Agent static‑analysis utility.
Adds dynamic support for *any* additional risks that are defined in an
external Risk‑Control Matrix (RCM) supplied as a CSV file.  Each row in the
matrix should, at a minimum, contain the following headings (case‑insensitive):

    Rule         – unique name for the control/risk to flag
    Pattern      – **raw Python regular‑expression** that detects the risk
    Severity     – High | Medium | Low (optional, defaults to Medium)
    Description  – Human‑readable explanation shown in the report

Additional columns are ignored.  Example CSV snippet::

    Rule,Pattern,Severity,Description
    Deprecated Requests Lib,\brequests\.session\(\),Low,The requests session object is deprecated.
    Long‑Running Loop,while True:,Medium,Unbounded loop may tie‑up resources.

The script will merge the dynamic rules with the built‑in checks and include
them in both the console output and the CSV report.
"""

# ───────────────────────────────  Logging  ────────────────────────────────
logging.basicConfig(
    filename="audit_log.txt",
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s",
)

# Built‑in severities; custom rules extend this at runtime
severity_map = {
    "Hardcoded Secrets": "High",
    "Prompt Injection Risk": "High",
    "Command Injection": "High",
    "Unsafe Eval/Exec Use": "Medium",
    "Logging/Exception Handling": "Medium",
    "Parsing Error": "Low",
    "File Read Error": "Low",
}

# ───────────────────────  Built‑in static checks  ─────────────────────────

def check_eval_exec(tree: ast.AST, file_path: str) -> List[Dict]:
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            issues.append({
                "line": node.lineno,
                "rule": "Unsafe Eval/Exec Use",
                "severity": severity_map["Unsafe Eval/Exec Use"],
                "description": f"Use of {node.func.id}() is unsafe and can execute arbitrary code.",
            })
    return issues

def check_os_system(tree: ast.AST, file_path: str) -> List[Dict]:
    issues = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            issues.append({
                "line": node.lineno,
                "rule": "Command Injection",
                "severity": severity_map["Command Injection"],
                "description": "Use of os.system() can lead to shell injection.",
            })
    return issues

def check_prompt_injection(tree: ast.AST, file_path: str) -> List[Dict]:
    """Detect dynamically concatenated prompts sent to the OpenAI SDK."""
    issues = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "create"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr in {"Completion", "ChatCompletion"}
        ):
            for kw in node.keywords:
                if kw.arg == "prompt" and isinstance(kw.value, (ast.BinOp, ast.JoinedStr)):
                    issues.append({
                        "line": node.lineno,
                        "rule": "Prompt Injection Risk",
                        "severity": severity_map["Prompt Injection Risk"],
                        "description": "Prompt is dynamically built using untrusted input, risking injection.",
                    })
    return issues

def check_hardcoded_secrets(code_str: str, file_path: str) -> List[Dict]:
    issues = []
    patterns = [
        r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
        r"(?i)secret[_-]?key\s*=\s*[\"\']?[A-Za-z0-9/+]{16,}[\"\']?",
        r"(?i)password\s*=\s*[\"\']?.{6,}[\"\']?",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, code_str):
            line_num = code_str[: match.start()].count("\n") + 1
            issues.append({
                "line": line_num,
                "rule": "Hardcoded Secrets",
                "severity": severity_map["Hardcoded Secrets"],
                "description": f"Detected hard‑coded secret matching pattern: {pattern}",
            })
    return issues

def check_logging_and_exceptions(tree: ast.AST, file_path: str) -> List[Dict]:
    issues: List[Dict] = []
    logging_imported = False

    for node in ast.walk(tree):
        # Track whether the script imported the logging module
        if isinstance(node, ast.Import):
            logging_imported |= any(alias.name == "logging" for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module == "logging":
            logging_imported = True
        # Flag bare or silent except blocks
        if isinstance(node, ast.ExceptHandler):
            if not node.body or (len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
                issues.append({
                    "line": node.lineno,
                    "rule": "Logging/Exception Handling",
                    "severity": severity_map["Logging/Exception Handling"],
                    "description": "Empty or silent exception block detected.",
                })

    if not logging_imported:
        issues.append({
            "line": 0,
            "rule": "Logging/Exception Handling",
            "severity": severity_map["Logging/Exception Handling"],
            "description": "Logging module not imported; critical actions may not be monitored.",
        })
    return issues

# ─────────────────────  Dynamic risk matrix handling  ─────────────────────

def load_custom_risks(matrix_path: str) -> List[Dict]:
    """Load additional regex‑based risks from a CSV Risk‑Control Matrix."""
    if not os.path.isfile(matrix_path):
        logging.warning("Risk matrix not found: %s", matrix_path)
        return []

    custom_risks: List[Dict] = []
    try:
        with open(matrix_path, newline="", encoding="utf-8-sig") as fp:
            reader = csv.DictReader(fp)
            for row in reader:
                rule = (row.get("Rule") or row.get("Risk") or "").strip()
                pattern = (row.get("Pattern") or row.get("Regex") or "").strip()
                if not rule or not pattern:
                    continue  # skip incomplete rows

                severity = (row.get("Severity") or "Medium").title()
                description = (row.get("Description") or f"Custom risk detected: {rule}").strip()

                # Extend severity map so it appears in consistent casing later
                if severity not in severity_map.values():
                    severity_map[rule] = severity  # local override

                custom_risks.append({
                    "rule": rule,
                    "pattern": pattern,
                    "severity": severity,
                    "description": description,
                })
    except Exception as exc:
        logging.error("Failed to load risk matrix %s: %s", matrix_path, exc)
    else:
        logging.info("Loaded %d custom risks from %s", len(custom_risks), matrix_path)

    return custom_risks

def check_custom_regexes(code_str: str, custom_risks: List[Dict]) -> List[Dict]:
    """Apply each user‑supplied regex to the given code string."""
    issues: List[Dict] = []
    for risk in custom_risks:
        compiled = re.compile(risk["pattern"], re.MULTILINE | re.IGNORECASE)
        for match in compiled.finditer(code_str):
            line_num = code_str[: match.start()].count("\n") + 1
            issues.append({
                "line": line_num,
                "rule": risk["rule"],
                "severity": risk["severity"],
                "description": risk["description"],
            })
    return issues

# ─────────────────────────────  Core engine  ──────────────────────────────

def scan_code(code_str: str, file_path: str, custom_risks: List[Dict]) -> List[Dict]:
    issues: List[Dict] = []
    try:
        tree = ast.parse(code_str)
    except Exception as exc:
        logging.error("AST parsing failed for %s: %s", file_path, exc)
        return [
            {
                "line": 0,
                "rule": "Parsing Error",
                "severity": severity_map["Parsing Error"],
                "description": f"Code could not be parsed: {exc}",
            }
        ]

    # Built‑in detectors
    issues.extend(check_eval_exec(tree, file_path))
    issues.extend(check_os_system(tree, file_path))
    issues.extend(check_prompt_injection(tree, file_path))
    issues.extend(check_hardcoded_secrets(code_str, file_path))
    issues.extend(check_logging_and_exceptions(tree, file_path))

    # Custom regex‑based checks
    if custom_risks:
        issues.extend(check_custom_regexes(code_str, custom_risks))

    return issues


def audit_directory(directory_path: str, custom_risks: List[Dict]):
    all_results: List[Dict] = []
    file_statuses: List[Dict] = []
    scanned_files = 0

    for root, _, files in os.walk(directory_path):
        for fname in files:
            if fname.endswith(".py"):
                scanned_files += 1
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        code = f.read()
                        issues = scan_code(code, fpath, custom_risks)
                        for issue in issues:
                            issue["file"] = fpath
                            all_results.append(issue)
                except Exception as exc:
                    logging.error("Failed to read %s: %s", fpath, exc)
                    all_results.append({
                        "file": fpath,
                        "line": 0,
                        "rule": "File Read Error",
                        "severity": severity_map["File Read Error"],
                        "description": f"Could not read file: {exc}",
                    })
                    issues = [1]  # so that status becomes "Issues Found"

                status = "Issues Found" if issues else "Pass"
                file_statuses.append({
                    "file": fpath,
                    "status": status,
                    "issue_count": len(issues),
                })

    return all_results, file_statuses, scanned_files


def export_to_csv(results: List[Dict], file_statuses: List[Dict], output_path: str = "audit_results.csv"):
    fieldnames = ["File", "Line", "Rule", "Severity", "Description", "Status"]
    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        issues_by_file: Dict[str, List[Dict]] = defaultdict(list)
        for record in results:
            issues_by_file[record["file"]].append(record)

        for file_record in file_statuses:
            file = file_record["file"]
            status = file_record["status"]
            if file in issues_by_file:
                for issue in issues_by_file[file]:
                    writer.writerow(
                        {
                            "File": file,
                            "Line": issue.get("line", ""),
                            "Rule": issue.get("rule", ""),
                            "Severity": issue.get("severity", ""),
                            "Description": issue.get("description", ""),
                            "Status": status,
                        }
                    )
            else:
                writer.writerow(
                    {
                        "File": file,
                        "Line": "",
                        "Rule": "",
                        "Severity": "",
                        "Description": "",
                        "Status": "Pass",
                    }
                )

    logging.info("CSV report saved to %s", output_path)
    print(f"✅ CSV report saved to: {output_path}")


# ────────────────────────────────  CLI  ─────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Audit Python AI‑agent scripts for risks (built‑in + custom)."
    )
    parser.add_argument("directory", type=str, help="Directory containing agent code to scan")
    parser.add_argument(
        "--csv", type=str, default="audit_results.csv", help="Output CSV file name"
    )
    parser.add_argument(
        "--risk_matrix",
        type=str,
        default="Full_Enhanced_AI_Agent_Risk_Control_Matrix.csv",
        help="Path to the Risk‑Control Matrix CSV that defines additional regex checks",
    )

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        logging.error("Directory does not exist: %s", args.directory)
        print(f"❌ Error: Directory '{args.directory}' does not exist.")
        exit(1)

    # Load custom risks, if any
    custom_risks = load_custom_risks(args.risk_matrix)

    logging.info("Starting audit of directory: %s", args.directory)
    print(f"🔍 Scanning directory: {args.directory}")

    results, file_statuses, file_count = audit_directory(args.directory, custom_risks)

    if file_count == 0:
        logging.warning("No Python (.py) files found.")
        print("⚠️  No Python (.py) files found. Nothing to scan.")
        exit(0)

    # Console summary
    for result in results:
        print(
            f"[{result['file']}:{result['line']}] {result['rule']} - {result['severity']} - {result['description']}"
        )

    export_to_csv(results, file_statuses, output_path=args.csv)
