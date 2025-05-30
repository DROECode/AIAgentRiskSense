
import os
import ast
import argparse
import csv
import logging
import re
from collections import defaultdict

# Configure logging
logging.basicConfig(
    filename="audit_log.txt",
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Severity map
severity_map = {
    "Hardcoded Secrets": "High",
    "Prompt Injection Risk": "High",
    "Command Injection": "High",
    "Unsafe Eval/Exec Use": "Medium",
    "Logging/Exception Handling": "Medium",
    "Parsing Error": "Low",
    "File Read Error": "Low"
}

def check_eval_exec(tree, file_path):
    logging.info(f"Running Eval/Exec Use check on {file_path}")
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            issues.append({
                "line": node.lineno,
                "rule": "Unsafe Eval/Exec Use",
                "severity": severity_map["Unsafe Eval/Exec Use"],
                "description": f"Use of {node.func.id}() is unsafe and can execute arbitrary code."
            })
    return issues

def check_os_system(tree, file_path):
    logging.info(f"Running Command Injection check on {file_path}")
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                issues.append({
                    "line": node.lineno,
                    "rule": "Command Injection",
                    "severity": severity_map["Command Injection"],
                    "description": "Use of os.system() can lead to shell injection."
                })
    return issues

def check_prompt_injection(tree, file_path):
    logging.info(f"Running Prompt Injection check on {file_path}")
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "create" and isinstance(node.func.value, ast.Attribute):
                if node.func.value.attr in {"Completion", "ChatCompletion"}:
                    for kw in node.keywords:
                        if kw.arg == "prompt" and isinstance(kw.value, (ast.BinOp, ast.JoinedStr)):
                            issues.append({
                                "line": node.lineno,
                                "rule": "Prompt Injection Risk",
                                "severity": severity_map["Prompt Injection Risk"],
                                "description": "Prompt is dynamically built using untrusted input, risking injection."
                            })
    return issues

def check_hardcoded_secrets(code_str, file_path):
    logging.info(f"Running Hardcoded Secrets check on {file_path}")
    issues = []
    patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'(?i)secret[_-]?key\s*=\s*["\']?[A-Za-z0-9/+]{16,}["\']?',
        r'(?i)password\s*=\s*["\']?.{6,}["\']?'
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, code_str):
            line_num = code_str[:match.start()].count('\n') + 1
            issues.append({
                "line": line_num,
                "rule": "Hardcoded Secrets",
                "severity": severity_map["Hardcoded Secrets"],
                "description": f"Detected hardcoded secret matching pattern: {pattern}"
            })
    return issues

def check_logging_and_exceptions(tree, file_path):
    logging.info(f"Running Logging/Exception Handling check on {file_path}")
    issues = []
    logging_imported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "logging":
                    logging_imported = True
        if isinstance(node, ast.ImportFrom) and node.module == "logging":
            logging_imported = True
        if isinstance(node, ast.ExceptHandler):
            if not node.body or (len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
                issues.append({
                    "line": node.lineno,
                    "rule": "Logging/Exception Handling",
                    "severity": severity_map["Logging/Exception Handling"],
                    "description": "Empty or silent exception block detected."
                })
    if not logging_imported:
        issues.append({
            "line": 0,
            "rule": "Logging/Exception Handling",
            "severity": severity_map["Logging/Exception Handling"],
            "description": "Logging module not imported; critical actions may not be monitored."
        })
    return issues

def scan_code(code_str, file_path):
    issues = []
    try:
        tree = ast.parse(code_str)
    except Exception as e:
        logging.error(f"AST parsing failed for {file_path}: {e}")
        return [{
            "line": 0,
            "rule": "Parsing Error",
            "severity": severity_map["Parsing Error"],
            "description": f"Code could not be parsed: {e}"
        }]
    issues.extend(check_eval_exec(tree, file_path))
    issues.extend(check_os_system(tree, file_path))
    issues.extend(check_prompt_injection(tree, file_path))
    issues.extend(check_hardcoded_secrets(code_str, file_path))
    issues.extend(check_logging_and_exceptions(tree, file_path))
    return issues

def audit_directory(directory_path):
    all_results = []
    file_statuses = []
    scanned_files = 0

    for root, _, files in os.walk(directory_path):
        for fname in files:
            if fname.endswith(".py"):
                scanned_files += 1
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        code = f.read()
                        issues = scan_code(code, fpath)
                        for issue in issues:
                            issue["file"] = fpath
                            all_results.append(issue)
                except Exception as e:
                    logging.error(f"Failed to read {fpath}: {e}")
                    issues = [{
                        "file": fpath,
                        "line": 0,
                        "rule": "File Read Error",
                        "severity": severity_map["File Read Error"],
                        "description": f"Could not read file: {e}"
                    }]
                    all_results.extend(issues)

                status = "Issues Found" if issues else "Pass"
                file_statuses.append({
                    "file": fpath,
                    "status": status,
                    "issue_count": len(issues)
                })

    return all_results, file_statuses, scanned_files

def export_to_csv(results, file_statuses, output_path="audit_results.csv"):
    fieldnames = ["File", "Line", "Rule", "Severity", "Description", "Status"]
    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        issues_by_file = defaultdict(list)
        for r in results:
            issues_by_file[r["file"]].append(r)

        for file_record in file_statuses:
            file = file_record["file"]
            status = file_record["status"]
            if file in issues_by_file:
                for issue in issues_by_file[file]:
                    writer.writerow({
                        "File": file,
                        "Line": issue.get("line", ""),
                        "Rule": issue.get("rule", ""),
                        "Severity": issue.get("severity", ""),
                        "Description": issue.get("description", ""),
                        "Status": status
                    })
            else:
                writer.writerow({
                    "File": file,
                    "Line": "",
                    "Rule": "",
                    "Severity": "",
                    "Description": "",
                    "Status": "Pass"
                })

    logging.info(f"CSV report saved to {output_path}")
    print(f"✅ CSV report saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit Python AI agent scripts for risks.")
    parser.add_argument("directory", type=str, help="Directory containing agent code")
    parser.add_argument("--csv", type=str, default="audit_results.csv", help="Output CSV file name")

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        logging.error(f"Directory does not exist: {args.directory}")
        print(f"❌ Error: Directory '{args.directory}' does not exist.")
        exit(1)

    logging.info(f"Starting audit of directory: {args.directory}")
    print(f"🔍 Scanning directory: {args.directory}")
    results, file_statuses, file_count = audit_directory(args.directory)

    if file_count == 0:
        logging.warning("No Python (.py) files found.")
        print("⚠️ No Python (.py) files found. Nothing to scan.")
        exit(0)

    for result in results:
        print(f"[{result['file']}:{result['line']}] {result['rule']} - {result['severity']} - {result['description']}")

    export_to_csv(results, file_statuses, output_path=args.csv)
