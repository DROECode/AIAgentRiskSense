import os
import ast
import argparse
import csv
import logging
from collections import defaultdict

# Set up logging
logging.basicConfig(
    filename="audit_log.txt",
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Severity mapping
severity_map = {
    "Hardcoded Secrets": "High",
    "Prompt Injection Risk": "High",
    "Command Injection": "High",
    "Unsafe Eval/Exec Use": "Medium",
    "Logging/Exception Handling": "Medium",
    "Parsing Error": "Low",
    "File Read Error": "Low"
}

# Placeholder scan logic
def scan_code(code_str, file_path):
    logging.info(f"Scanning file: {file_path}")
    issues = []
    if "eval(" in code_str:
        line_num = next((i+1 for i, line in enumerate(code_str.splitlines()) if "eval(" in line), 0)
        issues.append({
            "line": line_num,
            "rule": "Unsafe Eval/Exec Use",
            "severity": severity_map["Unsafe Eval/Exec Use"],
            "description": "Use of eval() is unsafe."
        })
        logging.warning(f"eval() found in {file_path} at line {line_num}")
    if not issues:
        logging.info(f"No issues found in {file_path}")
    return issues

# Scan directory
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

# Export to CSV
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

# Entry point
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
