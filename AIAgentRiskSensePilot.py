import ast
import re

class Rule:
    """Represents a single audit rule for code scanning."""
    def __init__(self, name, description, check_func):
        self.name = name
        self.description = description
        self.check_func = check_func  # function that performs the check and returns list of issues

    def run(self, tree, code_str):
        """Run the rule's check_func on the AST tree and raw code string. Return a list of issue dicts."""
        return self.check_func(tree, code_str)

# --- 1. Define check functions for each rule ---

def check_unsafe_eval_exec(tree, code_str):
    """Flag use of eval() or exec() which can execute arbitrary code."""
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Check for direct calls to eval or exec
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                issues.append({
                    "line": node.lineno,
                    "issue": f"Use of dangerous function '{node.func.id}' (allows arbitrary code execution)"
                })
    return issues

def check_shell_injection(tree, code_str):
    """Flag use of OS shell commands with untrusted input (possible command injection)."""
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # os.system(...) call
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr == "system":
                    issues.append({
                        "line": node.lineno,
                        "issue": "os.system call used (could execute shell commands from input)"
                    })
            # subprocess.run(..., shell=True) or subprocess.call(..., shell=True)
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "subprocess" and node.func.attr in {"run", "call"}:
                    # Check arguments for shell=True
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            issues.append({
                                "line": node.lineno,
                                "issue": "subprocess.run with shell=True (allows shell injection via input)"
                            })
    return issues

def check_prompt_injection(tree, code_str):
    """Flag LLM prompt constructions that include unvalidated input (potential prompt injection)."""
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Look for openai.Completion.create or openai.ChatCompletion.create calls (typical LLM prompt usage)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "create":
                # node.func.value could be something like openai.Completion or openai.ChatCompletion (an Attribute of Name 'openai')
                val = node.func.value
                if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
                    if val.value.id == "openai" and val.attr in {"Completion", "ChatCompletion"}:
                        # Found a call like openai.Completion.create(...)
                        # Check if 'prompt' argument exists and is constructed dynamically
                        for kw in node.keywords:
                            if kw.arg == "prompt":
                                # If the prompt value is a concatenation or f-string (BinOp or JoinedStr in AST), likely dynamic
                                if isinstance(kw.value, ast.BinOp) or isinstance(kw.value, ast.JoinedStr):
                                    issues.append({
                                        "line": node.lineno,
                                        "issue": "LLM prompt is dynamically constructed from input (possible prompt injection risk)"
                                    })
    return issues

def check_hardcoded_secrets(tree, code_str):
    """Flag likely hardcoded secrets (API keys, passwords) in code or config."""
    issues = []
    # Define some regex patterns for common secret formats (can be extended as needed)
    secret_patterns = [
        r'AKIA[0-9A-Z]{16}',           # AWS Access Key ID pattern
        r'(?i)secret[_-]?key\s*=\s*["\']?[A-Za-z0-9/+]{16,}["\']?',  # Generic "secret key" assignment with base64-ish value
        r'(?i)password\s*=\s*["\']?.{6,}["\']?'  # "password" assignment (value of length >=6 as a naive check)
    ]
    for pattern in secret_patterns:
        for match in re.finditer(pattern, code_str):
            line_num = code_str.count("\n", 0, match.start()) + 1
            issues.append({
                "line": line_num,
                "issue": f"Hardcoded credential or secret (matches pattern: {pattern})"
            })
    return issues

def check_logging_and_exceptions(tree, code_str):
    """Check for presence of logging and proper exception handling (control and monitoring)."""
    issues = []
    logging_imported = False
    for node in ast.walk(tree):
        # Detect if logging module is imported
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "logging":
                    logging_imported = True
        if isinstance(node, ast.ImportFrom):
            if node.module == "logging":
                logging_imported = True
        # Detect bare except clauses with no logging or action
        if isinstance(node, ast.ExceptHandler):
            # If the except block is empty or just passes, it's a bad practice
            if not node.body or (len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
                issues.append({
                    "line": node.lineno,
                    "issue": "Exception caught and ignored (no handling or logging in except block)"
                })
    # If logging is never imported or used in a non-trivial agent, flag it
    if not logging_imported:
        issues.append({
            "line": 0,
            "issue": "No logging detected in code (important actions may not be logged)"
        })
    return issues

# --- 2. Combine all rules into a list ---
rules = [
    Rule("Unsafe Eval/Exec Use", "Use of eval() or exec() functions (code injection risk)", check_unsafe_eval_exec),
    Rule("Command Injection", "Execution of shell commands using os.system or subprocess with shell=True", check_shell_injection),
    Rule("Prompt Injection Risk", "LLM prompt uses untrusted input (prompt injection vulnerability)", check_prompt_injection),
    Rule("Hardcoded Secrets", "Hardcoded credentials or sensitive secrets in code", check_hardcoded_secrets),
    Rule("Logging/Exception Handling", "Lack of logging or improper exception handling", check_logging_and_exceptions)
]

def scan_code(code_str):
    """
    Analyze a Python code string and return a list of identified issues.
    Each issue is a dict with rule name, line number, and description.
    """
    issues_found = []
    try:
        tree = ast.parse(code_str)
    except Exception as parse_err:
        # If code is not syntactically correct, we cannot parse it for AST
        issues_found.append({
            "rule": "Parsing Error",
            "line": 0,
            "description": f"Code parsing failed: {parse_err}"
        })
        return issues_found

    for rule in rules:
        results = rule.run(tree, code_str)
        for res in results:
            issues_found.append({
                "rule": rule.name,
                "line": res["line"],
                "description": res["issue"]
            })
    return issues_found

# Example usage on a given script (string or file content):
example_code = """
import openai
import os

API_KEY = "AKIA1234567890ABCDEF"  # hardcoded AWS key example
password = "supersecret"  # hardcoded password example

def agent(user_input):
    # Construct prompt directly with user input (potential injection)
    prompt = f"User said: {user_input}"
    response = openai.Completion.create(engine="davinci", prompt=prompt)
    # Execute command with user input (unsafe)
    os.system(user_input)
    try:
        risky_action = eval(user_input)  # executing user input as code!
    except Exception:
        pass  # exceptions are silently ignored
    return response
"""

issues = scan_code(example_code)
for issue in issues:
    print(f"[Line {issue['line']}] {issue['rule']}: {issue['description']}")
