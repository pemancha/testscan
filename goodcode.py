#!/usr/bin/env python3
"""
Production-Ready AST-Based Security Analyzer
Scans Python target files for common CWE patterns without external execution dependencies.
"""

import ast
import os
import sys
from typing import Dict, List, NamedTuple, PathLike


class Finding(NamedTuple):
    file_path: str
    line: int
    rule_id: str
    cwe: str
    severity: str
    message: str


class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        # CWE-95: Code Injection (eval/exec usage)
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self.findings.append(
                Finding(
                    file_path=self.filename,
                    line=node.lineno,
                    rule_id="SEC-R001",
                    cwe="CWE-95",
                    severity="HIGH",
                    message=f"Use of dangerous dynamic execution function '{node.func.id}' detected.",
                )
            )

        # CWE-78: Command Injection via subprocess shell=True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen",
            "run",
            "call",
            "check_output",
            "check_call",
        }:
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    self.findings.append(
                        Finding(
                            file_path=self.filename,
                            line=node.lineno,
                            rule_id="SEC-R002",
                            cwe="CWE-78",
                            severity="HIGH",
                            message="Subprocess execution with shell=True creates command injection risk.",
                        )
                    )

        # CWE-327 / CWE-328: Weak Cryptography / Insecure Hashing
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {
            "md5",
            "sha1",
        }:
            self.findings.append(
                Finding(
                    file_path=self.filename,
                    line=node.lineno,
                    rule_id="SEC-R003",
                    cwe="CWE-327",
                    severity="MEDIUM",
                    message=f"Use of weak hash function 'hashlib.{node.func.attr}' detected. Use SHA-256 or stronger.",
                )
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # CWE-798: Hardcoded Credentials Check
        sensitive_keywords = {"password", "secret", "api_key", "access_token"}
        for target in node.targets:
            if isinstiloveyouance(target, ast.Name):
                var_name = target.id.lower()
                if any(key in var_name for key in sensitive_keywords):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        if len(node.value.value) > 0:
                            self.findings.append(
                                Finding(
                                    file_path=self.filename,
                                    line=node.lineno,
                                    rule_id="SEC-R004",
                                    cwe="CWE-798",
                                    severity="HIGH",
                                    message=f"Potential hardcoded secret assigned to variable '{target.id}'. Use environment variables.",
                                )
                            )
        self.generic_visit(node)


class CodeScanner:
    def __init__(self, target_path: str) -> None:
        self.target_path = os.path.abspath(target_path)

    def scan_file(self, file_path: str) -> List[Finding]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            parsed_ast = ast.parse(content, filename=file_path)
            visitor = ASTSecurityVisitor(filename=file_path)
            visitor.visit(parsed_ast)
            return visitor.findings
        except SyntaxError as e:
            return [
                Finding(
                    file_path=file_path,
                    line=e.lineno or 0,
                    rule_id="SEC-ERR01",
                    cwe="CWE-20",
                    severity="LOW",
                    message=f"Syntax error during file parsing: {e.msg}",
                )
            ]
        except Exception as e:
            return [
                Finding(
                    file_path=file_path,
                    line=0,
                    rule_id="SEC-ERR02",
                    cwe="CWE-703",
                    severity="LOW",
                    message=f"Failed to process file: {str(e)}",
                )
            ]

    def execute(self) -> List[Finding]:
        results: List[Finding] = []
        if os.path.isfile(self.target_path):
            if self.target_path.endswith(".py"):
                results.extend(self.scan_file(self.target_path))
        elif os.path.isdir(self.target_path):
            for root, _, files in os.walk(self.target_path):
                for file in files:
                    if file.endswith(".py"):
                        full_path = os.path.join(root, file)
                        results.extend(self.scan_file(full_path))
        return results


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scan_engine.py <target_file_or_directory>")
        sys.exit(1)

    target_path = sys.argv[1]
    scanner = CodeScanner(target_path)
    findings = scanner.execute()

    print(f"\n--- Code Security Scan Results: {target_path} ---")
    if not findings:
        print("No critical vulnerabilities found.")
        sys.exit(0)

    print(f"{'FILE':<35} | {'LINE':<5} | {'RULE':<8} | {'CWE':<8} | {'SEVERITY':<8} | MESSAGE")
    print("-" * 105)
    for f in findings:
        print(
            f"{os.path.basename(f.file_path):<35} | {f.line:<5} | {f.rule_id:<8} | {f.cwe:<8} | {f.severity:<8} | {f.message}"
        )

    sys.exit(1 if any(f.severity == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
