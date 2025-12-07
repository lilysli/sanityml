import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple, Optional, Set


class ToolError(Exception):
    """Raised when a required tool is missing or fails critically."""
    pass


def discover_targets(
    target: Path,
    scan_notebooks: bool = True,
    scan_python: bool = True,
    scan_deps: bool = True,
    scan_models: bool = True,
) -> dict:
    """Discover files to scan. Returns dict with lists/paths."""
    results = {}

    if scan_python:
        results["py_files"] = sorted(target.rglob("*.py"))
    if scan_notebooks:
        results["notebooks"] = sorted(target.rglob("*.ipynb"))
    if scan_deps:
        req_file = target / "requirements.txt"
        results["requirements"] = req_file if req_file.exists() else None
    if scan_models:
        model_exts = ["*.pt", "*.pth", "*.pkl", "*.joblib", "*.h5", "*.safetensors"]
        models = {p for ext in model_exts for p in target.rglob(ext)}
        results["models"] = sorted(models)

    return results


def notebook_to_python(notebook_path: Path, output_path: Path) -> None:
    """Convert .ipynb to .py (only code cells). Raises on error."""
    try:
        data = notebook_path.read_text(encoding="utf-8")
        nb = json.loads(data)
        cells = nb.get("cells", [])
        if not cells:
            raise ValueError("No cells in notebook")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# Converted from {notebook_path.name}\n")
            code_found = False
            for i, cell in enumerate(cells):
                if cell.get("cell_type") == "code":
                    source = cell.get("source", [])
                    if isinstance(source, str):
                        lines = source.splitlines(keepends=True)
                    elif isinstance(source, list):
                        lines = source
                    else:
                        continue

                    # Skip empty or comment-only cells
                    if lines and any(line.strip() and not line.strip().startswith("#") for line in lines):
                        code_found = True
                        f.write(f"\n# --- Cell {i+1} ---\n")
                        f.writelines(lines)
                        f.write("\n")

            if not code_found:
                raise ValueError("No executable code in notebook")

    except Exception as e:
        raise RuntimeError(f"Conversion failed for {notebook_path.name}: {type(e).__name__}: {e}")


def run_tool(
    cmd: List[str],
    *, 
    label: str = "Running",
    timeout: int = 120,
) -> Tuple[str, int]:
    """Run subprocess, return (output, exit_code). Never raises; safe for CLI."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        output = stdout or stderr
        return output, result.returncode

    except FileNotFoundError:
        cmd_name = cmd[0]
        return f"'{cmd_name}' not found. Try: `pip install {cmd_name}`", -1
    except subprocess.TimeoutExpired:
        return "timed out", -1
    except Exception as e:
        return f"unexpected error: {e}", -1


def scan_python_files(target_paths: List[Path], label: str = "Scanning Python files") -> Tuple[str, int]:
    if not target_paths:
        return "⏩ No Python files to scan", 0
    paths = [str(p) for p in target_paths]
    return run_tool(["bandit", "-r"] + paths + ["-f", "txt"], label=label)


def scan_notebooks(notebooks: List[Path], label: str = "Scanning notebooks") -> Tuple[str, int, List[str]]:
    """Returns (output, code, errors)"""
    if not notebooks:
        return "⏩ No notebooks to scan", 0, []

    errors = []
    py_files_nb = []

    with tempfile.TemporaryDirectory() as tmpdir:
        for nb in notebooks:
            py_path = Path(tmpdir) / f"{nb.stem}_{nb.parent.name}.py"
            try:
                notebook_to_python(nb, py_path)
                if py_path.exists() and py_path.stat().st_size > 30:
                    py_files_nb.append(py_path)
            except Exception as e:
                errors.append(str(e))

        if errors:
            error_summary = "\n".join(f"⚠ {err}" for err in errors)
        else:
            error_summary = ""

        if py_files_nb:
            output, code = run_tool(
                ["bandit", "-r"] + [str(p) for p in py_files_nb] + ["-f", "txt"],
                label=label
            )
            return f"{error_summary}\n{output}".strip(), code, errors
        else:
            if not errors:
                return "⚠ No executable code in notebooks", 0, []
            return error_summary, 0, errors


def scan_dependencies(req_file: Optional[Path], label: str = "Scanning dependencies") -> Tuple[str, int]:
    if not req_file:
        return "⏩ No requirements.txt", 0
    return run_tool(["pip-audit", "-r", str(req_file)], label=label)


def scan_models(models: List[Path], label: str = "Scanning models") -> Tuple[str, int]:
    if not models:
        return "⏩ No model files to scan", 0
    paths = [str(m) for m in models]
    return run_tool(["modelscan", "-p"] + paths, label=label)


def generate_report_summary(
    py_files: List[Path],
    notebooks: List[Path],
    models: List[Path],
    req_exists: bool,
    duration: float,
    any_issue: bool,
    any_error: bool,
) -> str:
    py_f = "file" if len(py_files) == 1 else "files"
    nb_f = "notebook" if len(notebooks) == 1 else "notebooks"
    md_f = "model" if len(models) == 1 else "models"
    req_text = "1 requirements.txt" if req_exists else "no requirements.txt"

    status = (
        "🚨 Issues detected." if any_issue else
        "⚠️  Scan completed with tool errors." if any_error else
        "✅ All checks passed."
    )

    summary = f"""\
{status}
🔍 {len(py_files)} python {py_f}, {len(notebooks)} {nb_f}, {len(models)} {md_f}, {req_text} scanned
⏱  Completed in {duration:.1f}s
"""
    return summary