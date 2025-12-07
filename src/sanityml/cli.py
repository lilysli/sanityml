import time
import sys
from pathlib import Path
import click

from .core import (
    discover_targets,
    scan_python_files,
    scan_notebooks,
    scan_dependencies,
    scan_models,
    generate_report_summary,
)


def hr(char="─", width=60, color="bright_white"):
    line = char * width
    click.secho(f"{line}", fg=color, dim=True)


def _print_discovery(discovery: dict):
    click.secho("──[ 🔍 Discovery ]──", fg="bright_cyan", bold=True)
    hr()

    py_files = discovery.get("py_files", [])
    notebooks = discovery.get("notebooks", [])
    req_file = discovery.get("requirements")
    models = discovery.get("models", [])

    if notebooks:
        click.secho(f"📓 Notebooks ({len(notebooks)})", fg="bright_blue", bold=True)
        for nb in notebooks[:10]:
            click.secho(f"   • {nb.name}", fg="bright_blue")
        if len(notebooks) > 10:
            click.secho(f"   • ... (+{len(notebooks) - 10} more)", dim=True)
    else:
        click.secho("📓 Notebooks: 0", dim=True)

    if py_files:
        click.secho(f"🐍 Python files ({len(py_files)})", fg="bright_green", bold=True)
        for py in py_files[:10]:
            click.secho(f"   • {py.name}", fg="bright_green")
        if len(py_files) > 10:
            click.secho(f"   • ... (+{len(py_files) - 10} more)", dim=True)
    else:
        click.secho("🐍 Python files: 0", dim=True)

    if req_file:
        click.secho("📦 Dependencies (1)", fg="bright_yellow", bold=True)
        click.secho(f"   • requirements.txt", fg="bright_yellow")
    else:
        click.secho("📦 Dependencies: 0", dim=True)

    if models:
        click.secho(f"🧠 Models ({len(models)})", fg="magenta", bold=True)
        for model in models[:10]:
            click.secho(f"   • {model.name}", fg="magenta")
        if len(models) > 10:
            click.secho(f"   • ... (+{len(models) - 10} more)", dim=True)
    else:
        click.secho("🧠 Models: 0", dim=True)

    hr()
    click.echo()


def _print_scan_section(
    title: str,
    output: str,
    code: int,
    *,
    is_notebook: bool = False,
):
    click.secho(title, fg="bright_white", bold=True)
    hr("─", 40, "bright_white")

    lines = output.splitlines() if output else []
    if not lines:
        click.secho("│ ⏩ Nothing to report", dim=True)
        click.echo()
        return

    for line in lines:
        if not line.strip():
            continue
        if "not found" in line or line.startswith("⚠") or line.startswith("⏩"):
            click.secho(f"│ {line}", fg="white")
        elif "UNSAFE" in line or "risk" in line.lower() or "CVE-" in line or "PYSEC-" in line:
            click.secho(f"│ {line}", fg="white")
        else:
            click.secho(f"│  {line}", fg="white")

    click.echo()
    return code == 1, code >= 2  # (has_issue, has_error)


@click.command()
@click.argument("target", type=click.Path(exists=True, file_okay=False))
@click.option("--full", is_flag=True, help="Scan all (default if no flags given).")
@click.option("--python", is_flag=True, help="Scan .py files.")
@click.option("--notebooks", is_flag=True, help="Scan .ipynb files.")
@click.option("--deps", "--dependencies", is_flag=True, help="Scan requirements.txt.")
@click.option("--models", is_flag=True, help="Scan model files (.pt, .pkl, etc.).")
def main(target, full, python, notebooks, deps, models):
    target = Path(target).resolve()
    start_time = time.time()
    
    # Determine scan types
    any_granular = python or notebooks or deps or models
    do_scan_python = python or (not any_granular)
    do_scan_notebooks = notebooks or (not any_granular)
    do_scan_deps = deps or (not any_granular)
    do_scan_models = models or (not any_granular)

    # Banner
    click.echo()
    click.secho("  ⚙️   ", nl=False)
    click.secho("sanityML", fg="bright_green", bold=True)
    click.secho("  ──  vulnerabilities scanner for ML projects", fg="bright_green")
    click.echo()

    # Discovery
    discovery = discover_targets(
        target,
        scan_notebooks=do_scan_notebooks,
        scan_python=do_scan_python,
        scan_deps=do_scan_deps,
        scan_models=do_scan_models,
    )
    _print_discovery(discovery)

    # Scan Phase
    click.secho("──[ 🛡️  Scan ]──", fg="bright_cyan", bold=True)
    hr()
    click.echo()

    any_issue = False
    any_error = False

    # Python
    if do_scan_python:
        output, code = scan_python_files(discovery.get("py_files", []))
        issue, error = _print_scan_section("🐍 bandit — Python code", output, code)
        any_issue |= issue
        any_error |= error

    # Notebooks
    if do_scan_notebooks:
        output, code, _ = scan_notebooks(discovery.get("notebooks", []))
        issue, error = _print_scan_section("📓 bandit — Notebooks", output, code, is_notebook=True)
        any_issue |= issue
        any_error |= error

    # Dependencies
    if do_scan_deps:
        output, code = scan_dependencies(discovery.get("requirements"))
        issue, error = _print_scan_section("📦 pip-audit — Dependencies", output, code)
        any_issue |= issue
        any_error |= error

    # Models
    if do_scan_models:
        output, code = scan_models(discovery.get("models", []))
        issue, error = _print_scan_section("🧠 modelscan — Models", output, code)
        any_issue |= issue
        any_error |= error

    hr()
    click.echo()

    # Report
    click.secho("──[ 📊 Report ]──", fg="bright_cyan", bold=True)
    hr()

    summary = generate_report_summary(
        py_files=discovery.get("py_files", []),
        notebooks=discovery.get("notebooks", []),
        models=discovery.get("models", []),
        req_exists=bool(discovery.get("requirements")),
        duration=time.time() - start_time,
        any_issue=any_issue,
        any_error=any_error,
    )
    click.echo(summary)
    hr()

    sys.exit(1 if any_issue or any_error else 0)


if __name__ == "__main__":
    main()