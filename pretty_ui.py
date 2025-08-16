# pretty_ui.py
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from io import StringIO
from time import monotonic
import traceback
import sys
import os

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.traceback import Traceback
from rich.rule import Rule

console = Console(force_terminal=True, soft_wrap=False)

def banner(title: str):
    console.print(Rule(style="bold cyan"))
    console.print(f"[bold cyan]{title}[/bold cyan]")
    console.print(Rule(style="bold cyan"))

class SuiteUI:
    def __init__(self, suite_name: str, show_stdout=True, show_stderr=True):
        self.suite_name = suite_name
        self.show_stdout = show_stdout
        self.show_stderr = show_stderr
        self.results = []  # list of dicts: {name, ok, secs, out, err, err_text}

    def header(self, tests_count: int):
        banner(f"Traffgen: Running suite '{self.suite_name}' ({tests_count} tests)")
        console.print(
            Panel.fit(
                "[b]Tip:[/b] Press [i]Ctrl+C[/i] to stop safely; partial results will still be summarized.",
                title="Run Info",
                border_style="blue",
            )
        )

    @contextmanager
    def run_test(self, name: str):
        out_buf = StringIO()
        err_buf = StringIO()
        start = monotonic()
        ok = False
        err_text = ""

        with Progress(
            SpinnerColumn(style="green"),
            TextColumn("[bold white]Running:[/bold white] {task.description}"),
            TimeElapsedColumn(),
            transient=True,
            console=console,
        ) as progress:
            task_id = progress.add_task(name, start=False)
            progress.start_task(task_id)
            try:
                with redirect_stdout(out_buf), redirect_stderr(err_buf):
                    yield  # run the test body
                ok = True
            except KeyboardInterrupt:
                raise
            except Exception:
                # Capture rich traceback for pretty display later
                err_text = traceback.format_exc()
                ok = False
            finally:
                secs = max(0.0, monotonic() - start)
                self.results.append(
                    {
                        "name": name,
                        "ok": ok,
                        "secs": secs,
                        "out": out_buf.getvalue(),
                        "err": err_buf.getvalue(),
                        "err_text": err_text,
                    }
                )

    def summarize(self):
        passed = sum(1 for r in self.results if r["ok"])
        failed = len(self.results) - passed
        color = "green" if failed == 0 else ("yellow" if passed else "red")
        console.print(Panel.fit(f"[bold {color}]Done[/bold {color}]  "
                                f"[green]{passed} passed[/green], "
                                f"[red]{failed} failed[/red]",
                                title="Summary", border_style=color))

        table = Table(title="Test Results", show_lines=False, expand=True, pad_edge=False)
        table.add_column("#", justify="right", style="dim", width=4)
        table.add_column("Test", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Time", justify="right")
        table.add_column("Notes", overflow="fold")

        for i, r in enumerate(self.results, 1):
            status = "[green]PASS[/green]" if r["ok"] else "[red]FAIL[/red]"
            notes = ""
            if r["ok"]:
                if r["out"].strip():
                    notes = r["out"].strip().splitlines()[-1][:160]
            else:
                if r["err"].strip():
                    notes = r["err"].strip().splitlines()[-1][:160]
                elif r["err_text"]:
                    notes = r["err_text"].strip().splitlines()[-1][:160]
            table.add_row(str(i), r["name"], status, f"{r['secs']:.1f}s", notes)

        console.print(table)

        # Detailed sections for failures (stdout/stderr + traceback)
        failures = [r for r in self.results if not r["ok"]]
        if failures:
            console.print(Rule("[red]Failure Details[/red]"))
            for r in failures:
                console.print(Panel.fit(f"[bold red]{r['name']}[/bold red]", border_style="red"))
                if r["out"].strip():
                    console.print(Panel(r["out"].rstrip(), title="stdout", border_style="cyan"))
                if r["err"].strip():
                    console.print(Panel(r["err"].rstrip(), title="stderr", border_style="magenta"))
                if r["err_text"]:
                    console.print(
                        Traceback.from_exception(
                            *sys.exc_info(),
                            show_locals=False
                        )
                        if hasattr(sys, "_last_traceback_placeholder_never_set")  # never true; keep API parity
                        else Panel(r["err_text"], title="exception", border_style="red")
                    )

def is_interactive() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") not in (None, "dumb")
