from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# Define a custom color theme
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "highlight": "bold magenta"
})

console = Console(theme=custom_theme)

class Logger:
    @staticmethod
    def info(msg: str):
        console.print(f"[info][*][/info] {msg}")

    @staticmethod
    def success(msg: str):
        console.print(f"[success][+][/success] {msg}")

    @staticmethod
    def warning(msg: str):
        console.print(f"[warning][!][/warning] {msg}")

    @staticmethod
    def error(msg: str):
        console.print(f"[error][-][/error] {msg}")

    @staticmethod
    def banner(title: str, subtitle: str = ""):
        console.print(Panel(f"[bold cyan]{subtitle}[/bold cyan]", title=f"[bold magenta]{title}[/bold magenta]", expand=False))

    @staticmethod
    def get_progress():
        """Returns a styled Progress context manager for async tasks."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=console
        )
