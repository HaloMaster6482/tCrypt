from __future__ import annotations

import os
import tempfile
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .crypto import (
    DEFAULT_KEY_FILE,
    TcryptionError,
    decode_message_artifact,
    decrypt_bytes,
    encode_message_artifact,
    encrypt_bytes,
    key_file_path,
    load_or_create_key_file,
)

app = typer.Typer(add_completion=False, help="tCrypt locks files and secret messages.", rich_markup_mode="rich")
key_app = typer.Typer(add_completion=False, help="Show the hidden key file.")
app.add_typer(key_app, name="key")

console = Console()


def _banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]tCrypt[/bold cyan]\n[dim]Simple file and message encryption[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def _show_result(title: str, rows: list[tuple[str, str]]) -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Item", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    for left, right in rows:
        table.add_row(left, right)
    console.print(table)


def _confirm_replace(path: Path) -> bool:
    if not path.exists():
        return True

    console.print(
        Panel.fit(
            f"[bold yellow]A file already exists here.[/bold yellow]\n[white]{path}[/white]\n[dim]The existing file will be replaced with the new one.[/dim]",
            title="Replace file?",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )
    return typer.confirm("Replace it?", default=False)


def _atomic_write_bytes(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(delete=False, dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp") as temp_file:
        temp_file.write(data)
        temp_path = Path(temp_file.name)

    os.replace(temp_path, destination)


def _atomic_write_text(destination: Path, text: str) -> None:
    _atomic_write_bytes(destination, text.encode("utf-8"))


def _print_text_result(label: str, text: str, output: Path | None) -> None:
    if output is not None:
        if not _confirm_replace(output):
            raise typer.Exit(code=1)
        _atomic_write_text(output, text)
        _show_result(label, [("Saved to", str(output))])
        return

    console.print(Panel.fit(text, title=label, border_style="green", box=box.ROUNDED))


@key_app.command("path")
def show_key_path() -> None:
    _banner()
    key_path = key_file_path(DEFAULT_KEY_FILE)
    load_or_create_key_file(key_path)
    _show_result("Hidden Key File", [("Path", str(key_path)), ("Status", "Ready")])


@app.command("encrypt-file")
def encrypt_file(
    source: Path = typer.Argument(..., exists=True, readable=True, help="File to lock."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Where to save the locked file."),
    key_file: Path = typer.Option(DEFAULT_KEY_FILE, "--key-file", help="Hidden key file to use."),
) -> None:
    _banner()
    key = load_or_create_key_file(key_file)
    destination = output or source.with_suffix(source.suffix + ".tcrypt")
    if not _confirm_replace(destination):
        raise typer.Exit(code=1)
    artifact = encrypt_bytes("file", source.name, source.read_bytes(), key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(artifact)
    _show_result("File Locked", [("Input", str(source)), ("Output", str(destination)), ("Key file", str(key_file))])


@app.command("decrypt-file")
def decrypt_file(
    artifact: Path = typer.Argument(..., exists=True, readable=True, help="Locked file to open."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Where to save the unlocked file."),
    key_file: Path = typer.Option(DEFAULT_KEY_FILE, "--key-file", help="Hidden key file to use."),
) -> None:
    _banner()
    key = load_or_create_key_file(key_file)
    payload = decrypt_bytes(artifact.read_bytes(), key)
    if payload.kind != "file":
        raise typer.BadParameter("This file was not locked as a file.")

    destination = output or artifact.with_name(payload.name or artifact.stem)
    if not _confirm_replace(destination):
        raise typer.Exit(code=1)
    _atomic_write_bytes(destination, payload.data)
    _show_result("File Opened", [("Input", str(artifact)), ("Output", str(destination)), ("Key file", str(key_file))])


@app.command("encrypt-message")
def encrypt_message(
    message: str = typer.Argument(..., help="Secret message to lock."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save the locked message to a file."),
    key_file: Path = typer.Option(DEFAULT_KEY_FILE, "--key-file", help="Hidden key file to use."),
) -> None:
    _banner()
    key = load_or_create_key_file(key_file)
    artifact = encrypt_bytes("message", None, message.encode("utf-8"), key)
    token = encode_message_artifact(artifact)
    _print_text_result("Encrypted Message", token, output)
    _show_result("Key File", [("Path", str(key_file))])


@app.command("decrypt-message")
def decrypt_message(
    token: str = typer.Argument(..., help="The locked message text."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save the unlocked message to a file."),
    key_file: Path = typer.Option(DEFAULT_KEY_FILE, "--key-file", help="Hidden key file to use."),
) -> None:
    _banner()
    key = load_or_create_key_file(key_file)
    artifact = decode_message_artifact(token)
    payload = decrypt_bytes(artifact, key)
    if payload.kind != "message":
        raise typer.BadParameter("This text was not locked as a message.")

    text = payload.data.decode("utf-8")
    _print_text_result("Decrypted Message", text, output)
    _show_result("Key File", [("Path", str(key_file))])


def main() -> None:
    app()


if __name__ == "__main__":
    main()
