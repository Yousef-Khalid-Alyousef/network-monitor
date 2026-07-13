import time
import os
import threading
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

import traffic_monitor
import config

console = Console()

def _format_bytes(size: int) -> str:
    # Convert bytes to MB/GB
    mb = size / (1024 * 1024)
    if mb > 1024:
        return f"[red]{mb/1024:.2f} GB[/red]"
    elif mb > 500:
        return f"[yellow]{mb:.2f} MB[/yellow]"
    return f"[green]{mb:.2f} MB[/green]"

def generate_table() -> Table:
    table = Table(
        box=box.ROUNDED, 
        expand=True,
        header_style="bold cyan",
        title="[bold blue]Network Monitor V4.1 Dashboard[/bold blue]"
    )
    
    table.add_column("MAC Address", style="dim")
    table.add_column("IP Address", justify="center")
    table.add_column("Device Name", style="magenta")
    table.add_column("Data Usage (This Run)", justify="right")
    table.add_column("Top Port", justify="center")
    table.add_column("Connections (24h)", justify="center")
    table.add_column("Location")
    
    data = traffic_monitor.get_dashboard_data()
    # Sort by bytes used
    data.sort(key=lambda x: x["bytes"], reverse=True)
    
    for row in data:
        port_str = f"{row['top_port'][0].upper()} {row['top_port'][1]}" if row['top_port'] else "N/A"
        
        table.add_row(
            row["mac"],
            row["ip"],
            row["name"],
            _format_bytes(row["bytes"]),
            port_str,
            str(row["connections_24h"]),
            row["location"]
        )
        
    return table

def render_cli():
    # Clear screen for Windows/Linux
    os.system('cls' if os.name == 'nt' else 'clear')
    
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    
    header_text = f"Interface: {config.INTERFACE}  |  Subnet: {config.NETWORK_SUBNET}  |  Limit 1: {config.DATA_LIMIT_ALERT_BYTES / (1024**3):.2f} GB  |  Limit 2: {config.DATA_LIMIT_BLOCK_BYTES / (1024**3):.2f} GB"
    layout["header"].update(Panel(header_text, style="white on blue"))
    
    with Live(layout, console=console, refresh_per_second=2) as live:
        try:
            while True:
                layout["main"].update(generate_table())
                time.sleep(1)
        except KeyboardInterrupt:
            pass
