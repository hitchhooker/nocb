use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nocb::{ClipboardManager, Config};
use std::path::PathBuf;
use tokio::signal;

#[derive(Parser)]
#[command(name = "nocb")]
#[command(version = "1.1.2")]
#[command(about = "nearly optimal clipboard manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run clipboard daemon
    Daemon,
    /// Print clipboard history for rofi
    Print,
    /// Copy selection to clipboard (reads from stdin if no args)
    Copy {
        /// Selection text or image reference to copy
        #[arg(trailing_var_arg = true)]
        selection: Vec<String>
    },
    /// Clear clipboard history
    Clear,
    /// Remove entries by hash list
    Prune {
        /// File containing hash list or direct hashes
        #[arg(value_name = "HASHES")]
        input: Vec<String>
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // platform-specific display check
    #[cfg(target_os = "linux")]
    {
        if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
            eprintln!("Error: No display server available (neither X11 nor Wayland)");
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // arboard handles clipboard natively on macos/windows
    }

    let config = Config::load().context("Failed to load configuration")?;

    match cli.command {
        Commands::Daemon => {
            let mut manager = ClipboardManager::new(config).await?;

            tokio::select! {
                result = manager.run_daemon() => {
                    if let Err(e) = result {
                        eprintln!("Daemon error: {}", e);
                        std::process::exit(1);
                    }
                }
                _ = signal::ctrl_c() => {
                    println!("\nShutting down...");
                }
            }
        }
        Commands::Print => {
            let manager = ClipboardManager::new(config).await?;
            manager.print_history()?;
        }
        Commands::Copy { selection } => {
            let selection = if selection.is_empty() {
                use std::io::{self, Read};
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer)?;
                buffer.trim().to_string()
            } else {
                selection.join(" ")
            };

            if selection.is_empty() {
                return Ok(());
            }

            ClipboardManager::send_copy_command(&selection).await?;
        }
        Commands::Clear => {
            let mut manager = ClipboardManager::new(config).await?;
            manager.clear()?;
            println!("Clipboard history cleared");
        }
        Commands::Prune { input } => {
            let mut manager = ClipboardManager::new(config).await?;

            let hashes = if input.len() == 1 && PathBuf::from(&input[0]).exists() {
                let content = std::fs::read_to_string(&input[0])
                    .context("Failed to read hash file")?;
                content.lines().map(|s| s.trim().to_string()).collect()
            } else {
                input
            };

            manager.prune(&hashes)?;
            println!("Pruned {} entries", hashes.len());
        }
    }

    Ok(())
}
