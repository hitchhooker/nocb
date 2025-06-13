use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nocb::{ClipboardManager, Config};
use std::path::PathBuf;
use tokio::signal;

#[derive(Parser)]
#[command(name = "nocb")]
#[command(version = "1.0.0")]
#[command(about = "Nearly optimal clipboard manager")]
#[command(long_about = "A fast, efficient clipboard manager with X11 integration")]
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
    /// Copy selection to clipboard  
    Copy { 
        /// Selection text or image reference to copy
        selection: String 
    },
    /// Clear clipboard history
    Clear,
    /// Remove entries by hash list
    Prune { 
        /// File containing hash list or direct hashes
        #[arg(value_name = "HASHES")]
        input: Vec<String> 
    },
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // check X11 display
    if std::env::var("DISPLAY").is_err() {
        eprintln!("Error: X display not available. Please start Xorg first.");
        std::process::exit(1);
    }

    // load config
    let config = Config::load().context("Failed to load configuration")?;
    
    match cli.command {
        Commands::Version => {
            println!("nocb v1.0.0 - Nearly Optimal Clipboard Manager");
            println!("Fast clipboard manager with X11 integration");
            return Ok(());
        }
        Commands::Daemon => {
            println!("Starting nocb daemon...");
            let mut manager = ClipboardManager::new(config).await?;
            
            tokio::select! {
                result = manager.run() => {
                    if let Err(e) = result {
                        eprintln!("Daemon error: {}", e);
                        std::process::exit(1);
                    }
                }
                _ = signal::ctrl_c() => {
                    println!("Shutting down gracefully...");
                }
            }
        }
        Commands::Print => {
            let manager = ClipboardManager::new(config).await?;
            let _ = manager.print_history();
        }
        Commands::Copy { selection } => {
            let mut manager = ClipboardManager::new(config).await?;
            manager.copy_selection(&selection).await?;
        }
        Commands::Clear => {
            let mut manager = ClipboardManager::new(config).await?;
            manager.clear()?;
            println!("Clipboard history cleared");
        }
        Commands::Prune { input } => {
            let mut manager = ClipboardManager::new(config).await?;
            
            // check if input is a file or direct hashes
            let hashes = if input.len() == 1 && PathBuf::from(&input[0]).exists() {
                let content = std::fs::read_to_string(&input[0])
                    .context("Failed to read hash file")?;
                content.lines().map(|s| s.trim().to_string()).collect()
            } else {
                // direct hash arguments
                input
            };
            
            manager.prune(&hashes)?;
            println!("Pruned {} entries", hashes.len());
        }
    }

    Ok(())
}
