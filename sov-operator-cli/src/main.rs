use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "sov-operator")]
#[command(about = "CLI оператора СОВ", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    ShowAlerts {
        #[arg(short, long, default_value = "logs/alerts.log")]
        alerts: String,
    },
    ShowAudit {
        #[arg(short, long, default_value = "logs/audit.log")]
        audit: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ShowAlerts { alerts } => {
            let text = std::fs::read_to_string(alerts)?;
            for line in text.lines() {
                println!("{line}");
            }
        }
        Command::ShowAudit { audit } => {
            let text = std::fs::read_to_string(audit)?;
            for line in text.lines() {
                println!("{line}");
            }
        }
    }

    Ok(())
}
