use clap::{Parser, Subcommand};
use sov_core::{load_roles, load_rules, RolesConfig, RuleSet};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sov-admin")]
#[command(about = "CLI администратора СОВ", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    ShowRules {
        #[arg(short, long, default_value = "config/rules.yaml")]
        rules: String,
    },

    UpdateRules {
        #[arg(short, long)]
        from: PathBuf,
        #[arg(short, long, default_value = "config/rules.yaml")]
        to: PathBuf,
    },

    ShowRoles {
        #[arg(short, long, default_value = "config/roles.yaml")]
        roles: String,
    },

    SetRole {
        #[arg(short, long)]
        user: String,
        #[arg(short, long)]
        role: String,
        #[arg(short, long, default_value = "config/roles.yaml")]
        roles: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ShowRules { rules } => {
            let rs: RuleSet = load_rules(&rules)?;
            println!("RuleSet version: {}", rs.version);
            for r in rs.rules {
                println!("- [{}] {} (severity {})", r.id, r.name, r.severity);
            }
        }
        Command::UpdateRules { from, to } => {
            std::fs::copy(&from, &to)?;
            println!("Rules updated from {:?} to {:?}", from, to);
            // TODO: отправить событие на анализатор + записать в аудит
        }
        Command::ShowRoles { roles } => {
            let rc: RolesConfig = load_roles(&roles)?;
            for b in rc.bindings {
                println!("{} => {:?}", b.username, b.role);
            }
        }
        Command::SetRole { user, role, roles } => {
            let mut rc: RolesConfig = load_roles(&roles)?;

            let role_parsed = match role.as_str() {
                "SecurityAdmin" => sov_core::Role::SecurityAdmin,
                "Operator" => sov_core::Role::Operator,
                _ => {
                    eprintln!("Unknown role: {role}");
                    return Ok(());
                }
            };

            if let Some(b) = rc.bindings.iter_mut().find(|b| b.username == user) {
                b.role = role_parsed;
            } else {
                rc.bindings.push(sov_core::RoleBinding {
                    username: user.clone(),
                    role: role_parsed,
                });
            }

            let yaml = serde_yaml::to_string(&rc)?;
            std::fs::write(&roles, yaml)?;
            println!("Role for user {user} set to {role}");

            // TODO: отправить событие role_change на анализатор
        }
    }

    Ok(())
}
