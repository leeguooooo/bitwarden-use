use std::io::Write as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod sock;
mod upgrade;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(
    name = "bitwarden-use",
    version,
    about = "Bitwarden/Vaultwarden CLI with FIDO2 (passkey) extraction"
)]
enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login {
        #[arg(long)]
        domain: Option<String>,
        #[arg(long, requires = "domain")]
        name: Option<String>,
        #[arg(long, requires = "domain")]
        user: Option<String>,
        #[arg(long, requires = "domain")]
        reveal: bool,
    },

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock {
        #[arg(long, conflicts_with = "keychain_store")]
        keychain: bool,
        /// Verify the master password via pinentry, then store it in the macOS login keychain.
        #[arg(long)]
        keychain_store: bool,
    },

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[arg(long, visible_alias = "json", conflicts_with_all = ["field", "full", "codes", "list_fields"], help = "Structured fields; masked unless --reveal")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[structopt(short, long, help = "Copy result to clipboard")]
        #[arg(requires = "reveal", conflicts_with_all = ["raw", "codes", "full", "list_fields"])]
        clipboard: bool,
        #[structopt(short, long, help = "List fields in this entry")]
        list_fields: bool,
        #[arg(long)]
        reveal: bool,
        #[arg(long, conflicts_with_all = ["field", "full", "list_fields"])]
        codes: bool,
    },

    #[command(
        about = "Run a command with secrets in its environment (values never printed)",
        long_about = "Run a command with vault secrets injected as environment variables.\n\n\
            Each --env is VAR=ITEM[#FIELD]: ITEM is a name, URI, UUID or bw:<uuid>; FIELD defaults \
            to the password (password, username, notes, totp or custom:<name>). Values go only to \
            the child process. Items outside reveal_folders ask for confirmation first, and every \
            item is written to the reveal audit log.\n\n\
            Example: bitwarden-use run --env GH_TOKEN='github token' -- gh api user"
    )]
    Run {
        #[arg(
            long = "env",
            value_name = "VAR=ITEM[#FIELD]",
            required = true
        )]
        env: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
            remainder will be saved as a note."
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[command(flatten)]
        write: commands::WriteOptions,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[arg(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
        #[command(flatten)]
        write: commands::WriteOptions,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
        #[command(flatten)]
        write: commands::WriteOptions,
    },

    #[command(
        about = "Update selected login fields; preview values safely before saving"
    )]
    Set {
        #[command(flatten)]
        find_args: FindArgs,
        #[command(flatten)]
        fields: commands::SetFields,
        #[command(flatten)]
        write: commands::WriteOptions,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
        #[command(flatten)]
        write: commands::WriteOptions,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Lock the password database")]
    Lock,

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(
        about = "Manage FIDO2 (passkey) credentials stored in the database"
    )]
    Fido2 {
        #[command(subcommand)]
        fido2: Fido2,
    },

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },

    #[command(
        about = "Upgrade bitwarden-use (CLI + agent) to the latest release",
        long_about = "Upgrade bitwarden-use and bitwarden-use-agent to the \
            latest GitHub release through install.sh (sha256-verified, \
            swapped in atomically; on failure the installed pair is kept), \
            into the directory this binary runs from. Refuses, changing \
            nothing, when the binary came from cargo, Homebrew, a source \
            build or anything install.sh did not lay out, and prints the \
            right command instead. Never unlocks or touches the vault, \
            config or the running agent; a running agent keeps the old \
            version until `stop-agent`.\n\n\
            Skill copies (Claude Code plugin, git checkout, npx skills \
            folder) are listed, and refreshed only with --skills.\n\n\
            Exit codes: 0 success (also: already current, or a check that \
            ran), 2 the check or download failed, 1 not upgraded here \
            (other install channel) or the upgrade did not finish."
    )]
    Upgrade {
        #[arg(long, help = "Only report current -> latest; change nothing")]
        check: bool,
        #[arg(
            long,
            help = "Like --check, as JSON (skills, install channel, agent)"
        )]
        json: bool,
        #[arg(
            long,
            help = "Also refresh this tool's own skill copies (plugin, git \
                    checkout); with the CLI current, only the skills"
        )]
        skills: bool,
        #[arg(
            long,
            value_name = "vX.Y.Z",
            help = "Install this release instead of the latest (downgrade \
                    allowed)"
        )]
        tag: Option<String>,
    },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login { .. } => "login".to_string(),
            Self::Unlock { .. } => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Run { .. } => "run".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Set { .. } => "set".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::Fido2 { fido2 } => {
                format!("fido2 {}", fido2.subcommand_name())
            }
            Self::StopAgent => "stop-agent".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
            Self::Upgrade { .. } => "upgrade".to_string(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Parser)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show,
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Parser)]
enum Fido2 {
    #[command(
        about = "List passkeys stored in the database \
            (entry name, rpId, credentialId)",
        visible_alias = "ls"
    )]
    List,
    #[command(
        about = "Display a passkey; the private key only with --reveal",
        long_about = "Display a passkey; the private key only with --reveal\n\n\
            Prints the credentialId, rpId, userHandle, keyType and keyCurve. \
            With --reveal (and Touch ID when reveal_folders is set) it also \
            prints the decrypted private key as base64url and as a PKCS#8 PEM \
            document. Prefer `fido2 assert`, which signs without exporting \
            the key. The entry can be selected by name, URI, UUID, or by the \
            credentialId of the passkey itself."
    )]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "Print the decrypted private key (audited)")]
        reveal: bool,
    },
    #[command(
        about = "Sign a WebAuthn assertion with a stored passkey; the private key never leaves the process",
        long_about = "Sign a WebAuthn assertion with a stored passkey\n\n\
            Builds authenticatorData (SHA-256 of the rpId, flags, counter) and \
            signs authenticatorData || clientDataHash with the passkey's P-256 \
            key (ES256). Prints JSON with the base64url authenticatorData and \
            DER signature. This is the getAssertion half of an authenticator; \
            unlike `fido2 get` it never exports the private key, so a platform \
            bridge can pass a challenge in and a signature out."
    )]
    Assert {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Relying party id; defaults to the credential's stored rpId"
        )]
        rp_id: Option<String>,
        #[arg(
            long,
            help = "SHA-256 of the clientDataJSON, 32 bytes as hex or base64url"
        )]
        client_data_hash: String,
        #[arg(
            long,
            help = "Signature counter to report; defaults to the stored counter (0 for synced passkeys)"
        )]
        counter: Option<u32>,
        #[arg(
            long,
            help = "Set the UV (user verified) flag in addition to UP"
        )]
        uv: bool,
    },
}

impl Fido2 {
    fn subcommand_name(&self) -> String {
        match self {
            Self::List => "list",
            Self::Get { .. } => "get",
            Self::Assert { .. } => "assert",
        }
        .to_string()
    }
}

fn main() {
    let opt = Opt::parse();

    // Once-a-day "new version" line on stderr; never touches the vault.
    // clap has already exited for --help / --version.
    upgrade::maybe_notify(matches!(opt, Opt::Upgrade { .. }));

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let subcommand_name = opt.subcommand_name();
    let res = match opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show(),
            Config::Set { key, value } => commands::config_set(&key, &value),
            Config::Unset { key } => commands::config_unset(&key),
        },
        Opt::Register => commands::register(),
        Opt::Login {
            domain,
            name,
            user,
            reveal,
        } => match domain {
            Some(domain) => commands::domain_login(
                &domain,
                name.as_deref(),
                user.as_deref(),
                reveal,
            ),
            None => commands::login(),
        },
        Opt::Unlock {
            keychain,
            keychain_store,
        } => {
            if keychain || keychain_store {
                commands::unlock_keychain(keychain_store)
            } else {
                commands::unlock()
            }
        }
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync => commands::sync(),
        Opt::List { fields, raw } => commands::list(&fields, raw),
        Opt::Get {
            find_args,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
            reveal,
            codes,
        } => commands::get(
            find_args.needle.clone(),
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            list_fields,
            reveal,
            codes,
        ),
        Opt::Run {
            env,
            folder,
            command,
        } => commands::run(&env, folder.as_deref(), &command),
        Opt::Search {
            term,
            fields,
            folder,
            raw,
        } => commands::search(&term, &fields, folder.as_deref(), raw),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
        ),
        Opt::Add {
            name,
            user,
            uri,
            folder,
            write,
        } => commands::add(
            &name,
            user.as_deref(),
            &uri.iter()
                // XXX not sure what the ui for specifying the match type
                // should be
                .map(|uri| (uri.clone(), None))
                .collect::<Vec<_>>(),
            folder.as_deref(),
            &write,
        ),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
            write,
        } => {
            let ty = if no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if only_numbers {
                rbw::pwgen::Type::Numbers
            } else if nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                len,
                ty,
                &write,
            )
        }
        Opt::Edit { find_args, write } => commands::edit(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            &write,
        ),
        Opt::Set {
            find_args,
            fields,
            write,
        } => commands::set(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            fields,
            &write,
        ),
        Opt::Remove { find_args, write } => commands::remove(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            &write,
        ),
        Opt::History { find_args } => commands::history(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Lock => commands::lock(),
        Opt::Purge => commands::purge(),
        Opt::Fido2 { fido2 } => match fido2 {
            Fido2::List => commands::fido2_list(),
            Fido2::Assert {
                find_args,
                rp_id,
                client_data_hash,
                counter,
                uv,
            } => commands::fido2_assert(
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                rp_id.as_deref(),
                &client_data_hash,
                counter,
                uv,
            ),
            Fido2::Get { find_args, reveal } => commands::fido2_get(
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                reveal,
            ),
        },
        Opt::StopAgent => commands::stop_agent(),
        Opt::Upgrade {
            check,
            json,
            skills,
            tag,
        } => std::process::exit(upgrade::run(&upgrade::Options {
            check,
            json,
            skills,
            tag,
        })),
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
    }
    .with_context(|| format!("rbw {subcommand_name}"));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    #[test]
    fn command_schema_and_new_interfaces() {
        Opt::command().debug_assert();
        for args in [
            vec![
                "bwu",
                "set",
                "item",
                "--uri-add",
                "https://example.com",
                "--match",
                "host",
                "--dry-run",
            ],
            vec!["bwu", "set", "item", "--totp", "JBSWY3DPEHPK3PXP", "--yes"],
            vec!["bwu", "get", "item", "--json", "--reveal"],
            vec!["bwu", "get", "item", "--codes"],
            vec![
                "bwu",
                "login",
                "--domain",
                "example.com",
                "--name",
                "item",
                "--user",
                "user",
                "--reveal",
            ],
            vec!["bwu", "unlock", "--keychain"],
            vec!["bwu", "edit", "item", "--allow-empty", "--yes"],
            vec!["bwu", "upgrade"],
            vec!["bwu", "upgrade", "--check"],
            vec!["bwu", "upgrade", "--json"],
        ] {
            assert!(Opt::try_parse_from(args).is_ok());
        }
        for args in [
            vec![
                "bwu",
                "set",
                "item",
                "--uri",
                "https://example.com",
                "--uri-add",
                "https://other.com",
            ],
            vec!["bwu", "set", "item", "--yes", "--dry-run"],
            vec!["bwu", "login", "--reveal"],
            vec!["bwu", "get", "item", "--json", "--field", "notes"],
            vec!["bwu", "unlock", "--keychain", "--keychain-store"],
        ] {
            assert!(Opt::try_parse_from(args).is_err());
        }
    }
}
