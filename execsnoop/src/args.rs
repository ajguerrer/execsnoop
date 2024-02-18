use clap::{value_parser, Parser};
use execsnoop_common::{DEFAULT_MAX_ARGS, TOTAL_MAX_ARGS, UID_ALL};

#[derive(Parser, Debug, Clone)]
#[command(version)]
/// Trace exec syscalls
pub struct Args {
    /// Include time column on output (HH:MM:SS)
    #[arg(short = 'T', long)]
    pub time: bool,
    /// Include timestamp on output
    #[arg(short, long)]
    pub timestamp: bool,
    /// Include failed `exec`s
    #[arg(short = 'x', long)]
    pub fails: bool,
    /// Trace this UID only
    #[arg(short, long, default_value_t=UID_ALL)]
    pub uid: u32,
    /// Only print commands matching this name, any arg
    #[arg(short, long)]
    pub name: Option<String>,
    /// Print UID column
    #[arg(short = 'U', long)]
    pub print_uid: bool,
    /// Maximum number of arguments parsed and displayed
    #[arg(long, default_value_t=DEFAULT_MAX_ARGS, value_parser=value_parser!(u32).range(..=i64::from(TOTAL_MAX_ARGS)))]
    pub max_args: u32,
}
