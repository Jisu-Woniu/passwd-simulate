use std::fmt::Debug;

use anyhow::{Context, Error, Result};
use clap::{Args, Parser};
use rand::thread_rng;

use rpassword::prompt_password;
use users::{get_current_uid, get_current_username};

use crypt::{crypt, salt::make_salt};

use store::{
    delete_password, is_valid_user, lock_account, unlock_account, update_password,
    user_has_password, verify_password,
};

mod crypt;
mod store;

/// My `passwd` impl: A program to simulate `passwd` behavior on UNIX-like systems.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct PasswdArgs {
    #[command(flatten)]
    operation: Operation,

    /// The user you want to change password.
    #[arg(default_value_t = get_username_unwrap())]
    username: String,
}

fn get_username_unwrap() -> String {
    get_current_username().unwrap().into_string().unwrap()
}

#[derive(Args, Clone, Debug)]
#[group(required = false, multiple = false)]
struct Operation {
    /// Lock the account
    #[arg(short = 'l', long = "lock")]
    lock: bool,

    /// Unlock the account.
    #[arg(short = 'u', long = "unlock")]
    unlock: bool,

    /// Delete password of the account.
    #[arg(short = 'd', long = "delete")]
    delete: bool,
}

/// Entry point of program.
fn main() -> Result<()> {
    // Detect username
    let args = PasswdArgs::parse();
    let username = args.username;

    if is_valid_user(&username)? {
        Err(Error::msg(format!("user '{}' does not exist", username)))?;
    }

    println!("Setting password for: {}", username);

    if get_current_uid() != 0 && user_has_password(&username)? {
        let old_password = prompt_password("Current password: ")
            .with_context(|| "Password change has been aborted.")?;
        verify_password(&username, &old_password).with_context(|| "Authentication failure.")?
    }

    match args.operation {
        Operation { lock: true, .. } => lock_account(&username)?,
        Operation { unlock: true, .. } => unlock_account(&username)?,
        Operation { delete: true, .. } => delete_password(&username)?,
        Operation { .. } => {
            let password = prompt_password("New password: ")
                .with_context(|| "Password change has been aborted.")?;
            let password_confirm = prompt_password("Retype new password: ")
                .with_context(|| "Password change has been aborted.")?;
            if password != password_confirm {
                Err(Error::msg("Sorry, passwords do not match."))?;
            } else if password.is_empty() {
                Err(Error::msg("No password has been supplied."))?;
            }
            let encrypted = crypt(
                password.as_bytes(),
                format!("$6${}", String::from_utf8(make_salt(16, thread_rng()))?).as_bytes(),
            );
            update_password(&username, &encrypted.with_context(|| "Encryption failed")?)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_cli() {
        use super::PasswdArgs;
        use clap::CommandFactory;
        PasswdArgs::command().debug_assert()
    }
}
