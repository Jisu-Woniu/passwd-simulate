#![allow(dead_code)]

use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

use anyhow::{Error, Result};

use shadow::Shadow;

use crate::crypt::crypt;

pub mod shadow;

/// Read shadow items from the shadow file.
fn read_shadow() -> Result<Vec<Shadow>> {
    let shadow_file = File::options().read(true).open("shadow")?;
    let reader = BufReader::new(shadow_file);

    Ok(reader
        .lines()
        .map(|line| line.unwrap().parse::<Shadow>().unwrap())
        .collect())
}

/// Write shadow items to the shadow file.
pub fn write_shadow(shadow_items: &[Shadow]) -> Result<()> {
    let shadow_file = File::options()
        .truncate(true)
        .create(true)
        .write(true)
        .open("shadow")?;
    let mut writer = BufWriter::new(shadow_file);
    for item in shadow_items {
        writeln!(writer, "{}", item)?;
    }
    Ok(())
}

/// Check if user has password using the shadow file.
pub fn user_has_password(username: &str) -> Result<bool> {
    let shadow_item = read_shadow()?
        .into_iter()
        .find(|item| item.username == username)
        .ok_or_else(|| Error::msg("No such user in database"))?;
    Ok(shadow_item.hashed_password.is_some())
}

/// Verify password using the shadow file.
pub fn verify_password(username: &str, password: &str) -> Result<()> {
    let shadow_item = read_shadow()?
        .into_iter()
        .find(|item| item.username == username)
        .ok_or_else(|| Error::msg("No such user in database"))?;
    match shadow_item.hashed_password {
        None => Ok(()), // If hashed password is empty, allow login.
        Some(hashed_password) => {
            if hashed_password.starts_with('!') {
                Err(Error::msg("Password mismatch."))
            } else if crypt(password.as_ref(), hashed_password.as_bytes())? == hashed_password {
                Ok(())
            } else {
                Err(Error::msg("Password mismatch."))
            }
        }
    }
}

/// Update password in the shadow file.
pub fn update_password(username: &str, hashed_password: &str) -> Result<()> {
    let mut shadow_items: Vec<_> = read_shadow()?.into_iter().collect();
    let shadow_item = shadow_items
        .iter_mut()
        .find(|item| item.username == username)
        .ok_or_else(|| Error::msg("No such user in database"))?;
    shadow_item.update_password(Some(hashed_password.to_string()));
    write_shadow(&shadow_items)?;
    Ok(())
}

/// Lock account by changing password in the shadow file.
pub fn lock_account(username: &str) -> Result<()> {
    let mut shadow_items: Vec<_> = read_shadow()?.into_iter().collect();
    let shadow_item = shadow_items
        .iter_mut()
        .find(|item| item.username == username)
        .ok_or_else(|| Error::msg("No such user in database"))?;
    match &shadow_item.hashed_password {
        None => shadow_item.update_password(Some("!".to_string())),
        Some(s) if !s.starts_with('!') => shadow_item.update_password(Some(format!("!{}", s))),
        // Already locked, do nothing.
        _ => {}
    }
    write_shadow(&shadow_items)?;
    Ok(())
}

/// Unlock account by changing password in the shadow file.
pub fn unlock_account(username: &str) -> Result<()> {
    let mut shadow_items: Vec<_> = read_shadow()?.into_iter().collect();
    let shadow_item = shadow_items
        .iter_mut()
        .find(|item| item.username == username)
        .ok_or_else(|| Error::msg("No such user in database"))?;
    match &shadow_item.hashed_password {
        Some(s) if s.starts_with('!') => {
            shadow_item.update_password(Some(s.trim_start_matches('!').to_string()))
        }
        _ => {}
    }
    write_shadow(&shadow_items)?;
    Ok(())
}

/// Delete a user's password in the shadow file.
pub fn delete_password(username: &str) -> Result<()> {
    let mut shadow_items: Vec<_> = read_shadow()?.into_iter().collect();
    let shadow_item = shadow_items
        .iter_mut()
        .find(|item| item.username == username)
        .ok_or_else(|| Error::msg("No such user in database"))?;
    shadow_item.update_password(None);
    write_shadow(&shadow_items)?;
    Ok(())
}

/// Get all usernames from the shadow file.
pub fn is_valid_user(username: &str) -> Result<bool> {
    Ok(read_shadow()?
        .into_iter()
        .map(|item| item.username)
        .find(|user| user == username)
        .is_some())
}
