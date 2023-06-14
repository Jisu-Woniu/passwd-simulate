use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use anyhow::Error;
use chrono::{Duration, Local, NaiveDate};

/// Shadow file entry
#[derive(Debug, Clone)]
pub struct Shadow {
    /// Username
    pub(crate) username: String,

    /// Hashed password. Normally, it should be result of crypt(), but can be anything else such as "!" for locked account.
    pub(crate) hashed_password: Option<String>,

    /// Date of last password change, expressed as the number of days since Jan 1, 1970 in file.
    last_updated: Option<NaiveDate>,

    /// Minimum number of days between password changes.
    min_age: Option<usize>,

    /// Maximum number of days between password changes.
    max_age: Option<usize>,

    /// Number of days before password expires to warn user to change it.
    warning_period: Option<usize>,

    /// Number of days after password expires until account is disabled.
    inactivity_period: Option<usize>,

    /// Date when account expires, expressed as the number of days since Jan 1, 1970 in file.
    account_exp_date: Option<NaiveDate>,

    /// Reserved for future use.
    reserved: Option<String>,
}

impl Shadow {
    /// Update password and set last_updated field accordingly.
    pub(crate) fn update_password(&mut self, new_hashed_password: Option<String>) {
        self.hashed_password = new_hashed_password;
        self.last_updated = Some(Local::now().date_naive());
    }
}

impl Display for Shadow {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.username,
            self.hashed_password.as_deref().unwrap_or_default(),
            self.last_updated
                .map(|date| (date - epoch_date()).num_days().to_string())
                .as_deref()
                .unwrap_or(""),
            self.min_age.map(|x| x.to_string()).as_deref().unwrap_or(""),
            self.max_age.map(|x| x.to_string()).as_deref().unwrap_or(""),
            self.warning_period
                .map(|x| x.to_string())
                .as_deref()
                .unwrap_or(""),
            self.inactivity_period
                .map(|x| x.to_string())
                .as_deref()
                .unwrap_or(""),
            self.account_exp_date
                .map(|date| (date - epoch_date()).num_days().to_string())
                .as_deref()
                .unwrap_or(""),
            self.reserved.as_deref().unwrap_or("")
        )
    }
}

// static EPOCH_DATE: NaiveDate = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();

fn epoch_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()
}

impl FromStr for Shadow {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_split: Vec<_> = s.trim().split(':').collect();
        if s_split.len() < 9 {
            Err(Error::msg("Bad format."))?
        }
        let mut s_split_iter = s_split.iter().cloned();
        let shadow_builder = ShadowBuilder::new()
            .username(s_split_iter.next())
            .hashed_password(s_split_iter.next());
        shadow_builder
            .build()
            .ok_or_else(|| Error::msg("Unknown error."))
    }
}

/// A builder for `Shadow` struct allowing partial setting
pub struct ShadowBuilder {
    username: Option<String>,
    hashed_password: Option<String>,
    last_updated: Option<NaiveDate>,
    min_age: Option<usize>,
    max_age: Option<usize>,
    warning_period: Option<usize>,
    inactivity_period: Option<usize>,
    account_exp_date: Option<NaiveDate>,
    reserved: Option<String>,
}

impl ShadowBuilder {
    pub fn new() -> Self {
        ShadowBuilder {
            username: None,
            hashed_password: None,
            last_updated: None,
            min_age: None,
            max_age: None,
            warning_period: None,
            inactivity_period: None,
            account_exp_date: None,
            reserved: None,
        }
    }

    fn str_to_owned(input: Option<&str>) -> Option<String> {
        match input {
            Some(username) if !username.is_empty() => Some(username.to_string()),
            _ => None,
        }
    }

    fn parse_date(input: Option<&str>) -> Option<NaiveDate> {
        match input {
            Some(input) if !input.is_empty() => input
                .parse()
                .ok()
                .map(|days_since_epoch| (epoch_date() + Duration::days(days_since_epoch))),
            _ => None,
        }
    }

    fn parse_int(input: Option<&str>) -> Option<usize> {
        match input {
            Some(input) if !input.is_empty() => input.parse().ok(),
            _ => None,
        }
    }

    pub fn username(mut self, username: Option<&str>) -> Self {
        self.username = Self::str_to_owned(username);
        self
    }

    pub fn hashed_password(mut self, hashed_password: Option<&str>) -> Self {
        self.hashed_password = Self::str_to_owned(hashed_password);
        self
    }

    pub fn last_updated(mut self, last_updated: Option<&str>) -> Self {
        self.last_updated = Self::parse_date(last_updated);
        self
    }

    pub fn min_age(mut self, min_age: Option<&str>) -> Self {
        self.min_age = Self::parse_int(min_age);
        self
    }

    pub fn max_age(mut self, max_age: Option<&str>) -> Self {
        self.max_age = Self::parse_int(max_age);
        self
    }

    pub fn warning_period(mut self, warning_period: Option<&str>) -> Self {
        self.warning_period = Self::parse_int(warning_period);
        self
    }

    pub fn inactivity_period(mut self, inactivity_period: Option<&str>) -> Self {
        self.inactivity_period = Self::parse_int(inactivity_period);
        self
    }

    pub fn account_exp_date(mut self, account_exp_date: Option<&str>) -> Self {
        self.account_exp_date = Self::parse_date(account_exp_date);
        self
    }

    pub fn reserved(mut self, reserved: Option<&str>) -> Self {
        self.reserved = Self::str_to_owned(reserved);
        self
    }

    pub fn build(self) -> Option<Shadow> {
        if let Some(username) = self.username {
            Some(Shadow {
                username,
                hashed_password: self.hashed_password,
                last_updated: self.last_updated,
                min_age: self.min_age,
                max_age: self.max_age,
                warning_period: self.warning_period,
                inactivity_period: self.inactivity_period,
                account_exp_date: self.account_exp_date,
                reserved: self.reserved,
            })
        } else {
            None
        }
    }
}

impl From<Shadow> for ShadowBuilder {
    fn from(value: Shadow) -> Self {
        Self {
            username: Some(value.username),
            hashed_password: value.hashed_password,
            last_updated: value.last_updated,
            min_age: value.min_age,
            max_age: value.max_age,
            warning_period: value.warning_period,
            inactivity_period: value.inactivity_period,
            account_exp_date: value.account_exp_date,
            reserved: value.reserved,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, NaiveDate};

    use crate::store::shadow::epoch_date;

    fn from_ymd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn date_calculations() {
        assert_eq!(from_ymd(2023, 6, 13) - epoch_date(), Duration::days(19521))
    }
}
