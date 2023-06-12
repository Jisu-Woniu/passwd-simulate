use std::env;

use rpassword::prompt_password;

use crypt::salt::make_salt;

mod crypt;
mod store;

fn main() {
    let n = env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(16);

    let password = prompt_password("Your Password: ").expect("No password provided");
    // let mut salt = b"$6$".to_vec();
    // salt.append(&mut make_salt(n));
    let salt_input = prompt_password("Your Salt: ");
    let salt = salt_input
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|_| make_salt(n));
    println!(
        "Your password is: {:?}, and your salt is {:?}",
        password,
        String::from_utf8_lossy(&salt)
    );
    println!(
        "After hashing: {}",
        crypt::crypt(password.as_bytes(), &salt).unwrap_or(String::from(""))
    );
}
