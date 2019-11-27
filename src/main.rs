extern crate crypto;
extern crate rand;

/* std imports */
use std::vec::Vec;
use std::env;

/* local modules */
pub mod pass_crypto;
pub mod pass_io;
pub mod pass_utils;

/* local constants */
pub const FILESIZE: i64 = 1048576;

#[derive(Clone, Debug)]
pub struct Store {
    key: String,
    val: String
}

fn main() {
    /* Collect arguments */
    let args: Vec<String> = env::args().collect();

    /* check number of arguments */
    if args.len() != 2 && args.len() != 3  {
        println!("\nUsage: ./password-manager <filename>\n\n\taction: [ select | add | change | delete | purge file | change master password ]\n");
        return;
    }

    /* grab the filename */
    let filename: String = args[1].clone();

    let rofi_wrapper = Some("/usr/bin/rofi -dmenu -fullscreen -i".to_string());
    let rofi_password_wrapper = Some("/usr/bin/rofi -dmenu -password -fullscreen".to_string());

    /* prompt for master password, then the action */
    let mut key: String = pass_utils::prompt("Master Password", "", rofi_password_wrapper.clone());
    if key == "" {
        return;
    }
    let mut action: String = String::new();

    while action != "Exit" {
                action = pass_utils::prompt("Action", "Select\nAdd\nChange\nDelete\nPurge File\nChange Master Password\nExit", rofi_wrapper.clone());
        if action == "" {
            return;
        }
        match &action[..] {
            "Purge File" => {
                let areyousure = pass_utils::prompt("Are you sure you would like to purge the file?", "No\nYes", rofi_wrapper.clone());
                if areyousure == "" {
                    return;
                } else if areyousure == "No" {
                    pass_utils::prompt("File not purged", "Ok", rofi_wrapper.clone());
                    continue;
                }
                /* gets random vector of bytes of length FILESIZE */
                let mut buf: Vec<u8> = pass_crypto::get_obfusc_buf_u8(FILESIZE);
                let reset_input = format!("%{}", pass_crypto::hash256(&key));
                
                /* writes buf to file */
                buf = pass_utils::store_string(key.as_bytes(), reset_input.as_bytes(), buf);
                pass_io::write_to_file(&filename, buf).unwrap();
                pass_utils::prompt("File purged.", "Ok", rofi_wrapper.clone());
                return;
            },
            "Select" => {
                /* get store */
                let (store, _) = pass_io::open_and_read(&key, &filename, rofi_wrapper.clone());
                /* grab accounts from store */
                let accts = pass_utils::keys_to_string(store.clone());
                match accts {
                    Some(keys) => {
                        /* prompt for which account to use */
                        let account = pass_utils::prompt("Account", &format!("..\n{}", keys), rofi_wrapper.clone());
                        if account == "" {
                            return;
                        } else if account == ".." {
                            continue;
                        }
                        /* get password of given account */
                        let pass = pass_utils::get_pass(store, account);

                        /* copy the password to clipboard */
                        pass_io::add_to_xclip(pass);
                        continue;
                    },
                    None => {
                        pass_utils::prompt("No accounts found", "Ok", rofi_wrapper.clone());
                        continue;
                    }
                }
            },
            "Add" => {
                /* get store */
                let (mut store, saved_pass) = pass_io::open_and_read(&key, &filename, rofi_wrapper.clone());
                /* prompt for which account to use */
                let account = pass_utils::prompt("New account name", "", rofi_wrapper.clone());
                if account == "" {
                    continue;
                }
                /* get password of given account */
                let pass = pass_utils::prompt(&format!("New password for account '{}'", account), "", rofi_password_wrapper.clone());
                if pass == "" {
                    return;
                }
                let areyousure = pass_utils::prompt(&format!("Add account '{}'?", account), "No\nYes", rofi_wrapper.clone());
                if areyousure == "" {
                    return;
                } else if areyousure == "No" {
                    pass_utils::prompt("Account not added", "Ok", rofi_wrapper.clone());
                    continue;
                }
                /* reset pass for account */
                store = pass_utils::add_pair(store, account, pass);
                /* stores new store to file */
                pass_io::store_to_file(store, &key, &saved_pass, &filename);
                pass_utils::prompt("Account added", "Ok", rofi_wrapper.clone());
                continue;
            },
            "Change" => {
                /* get store */
                let (mut store, saved_pass) = pass_io::open_and_read(&key, &filename, rofi_wrapper.clone());
                /* grab accounts from store */
                let accts = pass_utils::keys_to_string(store.clone());
                match accts {
                    Some(keys) => {
                        /* prompt for which account to use */
                        let account = pass_utils::prompt("Account", &format!("..\n{}", &keys), rofi_wrapper.clone());
                        if account == "" {
                            return;
                        } else if account == ".." {
                            continue;
                        }
                        /* get password of given account */
                        let pass = pass_utils::prompt(&format!("New password for account '{}'", account), "", rofi_password_wrapper.clone());
                        if pass == "" {
                            return;
                        }
                        let areyousure = pass_utils::prompt(&format!("Change password for account '{}'?", account), "No\nYes", rofi_wrapper.clone());
                        if areyousure == "" {
                            return;
                        } else if areyousure == "No" {
                            pass_utils::prompt("Password unchanged", "Ok", rofi_wrapper.clone());
                            continue;
                        }
                        /* reset pass for account */
                        store = pass_utils::change_pair(store, account.clone(), pass);
                        /* stores new store to file */
                        pass_io::store_to_file(store, &key, &saved_pass, &filename);
                        pass_utils::prompt(&format!("Password for account '{}' changed", account), "Ok", rofi_wrapper.clone());
                        continue;
                    },
                    None => {
                        pass_utils::prompt("No accounts found", "Ok", rofi_wrapper.clone());
                        continue;
                    }
                }
            },
            "Delete" => {
                /* get store */
                let (mut store, saved_pass) = pass_io::open_and_read(&key, &filename, rofi_wrapper.clone());
                /* grab accounts from store */
                let accts = pass_utils::keys_to_string(store.clone());
                match accts {
                    Some(keys) => {
                        /* prompt for which account to use */
                        let account = pass_utils::prompt("Account", &format!("..\n{}",&keys), rofi_wrapper.clone());
                        if account == "" {
                            return;
                        } else if account == ".." {
                            continue;
                        }
                        let areyousure = pass_utils::prompt(&format!("Delete account '{}'?", account), "No\nYes", rofi_wrapper.clone());
                        if areyousure == "" {
                            return;
                        }
                        if areyousure == "No" {
                            pass_utils::prompt("Account not deleted", "Ok", rofi_wrapper.clone());
                            continue;
                        }
                        /* reset pass for account */
                        store = pass_utils::delete_pair(store, account.clone());
                        /* stores new store to file */
                        pass_io::store_to_file(store, &key, &saved_pass, &filename);
                        pass_utils::prompt(&format!("Account '{}' deleted", account), "Ok", rofi_wrapper.clone());
                        continue;
                    },
                    None => {
                        pass_utils::prompt("No accounts found", "Ok", rofi_wrapper.clone());
                        continue;
                    }
                }
            },
            "Change Master Password" => {
                let (store, _) = pass_io::open_and_read(&key, &filename, rofi_wrapper.clone());
                key = pass_utils::prompt("New master password", "", rofi_password_wrapper.clone());
                if key == "" {
                    return;
                }
                let areyousure = pass_utils::prompt("Are you sure you would like to change your master password?", "No\nYes", rofi_wrapper.clone());
                if areyousure == "No" {
                    pass_utils::prompt("Master password unchanged", "Ok", rofi_wrapper.clone());
                    continue;
                }

                let saved_pass = pass_crypto::hash256(&key);
                pass_io::store_to_file(store, &key, &saved_pass, &filename);
                pass_utils::prompt("Master password updated", "Ok", rofi_wrapper.clone());
                return;
            },
            _ => {

            }
            
        }
    }
}


