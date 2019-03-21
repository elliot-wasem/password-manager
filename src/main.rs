
extern crate crypto;
extern crate rand;

use rand::Rng;
use crypto::{sha2::Sha256, digest::Digest};
use std::vec::Vec;
use std::io::prelude::*;
use std::fs::File;
use std::{env, str};
use std::path::Path;
use std::process::Command;

const FILESIZE: i64 = 1048576;

#[derive(Clone, Debug)]
struct Store {
    key: String,
    val: String
}

fn hash256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(input);
    hasher.result_str()
}

fn get_sha_key(input: &str, key: &str) -> String {
    let mut sha_key: String = hash256(key);
    while sha_key.len() < input.len() {
        sha_key = format!("{}{}", sha_key, hash256(&sha_key));
    }
    sha_key
}

/* get Vec<u8> of random u8's of length len */
fn get_obfusc_buf_u8(len: i64) -> Vec<u8>{
    let mut buf: Vec<u8> = Vec::new();
    let mut rand = rand::thread_rng();
    for _ in 0..len {
        buf.push(rand.gen());
    }
    buf
}

fn write_to_file(filename: &str, file_input: Vec<u8>) -> std::io::Result<()>{
    let mut output_file = File::create(filename)?;
    output_file.write(&file_input)?;
    Ok(())
}

fn read_from_file(filename: &str) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(filename)?;
    let mut input_buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut input_buffer)?;
    Ok(input_buffer)
}

fn retrieve_saved_gen(key: &str, buf: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut sha_key = hash256(key);
    let mut count_q = 0;
    let mut i = 0;
    loop {
        let index: usize = sha_key[0..=i].as_bytes().iter().fold(0,|a, &b| a + b as usize);
        let temp_val = buf[index]^sha_key.as_bytes()[i];
        if temp_val == 'Q' as u8 {
            count_q += 1;
            if count_q == 3 {
                break;
            }
        }
        result.push(temp_val);
        if i == sha_key.len() - 1 {
            sha_key = format!("{}{}", sha_key, hash256(&sha_key));
        }
        i += 1;
    }
    result.pop();
    result.pop();
    result
}

fn store_string(key: &[u8], val: &[u8], mut buf: Vec<u8>) -> Vec<u8>{
    let encrypted_val = encrypt_string_gen(str::from_utf8(val).unwrap(), str::from_utf8(key).unwrap());
    let sha_key = get_sha_key(str::from_utf8(&encrypted_val).unwrap(), str::from_utf8(key).unwrap());
    for i in 0..encrypted_val.len() {
        let index: usize = sha_key[0..=i].chars().fold(0,|a, b| a + b as usize);
        buf[index] = encrypted_val[i];
    }
    buf
}

fn encrypt_string_gen(input: &str, key: &str) -> Vec<u8> {
    let mut sha_key: String = hash256(key);
    let padded_input: String = format!("{}{}", input, "QQQ");
    let mut output: Vec<u8> = Vec::new();
    let input_bytes = padded_input.as_bytes();
    while sha_key.len() < input_bytes.len() {
        sha_key = format!("{}{}", sha_key, hash256(&sha_key));
    }
    let sha_key_bytes = sha_key.as_bytes();
    for i in 0..padded_input.len() {
        output.push(input_bytes[i]^sha_key_bytes[i]);
    }
    output
}

fn vec_u8_to_vec_store(input: Vec<u8>) -> (Option<Vec<Store>>, String) {
    let mut pass: String = String::new();
    let mut store: Vec<Store> = Vec::new();
    let in_str: String = (&input).iter().map(|c| *c as char).collect();

    for pair in in_str.split(",") {
        let mut split = pair.split(":");
        let k = match split.next() {
            Some(key) => key,
            None => panic!("k HAS NONE VALUE!")
        };
        
        let mut v = match split.next() {
            Some(val) => val,
            None => {
                /* means there are no key/values in it, so k holds '%hashofkey' */
                let mut temp = k.split("%");
                temp.next();
                let val = temp.next().unwrap().to_string();
                return (None, val)
            }
        };

        if v.contains("%") {
            let mut split_pass = v.split("%");
            v = split_pass.next().unwrap();
            pass = split_pass.next().unwrap().to_string();
        }
        store.push(Store {key: k.to_string(), val: v.to_string()});
    }
    (Some(store), pass)
}

fn vec_store_to_vec_u8(input: Option<Vec<Store>>, sha_key: String) -> Vec<u8> {
    let mut result: String = String::new();
    match input {
        Some(s) => {
            for store in s {
                result = format!("{}{}:{},", result, store.key, store.val);
            }
        },
        None => {
        }
    }
    if result.len() > 0 {
        result.pop().unwrap();
    }
    result = format!("{}%{}", result, sha_key);
    Vec::from(result)
}

/* bool of whether or not key is found in store */
fn in_store(store: Vec<Store>, key: String) -> bool {
    for s in store {
        if s.key == key {
            return true;
        }
    }
    false
}

fn add_pair(input: Option<Vec<Store>>, key: String, val: String) -> Option<Vec<Store>> {
    match input {
        Some(mut store) => {
            if !in_store(store.clone(), key.clone()) {
                store.push(Store {key, val});
            }
            Some(store)
        },
        None => {
            let mut new_store: Vec<Store> = Vec::new();
            new_store.push(Store{key, val});
            Some(new_store)
        }
    }
}

fn delete_pair(store: Option<Vec<Store>>, key: String) -> Option<Vec<Store>> {
    match store.clone() {
        Some(s) => {
            if in_store(s.clone(), key.clone()) {
                let mut result: Vec<Store> = Vec::new();
                for x in s {
                    if x.key != key {
                        result.push(x);
                    }
                }
                return Some(result);
            }
            store
        },
        None => None
    }
}

fn change_pair(input: Option<Vec<Store>>, key: String, val: String) -> Option<Vec<Store>> {
    match input {
        Some(store) => {
            if in_store(store.clone(), key.clone()) {
                let mut result: Vec<Store> = Vec::new();
                for s in store {
                    if s.key == key {
                        result.push(Store {key: key.clone(), val: val.clone()});
                    } else {
                        result.push(s)
                    }
                }
                Some(result)
            } else {
                add_pair(Some(store), key, val)
            }
        },
        None => None
    }
}

fn open_and_read(key: &str, filename: &str) -> (Option<Vec<Store>>, String) {
    let mut input_buffer: Vec<u8>;
    if Path::new(&filename).exists() {
        input_buffer = read_from_file(&filename).unwrap();
    } else {
        let saved_pass = hash256(&key);
        return (None, saved_pass);
    }
    let original_input = retrieve_saved_gen(&key, input_buffer);
    let (store, saved_pass) = vec_u8_to_vec_store(original_input.clone());
    let sha_key = hash256(&key);
    if sha_key != saved_pass {
        panic!("Bad password!!!");
    }
    (store, saved_pass)
}

fn store_to_file(store: Option<Vec<Store>>, key: &str, saved_pass: &str, filename: &str) {
    let mut buf: Vec<u8> = get_obfusc_buf_u8(FILESIZE);

    let new_input = vec_store_to_vec_u8(store, saved_pass.to_string());


    /* stores string in vector */
    buf = store_string(key.as_bytes(), &new_input, buf);

    /* writes buf to file */
    write_to_file(&filename, buf).unwrap();
}

fn keys_to_string(store: Option<Vec<Store>>) -> Option<String> {
    match store {
        Some(s) => {
            let mut keys: Vec<String> = Vec::new();
            let mut result = String::new();
            for x in s.clone() {
                keys.push(x.key.clone());
            }
            keys.sort();
            for x in keys {
                if result == "" {
                    result = format!("{}", x.clone());
                } else {
                    result = format!("{}\n{}", result, x.clone());
                }
            }
            Some(result)
        },
        None => None
    }
}

fn get_pass(input: Option<Vec<Store>>, k: String) -> String {
    match input {
        Some(store) => {
            for s in store {
                if s.key == k {
                    return s.val.clone()
                }
            }
            String::from("INVALID")
        },
        None => String::new()
    }
}

fn prompt(prompt: &str, input: &str, dmenu_wrapper: Option<String>) -> String {
    let wrapper = match dmenu_wrapper {
        Some(d_wrapper) => format!("sh {}", d_wrapper),
        None => "/usr/bin/dmenu".to_string()
    };
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo -e '{}' | {} -p '{}'", input, wrapper, prompt))
        .output()
        .expect("failed to execute process");
    let mut result: String = str::from_utf8(&output.stdout).unwrap().to_string();
    if result.len() <= 0 {
        return "".to_string();
    }else if result.as_bytes()[result.len()-1] == ("\n".as_bytes())[0] {
        result = result[..result.len() - 1].to_string();
    }
    result
}

fn add_to_xclip(buf: String) {
    Command::new("sh")
        .arg("-c")
        .arg(format!("echo -n '{}' | xclip -i", &buf))
        .spawn()
        .expect("xclip failed to execute");
}

fn main() {
    /* Collect arguments */
    let args: Vec<String> = env::args().collect();

    /* check number of arguments */
    if args.len() != 2 && args.len() != 3  {
        println!("\nUsage: ./password-manager <filename> [<dmenu-wrapper>]\n\n\taction: [ select | add | change | delete | purge file | change master password ]\n");
        return;
    }

    /* grab the filename */
    let filename: String = args[1].clone();

    let dmenu_wrapper: Option<String>;

    if args.len() < 3 {
        dmenu_wrapper = None;
    } else {
        dmenu_wrapper = Some(args[2].clone());
    }

    /* prompt for master password, then the action */
    let mut key: String = prompt("MasterPass:", "", dmenu_wrapper.clone());

    if key == "" {
        return;
    }
    let mut action: String = String::new();

    while action != "Exit" {
                action = prompt("Action:", "Select\nAdd\nChange\nDelete\nPurge File\nChange Master Password\nExit", dmenu_wrapper.clone());
        if action == "" {
            return;
        }
        match &action[..] {
            "Purge File" => {
                let areyousure = prompt("AreYouSure???", "No\nYes", dmenu_wrapper.clone());
                if areyousure == "" {
                    return;
                } else if areyousure == "No" {
                    prompt("FileNotPurged.", "Ok", dmenu_wrapper.clone());
                    continue;
                }
                /* gets random vector of bytes of length FILESIZE */
                let mut buf: Vec<u8> = get_obfusc_buf_u8(FILESIZE);
                let reset_input = format!("%{}", hash256(&key));
                
                /* writes buf to file */
                buf = store_string(key.as_bytes(), reset_input.as_bytes(), buf);
                write_to_file(&filename, buf).unwrap();
                prompt("FilePurged.", "Ok", dmenu_wrapper.clone());
                return;
            },
            "Select" => {
                /* get store */
                let (store, _) = open_and_read(&key, &filename);
                /* grab accounts from store */
                let accts = keys_to_string(store.clone());
                match accts {
                    Some(keys) => {
                        /* prompt for which account to use */
                        let account = prompt("Account:", &format!("..\n{}", keys), dmenu_wrapper.clone());
                        if account == "" {
                            return;
                        } else if account == ".." {
                            continue;
                        }
                        /* get password of given account */
                        let pass = get_pass(store, account);

                        /* copy the password to clipboard */
                        add_to_xclip(pass);
                        continue;
                    },
                    None => {
                        prompt("NoAccountsFound!", "Ok", dmenu_wrapper.clone());
                        continue;
                    }
                }
            },
            "Add" => {
                /* get store */
                let (mut store, saved_pass) = open_and_read(&key, &filename);
                /* prompt for which account to use */
                let account = prompt("NewAccount:", "", dmenu_wrapper.clone());
                if account == "" {
                    continue;
                }
                /* get password of given account */
                let pass = prompt("NewPass:", "", dmenu_wrapper.clone());
                if pass == "" {
                    return;
                }
                let areyousure = prompt("AddAccount?", "No\nYes", dmenu_wrapper.clone());
                if areyousure == "" {
                    return;
                } else if areyousure == "No" {
                    prompt("AccountNotAdded.", "Ok", dmenu_wrapper.clone());
                    continue;
                }
                /* reset pass for account */
                store = add_pair(store, account, pass);
                /* stores new store to file */
                store_to_file(store, &key, &saved_pass, &filename);
                prompt("AccountAdded.", "Ok", dmenu_wrapper.clone());
                continue;
            },
            "Change" => {
                /* get store */
                let (mut store, saved_pass) = open_and_read(&key, &filename);
                /* grab accounts from store */
                let accts = keys_to_string(store.clone());
                match accts {
                    Some(keys) => {
                        /* prompt for which account to use */
                        let account = prompt("Account:", &format!("..\n{}", &keys), dmenu_wrapper.clone());
                        if account == "" {
                            return;
                        } else if account == ".." {
                            continue;
                        }
                        /* get password of given account */
                        let pass = prompt("NewPass:", "", dmenu_wrapper.clone());
                        if pass == "" {
                            return;
                        }
                        let areyousure = prompt("AreYouSure???", "No\nYes", dmenu_wrapper.clone());
                        if areyousure == "" {
                            return;
                        } else if areyousure == "No" {
                            prompt("PasswordUnchanged!", "Ok", dmenu_wrapper.clone());
                            continue;
                        }
                        /* reset pass for account */
                        store = change_pair(store, account, pass);
                        /* stores new store to file */
                        store_to_file(store, &key, &saved_pass, &filename);
                        prompt("PasswordChanged!", "Ok", dmenu_wrapper.clone());
                        continue;
                    },
                    None => {
                        prompt("NoAccountsFound!", "Ok", dmenu_wrapper.clone());
                        continue;
                    }
                }
            },
            "Delete" => {
                /* get store */
                let (mut store, saved_pass) = open_and_read(&key, &filename);
                /* grab accounts from store */
                let accts = keys_to_string(store.clone());
                match accts {
                    Some(keys) => {
                        /* prompt for which account to use */
                        let account = prompt("Account:", &format!("..\n{}",&keys), dmenu_wrapper.clone());
                        if account == "" {
                            return;
                        } else if account == ".." {
                            continue;
                        }
                        let areyousure = prompt("AreYouSure???", "No\nYes", dmenu_wrapper.clone());
                        if areyousure == "" {
                            return;
                        }
                        if areyousure == "No" {
                            prompt("PasswordNotDeleted!", "Ok", dmenu_wrapper.clone());
                            continue;
                        }
                        /* reset pass for account */
                        store = delete_pair(store, account);
                        /* stores new store to file */
                        store_to_file(store, &key, &saved_pass, &filename);
                        prompt("PasswordDeleted!", "Ok", dmenu_wrapper.clone());
                        continue;
                    },
                    None => {
                        prompt("NoAccountsFound!", "Ok", dmenu_wrapper.clone());
                        continue;
                    }
                }
            },
            "Change Master Password" => {
                let (store, _) = open_and_read(&key, &filename);
                key = prompt("NewMasterPass:", "", dmenu_wrapper.clone());
                if key == "" {
                    return;
                }
                let areyousure = prompt("AreYouSure???", "No\nYes", dmenu_wrapper.clone());
                if areyousure == "No" {
                    prompt("PasswordUnchanged!", "Ok", dmenu_wrapper.clone());
                    continue;
                }

                let saved_pass = hash256(&key);
                store_to_file(store, &key, &saved_pass, &filename);
                prompt("PasswordChanged!", "Ok", dmenu_wrapper.clone());
                return;
            },
            _ => {

            }
            
        }
    }
}
