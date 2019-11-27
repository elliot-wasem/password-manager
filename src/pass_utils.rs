/* std imports */
use std::process::Command;

/* local modules */
use crate::pass_crypto;

/* local structs */
use crate::Store;

/**
 * Stores the value within the buf encrypted via key in a mathematically secure
 * manner.
 */
pub fn store_string(key: &[u8], val: &[u8], mut buf: Vec<u8>) -> Vec<u8>{
    let encrypted_val = pass_crypto::encrypt_string_gen(
	std::str::from_utf8(val).unwrap(),
	std::str::from_utf8(key).unwrap()
    );
    let sha_key = pass_crypto::get_sha_key(
	std::str::from_utf8(&encrypted_val).unwrap(),
	std::str::from_utf8(key).unwrap()
    );
    for i in 0..encrypted_val.len() {
        let index: usize = sha_key[0..=i].chars().fold(0,|a, b| a + b as usize);
        buf[index] = encrypted_val[i];
    }
    buf
}

/**
 * Converts a vector of u8's representing a key-value store to a vector of Stores
 */
pub fn vec_u8_to_vec_store(input: Vec<u8>) -> (Option<Vec<Store>>, String) {
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

/**
 * Converts a vector of Stores to a vector of u8's representing a key-value store
 */
pub fn vec_store_to_vec_u8(input: Option<Vec<Store>>, sha_key: String) -> Vec<u8> {
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

/**
 * Returns a boolean representing whether or not a particular key is found in a
 * store
 */
pub fn in_store(store: Vec<Store>, key: String) -> bool {
    for s in store {
        if s.key == key {
            return true;
        }
    }
    false
}

/**
 * Adds a key-value pair to a vector of stores
 */
pub fn add_pair(input: Option<Vec<Store>>, key: String, val: String) -> Option<Vec<Store>> {
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

/**
 * Deletes a key-value pair from a vector of stores
 */
pub fn delete_pair(store: Option<Vec<Store>>, key: String) -> Option<Vec<Store>> {
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

/**
 * Alters a key-value pair in a vector of stores
 */
pub fn change_pair(input: Option<Vec<Store>>, key: String, val: String) -> Option<Vec<Store>> {
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

/**
 * Creates one long string of all the keys
 */
pub fn keys_to_string(store: Option<Vec<Store>>) -> Option<String> {
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

/**
 * From Given a store and a key, returns the corresponding password.
 */
pub fn get_pass(input: Option<Vec<Store>>, k: String) -> String {
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

/**
 * Prompts user for input via Rofi.
 */
pub fn prompt(prompt: &str, input: &str, rofi_wrapper: Option<String>) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo -e '{}' | {} -p '{}'", input, rofi_wrapper.unwrap(), prompt))
        .output()
        .expect("failed to execute process");
    let mut result: String = std::str::from_utf8(&output.stdout).unwrap().to_string();
    if result.len() <= 0 {
        return "".to_string();
    }else if result.as_bytes()[result.len()-1] == ("\n".as_bytes())[0] {
        result = result[..result.len() - 1].to_string();
    }
    result
}
