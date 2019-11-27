/* std imports */
use std::path::Path;
use std::process::Command;
use std::fs::File;
use std::io::{Read, Write, Result};

/* local modules */
use crate::{pass_utils, pass_crypto};

/* local structs */
use crate::Store;

/* local constants */
use crate::FILESIZE;

/**
 * Trivially writes `file_input` to the file with name `filename`
 */
pub fn write_to_file(filename: &str, file_input: Vec<u8>) -> Result<()>{
    let mut output_file = File::create(filename)?;
    output_file.write(&file_input)?;
    Ok(())
}

/**
 * Trivially reads a file's contents into a Vec<u8>
 */
pub fn read_from_file(filename: &str) -> Result<Vec<u8>> {
    let mut f = File::open(filename)?;
    let mut input_buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut input_buffer)?;
    Ok(input_buffer)
}

/**
 * Opens file, decrypts it with the password, and returns the key-value store
 * representing the password file, along with the saved password
 */
pub fn open_and_read(key: &str, filename: &str, rofi_wrapper: Option<String>) -> (Option<Vec<Store>>, String) {
    let input_buffer: Vec<u8>;
    if Path::new(&filename).exists() {
        input_buffer = read_from_file(&filename).unwrap();
    } else {
        let saved_pass = pass_crypto::hash256(&key);
        return (None, saved_pass);
    }
    let original_input = pass_crypto::retrieve_saved_gen(&key, input_buffer);
    let (store, saved_pass) = pass_utils::vec_u8_to_vec_store(original_input.clone());
    let sha_key = pass_crypto::hash256(&key);
    if sha_key != saved_pass {
        pass_utils::prompt("Bad Password!", "Exit", rofi_wrapper.clone());
    }
    (store, saved_pass)
}

/**
 * Stores the key-value store to a file, encrypted via the saved password, to
 * a file with name `filename`
 */
pub fn store_to_file(store: Option<Vec<Store>>, key: &str, saved_pass: &str, filename: &str) {
    let mut buf: Vec<u8> = pass_crypto::get_obfusc_buf_u8(FILESIZE);

    let new_input = pass_utils::vec_store_to_vec_u8(store, saved_pass.to_string());


    /* stores string in vector */
    buf = pass_utils::store_string(key.as_bytes(), &new_input, buf);

    /* writes buf to file */
    write_to_file(&filename, buf).unwrap();
}

/**
 * Copies password to xclip clipboard manager
 */
pub fn add_to_xclip(buf: String) {
    Command::new("sh")
        .arg("-c")
        .arg(format!("echo -n '{}' | xclip -i", &buf))
        .spawn()
        .expect("xclip failed to execute");
}
