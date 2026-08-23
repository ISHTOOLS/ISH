use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn wasm_alloc(size: usize) -> *mut u8 {
    unsafe {
        let layout = Layout::from_size_align(size.max(1), 1).unwrap();
        alloc(layout)
    }
}

#[no_mangle]
pub extern "C" fn wasm_dealloc(ptr: *mut u8, size: usize) {
    unsafe {
        let layout = Layout::from_size_align(size.max(1), 1).unwrap();
        dealloc(ptr, layout);
    }
}

#[no_mangle]
pub extern "C" fn aes256gcm_encrypt(
    key_ptr: *const u8,
    nonce_ptr: *const u8,
    pt_ptr: *const u8,
    pt_len: usize,
    out_ptr: *mut u8,
) -> usize {
    unsafe {
        let key = Key::<Aes256Gcm>::from_slice(std::slice::from_raw_parts(key_ptr, 32));
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(std::slice::from_raw_parts(nonce_ptr, 12));
        let plaintext = std::slice::from_raw_parts(pt_ptr, pt_len);

        match cipher.encrypt(nonce, plaintext) {
            Ok(ct) => {
                let out = std::slice::from_raw_parts_mut(out_ptr, ct.len());
                out.copy_from_slice(&ct);
                ct.len()
            }
            Err(_) => 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn aes256gcm_decrypt(
    key_ptr: *const u8,
    nonce_ptr: *const u8,
    ct_ptr: *const u8,
    ct_len: usize,
    out_ptr: *mut u8,
) -> usize {
    unsafe {
        let key = Key::<Aes256Gcm>::from_slice(std::slice::from_raw_parts(key_ptr, 32));
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(std::slice::from_raw_parts(nonce_ptr, 12));
        let ciphertext = std::slice::from_raw_parts(ct_ptr, ct_len);

        match cipher.decrypt(nonce, ciphertext) {
            Ok(pt) => {
                let out = std::slice::from_raw_parts_mut(out_ptr, pt.len());
                out.copy_from_slice(&pt);
                pt.len()
            }
            Err(_) => usize::MAX,
        }
    }
}
