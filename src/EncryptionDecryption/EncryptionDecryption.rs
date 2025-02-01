use winapi::um::wincrypt::{HCRYPTKEY,CryptDecrypt,CryptEncrypt};
use winapi::um::fileapi::{ReadFile, CreateFileA, WriteFile, OPEN_EXISTING};
use winapi::um::winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE};
use std::ptr;
use std::ffi::CString;
use winapi::um::fileapi::{SetFilePointer, SetEndOfFile};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::FILE_BEGIN;

pub fn encryption(filename: CString, h_key: HCRYPTKEY) {
    
    unsafe {
        let handle = CreateFileA(
            filename.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,  
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );

        if handle.is_null() {
            return;
        }
        let bytes_to_read: u32 = 192;  
        let mut buffer: Vec<u8> = vec![0; bytes_to_read as usize];
        let mut bytes_read: u32 = 0;

        let mut eof = 0;
        let mut offset: i32 = 0;  

        while eof == 0 {
            let result = ReadFile(
                handle,
                buffer.as_mut_ptr() as *mut _,
                bytes_to_read,
                &mut bytes_read,
                ptr::null_mut(),
            );

            if result == 0 || bytes_read == 0 {
                eof = 1;
                continue;
            }
            buffer.truncate(bytes_read as usize);
            let mut data_len = buffer.len() as u32;
            if bytes_read < bytes_to_read {
                eof = 1;  
            }
            let encryption_result = CryptEncrypt(
                h_key,
                0,
                eof,  
                0,
                buffer.as_mut_ptr() as *mut u8,
                &mut data_len,
                (data_len + 16) as u32,  
            );
            if encryption_result == 0 {
                return
            } 
            SetFilePointer(handle, offset, ptr::null_mut(), FILE_BEGIN);
            let mut bytes_written: u32 = 0;
            if WriteFile(
                handle,
                buffer.as_ptr() as *const _,
                data_len,
                &mut bytes_written,
                ptr::null_mut(),
            ) == 0 {
                return;
            } 
            offset += bytes_to_read as i32;  
        }

        SetEndOfFile(handle);  
        CloseHandle(handle);
    }
}

pub fn decrypt_file(filename: CString, h_key: HCRYPTKEY)->i32{
  unsafe {
      let handle = CreateFileA(
          filename.as_ptr(),
          GENERIC_READ | GENERIC_WRITE,
          0,
          ptr::null_mut(),
          OPEN_EXISTING,  
          FILE_ATTRIBUTE_NORMAL,
          ptr::null_mut(),
      );
      if handle.is_null() {
          return 0;
      }
      let bytes_to_read: u32 = 192;  
      let mut buffer: Vec<u8> = vec![0; bytes_to_read as usize];
      let mut bytes_read: u32 = 0;
      let mut eof = 0;
      let mut offset: i32 = 0;

      while eof == 0 {
          let result = ReadFile(
              handle,
              buffer.as_mut_ptr() as *mut _,
              bytes_to_read,
              &mut bytes_read,
              ptr::null_mut(),
          );
          if result == 0 || bytes_read == 0 {
              eof = 1;
              continue;
          }
          buffer.truncate(bytes_read as usize);
          let mut data_len = buffer.len() as u32;
          if bytes_read < bytes_to_read {
              eof = 1;  
          }
          let encryption_result = CryptDecrypt(
              h_key,
              0,
              eof,  
              0,
              buffer.as_mut_ptr() as *mut u8,
              &mut data_len,  
          );

          if encryption_result == 0 {
              return 0;
          } 

          SetFilePointer(handle, offset, ptr::null_mut(), FILE_BEGIN);
          let mut bytes_written: u32 = 0;
          if WriteFile(
              handle,
              buffer.as_ptr() as *const _,
              data_len,
              &mut bytes_written,
              ptr::null_mut(),
          ) == 0 {
            return 0;
          }

          offset += bytes_to_read as i32;  
      }
      SetEndOfFile(handle);  
      CloseHandle(handle);
      return 1;
  }
}
