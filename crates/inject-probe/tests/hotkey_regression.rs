//! Regression test: does an injected (SendInput) Ctrl+Alt+R double-press
//! trigger a hotkey registered through `global-hotkey` (RegisterHotKey)?
//! Writes a marker file when both presses are observed, so the test can be
//! driven externally: run the test, send the keys, then inspect the marker.
//! Ignored by default because it requires an external key-sending harness
//! (see `coetest/post-hotkey.ps1` in the verification tooling).

use std::time::Duration;

fn marker_path() -> std::path::PathBuf {
    std::path::Path::new(r"C:\Users\alex3\AppData\Local\Temp\coetest")
        .join("hotkey-regression.txt")
}

#[test]
#[ignore]
fn registered_hotkey_receives_injected_double_press() {
    use global_hotkey::{
        GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
        hotkey::{Code, HotKey, Modifiers},
    };
    let _ = std::fs::remove_file(marker_path());
    let manager = GlobalHotKeyManager::new().expect("hotkey manager");
    let hotkey = HotKey::new(
        Some(Modifiers::CONTROL | Modifiers::ALT),
        Code::KeyR,
    );
    manager.register(hotkey).expect("register hotkey");

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut presses = 0u32;
    while std::time::Instant::now() < deadline {
        while let Ok(event) = GlobalHotKeyEvent::receiver().try_recv() {
            if event.id == hotkey.id() && event.state == HotKeyState::Pressed {
                presses += 1;
                let _ = std::fs::write(
                    marker_path(),
                    format!("press {presses} at {:?}\n", event.state),
                );
                eprintln!("HOTKEY-REGRESSION: press {presses} observed");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("HOTKEY-REGRESSION: total presses observed = {presses}");
    assert!(presses >= 2, "expected at least 2 injected presses, saw {presses}");
}
