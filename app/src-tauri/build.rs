fn main() {
    // capabilities/mobile/ names the notification plugin, which the Windows
    // build doesn't include, so only phone builds read that folder.
    let mobile = matches!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("android" | "ios"));
    let pattern = if mobile { "./capabilities/**/*.json" } else { "./capabilities/*.json" };
    tauri_build::try_build(tauri_build::Attributes::new().capabilities_path_pattern(pattern)).expect("tauri build");
}
