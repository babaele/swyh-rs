use std::io;
#[cfg(windows)]
use winres::WindowsResource;

// Local workaround for this machine: Security Center blacklists `reg.exe`, so
// `winres` 0.1.12 (which locates rc.exe only via the registry) cannot find the
// Windows SDK. Point it straight at the SDK's rc.exe when present; otherwise
// fall back to the normal registry lookup (behaviour unchanged on other boxes).
#[cfg(windows)]
const SDK_RC_DIR: &str = r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64";

fn main() -> io::Result<()> {
    #[cfg(windows)]
    {
        let mut res = WindowsResource::new();
        res.set_icon("assets/swyh-rs-2.ico");
        if std::path::Path::new(SDK_RC_DIR).join("rc.exe").exists() {
            res.set_toolkit_path(SDK_RC_DIR);
        }
        res.compile()?;
    }
    Ok(())
}
