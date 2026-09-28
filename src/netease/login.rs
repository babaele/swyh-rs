//! NetEase QR-code login + cookie persistence.
//!
//! The QR login protocol:
//!
//! 1. `GET /api/login/qrcode/generate?type=1&realtype=1` → `{ unikey, qrimg }`
//!    `qrimg` is a `data:image/png;base64,...` PNG encoding the URL
//!    `https://music.163.com/login?codekey=<unikey>`.
//! 2. Poll `GET /api/login/qrcode/check?type=1&key=<unikey>&timestamp=<ms>`
//!    every 1–2 s. Status codes:
//!      - 801 = waiting for scan
//!      - 802 = QR expired (> ~3 min)
//!      - 803 = scanned, waiting for phone confirmation
//!      - 800 = success; response `Set-Cookie` headers carry the login cookies
//!
//! No external API server, no Node, no OpenSSL — just [`NeteaseClient`] and
//! `ureq`.

use crate::netease::{NeteaseClient, QrImage, QrPoll, QrStatus};
use crate::utils::ui_logger::{LogCategory, ui_log};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

/// Issue a fresh QR code. Returns the decoded PNG bytes + the `unikey`
/// the caller has to pass to subsequent [`qr_check`] polls.
pub fn qr_generate(client: &NeteaseClient) -> Result<QrImage> {
    client
        .qr_generate()
        .context("NetEase: failed to fetch QR code")
}

/// Poll the login status once. `unikey` is the value returned by the
/// matching [`qr_generate`] call.
pub fn qr_check(client: &NeteaseClient, unikey: &str) -> Result<QrPoll> {
    client.qr_check(unikey).context("NetEase: QR check failed")
}

/// Merge the raw `Set-Cookie` header values returned by music.163.com on a
/// successful QR scan (`MUSIC_U=...; __csrf=...; NMTID=...; os=pc; ...`) into
/// a single `Cookie:` header value suitable for [`NeteaseClient::new`].
///
/// - Drops attributes after the first `;` (`Path`, `Expires`, `HttpOnly`,
///   `SameSite`, `Secure`).
/// - Skips cookies whose name is empty or whose value is empty.
/// - Preserves order.
/// - Cookie values that legitimately contain `=` (e.g. base64 padding) are
///   preserved verbatim — `split_once('=')` splits on the first `=` only.
pub fn merge_set_cookies(headers: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for raw in headers {
        // each Set-Cookie is e.g. "MUSIC_U=abc; Path=/; HttpOnly"
        // take only the first "name=value" pair
        let Some(first) = raw.split(';').next() else {
            continue;
        };
        let first = first.trim();
        if first.is_empty() {
            continue;
        }
        let Some((k, v)) = first.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        if k.is_empty() || v.is_empty() {
            continue;
        }
        parts.push(format!("{k}={v}"));
    }
    parts.join("; ")
}

/// Persist the merged cookie into the global config + write the config file.
///
/// Returns the merged string (the same value now lives at
/// `get_config().netease_cookie`). The function **must be called on the main
/// thread** (the one that owns the configuration) — background workers should
/// post the cookie back to the main thread and let it persist.
///
/// When the `gui` feature is enabled, this also wakes the FLTK event loop
/// so the GUI re-reads the config on the next redraw.
pub fn persist_login_cookie(cookie: &str) -> Result<()> {
    let value = cookie.trim().to_string();
    if value.is_empty() {
        return Ok(());
    }
    {
        use crate::globals::statics::get_config_mut;
        let mut conf = get_config_mut();
        conf.netease_cookie = Some(value.clone());
        if let Err(e) = conf.update_config() {
            return Err(anyhow::anyhow!("failed to persist NetEase cookie: {e:#}"));
        }
    }
    ui_log(
        LogCategory::Info,
        &format!("NetEase: QR login cookie saved ({} bytes)", value.len()),
    );
    #[cfg(feature = "gui")]
    {
        use crate::enums::messages::MessageType;
        use crate::globals::statics::get_msgchannel;
        use fltk::app;
        let _ = get_msgchannel().0.send(MessageType::LogMessage(format!(
            "tb_log: NetEase: QR login cookie saved ({} bytes)",
            value.len()
        )));
        app::awake();
    }
    Ok(())
}

/// Optional helper used by the QR code: decode the `data:image/png;base64,...`
/// field the generate endpoint returns into raw PNG bytes. Exposed so the GUI
/// layer can also use it if it ever wants to fetch a QR via a different path.
pub fn decode_qr_data_uri(data_uri: &str) -> Result<Vec<u8>> {
    let prefix = "base64,";
    let Some(idx) = data_uri.find(prefix) else {
        anyhow::bail!("QR image is not a base64 data URI");
    };
    let b64 = &data_uri[idx + prefix.len()..];
    B64.decode(b64).context("decoding QR image base64")
}

/// Map NetEase's numeric status code to our [`QrStatus`]. Unknown codes
/// (anything other than 801/802/803/800) collapse to [`QrStatus::Error`].
#[must_use]
pub fn status_from_code(code: i32) -> QrStatus {
    match code {
        801 => QrStatus::Waiting,
        802 => QrStatus::Expired,
        803 => QrStatus::Scanned,
        800 => QrStatus::Success,
        _ => QrStatus::Error,
    }
}

/// Convenience: turn a [`QrStatus`] into a short user-facing label.
/// Lives here so the CLI / GUI can share the wording.
#[must_use]
pub fn status_label(status: QrStatus) -> &'static str {
    match status {
        QrStatus::Waiting => "等待扫码",
        QrStatus::Scanned => "已扫码,请在手机上确认",
        QrStatus::Expired => "二维码已过期,请刷新",
        QrStatus::Success => "登录成功",
        QrStatus::Error => "二维码错误",
    }
}

/// Run a one-shot QR login flow on the calling thread. Blocks until the
/// flow terminates (success / expiry / error). Returns the merged cookie on
/// success.
///
/// Useful for the CLI mode; the GUI uses its own polling loop because the
/// FLTK event loop must keep spinning.
pub fn blocking_qr_login() -> Result<Option<String>> {
    let client = NeteaseClient::new("");
    let img = qr_generate(&client)?;
    ui_log(
        LogCategory::Info,
        &format!(
            "NetEase: QR generated (unikey={}, {} bytes PNG)",
            img.unikey,
            img.png_bytes.len()
        ),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let poll = qr_check(&client, &img.unikey)?;
        ui_log(
            LogCategory::Info,
            &format!(
                "NetEase: QR poll code={} status={:?}",
                poll.code, poll.status
            ),
        );
        match poll.status {
            QrStatus::Waiting | QrStatus::Scanned => continue,
            QrStatus::Expired => return Ok(None),
            QrStatus::Success => {
                let merged = merge_set_cookies(&poll.set_cookies);
                return Ok(Some(merged));
            }
            QrStatus::Error => {
                anyhow::bail!("NetEase: QR poll returned unknown code {}", poll.code);
            }
        }
    }
    anyhow::bail!("NetEase: QR login timed out after 3 minutes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_mapping() {
        assert_eq!(status_from_code(801), QrStatus::Waiting);
        assert_eq!(status_from_code(802), QrStatus::Expired);
        assert_eq!(status_from_code(803), QrStatus::Scanned);
        assert_eq!(status_from_code(800), QrStatus::Success);
        assert_eq!(status_from_code(999), QrStatus::Error);
    }

    #[test]
    fn decode_qr_data_uri_strips_prefix() {
        // 1×1 transparent PNG, valid base64
        let uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
        let bytes = decode_qr_data_uri(uri).unwrap();
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    }
}
