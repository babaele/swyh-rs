//! NetEase Cloud Music (`网易云音乐`) source support.
//!
//! Normally swyh-rs captures the audio device and streams a re-encoded copy of
//! whatever the PC is playing. This module adds a second, independent source: a
//! track is resolved through a `NeteaseCloudMusicApi`-compatible server and the
//! original audio file is then relayed to the renderer **byte for byte**, so no
//! decode/encode step ever touches the audio (see [`proxy`]).
//!
//! - [`api`]   : search, playlist lookup and song URL resolution
//! - [`login`] : QR-code login (auto-fetch the MUSIC_U / __csrf cookie) and
//!   user-info / user-playlist lookup
//! - [`proxy`] : the `/netease/<id>[.ext]` HTTP endpoint the renderer pulls from
//! - [`queue`] : play a list of tracks on a renderer, advancing automatically
//!
//! The login cookie (`netease_cookie` in the config file) is needed for
//! VIP / lossless tracks and for fetching the user's own playlists. We sign
//! weapi / eapi requests in pure Rust on top of `aes` / `num-bigint` / `md-5`
//! and talk to `music.163.com` directly — no external API server is required.

pub mod api;
pub mod login;
pub mod proxy;
pub mod queue;

pub use api::{NeteaseClient, SongUrl};
pub use login::{
    blocking_qr_login, decode_qr_data_uri, merge_set_cookies, persist_login_cookie, qr_check,
    qr_generate, status_from_code, status_label,
};
pub use proxy::{NETEASE_PATH_PREFIX, netease_track_url, parse_netease_path, serve_netease_track};
pub use queue::{netease_next, netease_stop, start_netease_queue};

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// A single NetEase Cloud Music track.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track {
    /// NetEase song id
    pub id: u64,
    /// song title
    pub name: String,
    /// artist name(s), joined with `, `
    pub artist: String,
    /// album name
    pub album: String,
    /// duration in milliseconds (`0` when the API did not report one)
    pub duration_millis: u64,
}

impl Track {
    /// duration in seconds, for the auto-advance heuristic in [`queue`]
    #[must_use]
    pub fn duration_secs(&self) -> f64 {
        self.duration_millis as f64 / 1000.0
    }
}

/// The audio quality (bitrate tier) requested from NetEase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Quality {
    /// 128 kbps MP3, available without login
    Standard,
    /// 320 kbps MP3
    Exhigh,
    /// FLAC lossless (default)
    #[default]
    Lossless,
    /// Hi-Res (>48 kHz / 24 bit), needs a VIP account
    Hires,
}

impl Quality {
    /// all qualities, in ascending order — index is used as the GUI `Choice` value
    pub const ALL: [Quality; 4] = [
        Quality::Standard,
        Quality::Exhigh,
        Quality::Lossless,
        Quality::Hires,
    ];

    /// the `level` parameter of `/song/url/v1`
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Quality::Standard => "standard",
            Quality::Exhigh => "exhigh",
            Quality::Lossless => "lossless",
            Quality::Hires => "hires",
        }
    }

    /// the `br` (bitrate) parameter of the legacy `/song/url` endpoint
    #[must_use]
    pub fn bitrate(self) -> u32 {
        match self {
            Quality::Standard => 128_000,
            Quality::Exhigh => 320_000,
            Quality::Lossless | Quality::Hires => 999_000,
        }
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Quality {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "standard" => Ok(Quality::Standard),
            "exhigh" | "high" => Ok(Quality::Exhigh),
            "lossless" | "flac" => Ok(Quality::Lossless),
            "hires" | "hi-res" => Ok(Quality::Hires),
            _ => Err(()),
        }
    }
}

/// Format a duration in seconds as the `H:MM:SS` string DIDL-Lite expects.
#[must_use]
pub fn format_duration(secs: f64) -> String {
    let total = if secs.is_finite() && secs > 0.0 {
        secs as u64
    } else {
        0
    };
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    format!("{h}:{m:02}:{s:02}")
}

/// A NetEase Cloud Music user playlist (我的歌单 / 收藏的歌单).
#[derive(Debug, Clone)]
pub struct Playlist {
    pub id: u64,
    pub name: String,
    pub track_count: u32,
    pub creator_nickname: String,
    pub cover_url: Option<String>,
}

/// Logged-in user account info returned by `/weapi/nuser/account/get`.
#[derive(Debug, Clone)]
pub struct UserAccount {
    /// `profile.userId` / `account.id` — the canonical numeric user id
    pub id: u64,
    pub nickname: String,
}

/// Status reported by NetEase's QR-code login poll endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrStatus {
    /// 801 — QR shown, waiting for the user to scan
    Waiting,
    /// 802 — QR expired (> ~3 min old)
    Expired,
    /// 803 — user scanned, waiting for phone confirmation
    Scanned,
    /// 800 — login succeeded; the matching `QrPoll` carries the Set-Cookie
    /// values the server returned
    Success,
    /// transport / parse / unknown server response — keep polling
    Error,
}

/// What `/api/login/qrcode/check` returned after parsing.
#[derive(Debug, Clone)]
pub struct QrPoll {
    pub status: QrStatus,
    /// Numeric code the server actually returned (`801` / `802` / `803` /
    /// `800`). Useful for diagnostics.
    pub code: i32,
    /// Raw `Set-Cookie` header values, in the order they came back. Only
    /// populated for [`QrStatus::Success`].
    pub set_cookies: Vec<String>,
}

/// What `/api/login/qrcode/generate` returned.
#[derive(Debug, Clone)]
pub struct QrImage {
    pub unikey: String,
    /// Raw PNG bytes (already decoded from the `data:image/png;base64,...`
    /// `qrimg` field the API returns).
    pub png_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_round_trip() {
        for q in Quality::ALL {
            let s = q.as_str();
            assert_eq!(Quality::from_str(s), Ok(q), "round trip failed for {s}");
        }
        assert_eq!(Quality::from_str("LOSSLESS"), Ok(Quality::Lossless));
        assert_eq!(Quality::from_str("nonsense"), Err(()));
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(0.0), "0:00:00");
        assert_eq!(format_duration(65.4), "0:01:05");
        assert_eq!(format_duration(3725.0), "1:02:05");
        assert_eq!(format_duration(f64::NAN), "0:00:00");
    }

    #[test]
    fn track_duration_secs() {
        let t = Track {
            id: 1,
            name: "n".into(),
            artist: "a".into(),
            album: "b".into(),
            duration_millis: 210_000,
        };
        assert!((t.duration_secs() - 210.0).abs() < f64::EPSILON);
    }

    #[test]
    fn merge_set_cookies_handles_common_shapes() {
        // single cookie, no attributes
        let one = vec!["MUSIC_U=abc".to_string()];
        assert_eq!(merge_set_cookies(&one), "MUSIC_U=abc");
        // multiple Set-Cookie headers, each with attrs after `;`
        let many = vec![
            "MUSIC_U=abc; Path=/; HttpOnly".to_string(),
            "__csrf=def; Path=/".to_string(),
            "NMTID=ghi; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        ];
        assert_eq!(
            merge_set_cookies(&many),
            "MUSIC_U=abc; __csrf=def; NMTID=ghi"
        );
        // value containing `=` (base64 padding) — split_once on first `=`
        let padded = vec!["MUSIC_U=abc==; Path=/".to_string()];
        assert_eq!(merge_set_cookies(&padded), "MUSIC_U=abc==");
        // empty parts / malformed entries skipped
        let mixed = vec![
            "MUSIC_U=abc".to_string(),
            "".to_string(),
            "=novalue".to_string(),
            "noequals".to_string(),
            "keyonly=".to_string(),
        ];
        assert_eq!(merge_set_cookies(&mixed), "MUSIC_U=abc");
        // empty input → empty output
        assert_eq!(merge_set_cookies(&[]), "");
    }
}
