//! NetEase Cloud Music API client.
//!
//! Talks to a `NeteaseCloudMusicApi`-compatible HTTP server
//! (<https://github.com/Binaryify/NeteaseCloudMusicApi>) which handles the
//! request signing/encryption NetEase requires. Only three endpoints are used:
//!
//! | endpoint            | purpose                                  |
//! |---------------------|------------------------------------------|
//! | `/cloudsearch`      | search for songs by keyword (no login)   |
//! | `/playlist/detail`  | list the tracks of a playlist            |
//! | `/song/url/v1`      | resolve a song id to a playable URL      |
//!
//! `/song/url` (the legacy, `br`-based endpoint) is used as a fallback for API
//! servers that predate `/song/url/v1`.

use super::{Quality, Track};
use crate::globals::statics::get_config;
use anyhow::{Context, Result, anyhow};
use log::debug;
use serde::Deserialize;
use std::time::Duration;

/// default base URL of the `NeteaseCloudMusicApi` server
pub const DEFAULT_API_BASE: &str = "http://127.0.0.1:3000";

/// how long a resolved song URL is reused before it is refreshed
pub const URL_TTL: Duration = Duration::from_secs(300);

/// browser UA NetEase expects on its CDN
pub(super) const CDN_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/122.0.0.0 Safari/537.36";
/// the CDN only serves files to requests that look like they come from the site
pub(super) const CDN_REFERER: &str = "https://music.163.com/";

/// A resolved, directly playable audio URL.
#[derive(Debug, Clone)]
pub struct SongUrl {
    /// NetEase song id
    pub id: u64,
    /// the CDN url of the audio file
    pub url: String,
    /// NetEase's own file type designation (`flac`, `mp3`, `m4a`, ...)
    pub file_type: String,
    /// bitrate in bits per second as reported by the API
    pub br: u64,
    /// file size in bytes as reported by the API
    pub size: u64,
}

impl SongUrl {
    /// MIME type to hand to the renderer for this file
    #[must_use]
    pub fn mime(&self) -> &'static str {
        mime_for_type(&self.file_type)
    }

    /// file extension matching [`SongUrl::file_type`], used in the proxy URL
    #[must_use]
    pub fn ext(&self) -> &'static str {
        match self.file_type.as_str() {
            "flac" => "flac",
            "m4a" | "mp4" => "m4a",
            "ape" => "ape",
            "wav" => "wav",
            "ogg" => "ogg",
            _ => "mp3",
        }
    }
}

/// Map a NetEase `type` string to a MIME type.
#[must_use]
pub fn mime_for_type(file_type: &str) -> &'static str {
    match file_type.to_ascii_lowercase().as_str() {
        "flac" => "audio/flac",
        "m4a" | "mp4" => "audio/mp4",
        "ape" => "audio/x-ape",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        _ => "audio/mpeg",
    }
}

// ---------------------------------------------------------------- API payloads

#[derive(Debug, Deserialize, Default)]
struct SearchResp {
    #[serde(default)]
    result: SearchResult,
}

#[derive(Debug, Deserialize, Default)]
struct SearchResult {
    #[serde(default)]
    songs: Vec<RawSong>,
}

#[derive(Debug, Deserialize, Default)]
struct PlaylistResp {
    #[serde(default)]
    playlist: Option<RawPlaylist>,
}

#[derive(Debug, Deserialize, Default)]
struct RawPlaylist {
    #[serde(default)]
    tracks: Vec<RawSong>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct RawSong {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    ar: Vec<RawArtist>,
    #[serde(default)]
    al: Option<RawAlbum>,
    /// duration in milliseconds
    #[serde(default)]
    dt: u64,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct RawArtist {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct RawAlbum {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct SongUrlResp {
    #[serde(default)]
    data: Vec<RawSongUrl>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSongUrl {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    br: u64,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    r#type: Option<String>,
}

impl From<RawSong> for Track {
    fn from(s: RawSong) -> Track {
        let artist =
            s.ar.iter()
                .map(|a| a.name.as_str())
                .filter(|n| !n.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
        Track {
            id: s.id,
            name: s.name,
            artist,
            album: s.al.map_or_else(String::new, |a| a.name),
            duration_millis: s.dt,
        }
    }
}

// ------------------------------------------------------------------- the client

/// A thin client for the `NeteaseCloudMusicApi` server.
#[derive(Debug, Clone)]
pub struct NeteaseClient {
    agent: ureq::Agent,
    base: String,
    cookie: String,
    quality: Quality,
}

impl NeteaseClient {
    /// Build a client from the current configuration.
    #[must_use]
    pub fn from_config() -> NeteaseClient {
        let (base, cookie, quality) = {
            let cfg = get_config();
            (
                cfg.netease_api_base
                    .clone()
                    .unwrap_or_else(|| DEFAULT_API_BASE.to_string()),
                cfg.netease_cookie.clone().unwrap_or_default(),
                cfg.netease_quality.unwrap_or_default(),
            )
        };
        NeteaseClient::new(base, cookie, quality)
    }

    /// Build a client with explicit settings (used by the tests and the CLI).
    #[must_use]
    pub fn new(
        base: impl Into<String>,
        cookie: impl Into<String>,
        quality: Quality,
    ) -> NeteaseClient {
        // no global timeout: a lossless track can be large and slow to fetch,
        // but a server that never accepts the connection must not hang forever
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_connect(Some(Duration::from_secs(10)))
                .build(),
        );
        NeteaseClient {
            agent,
            base: base.into().trim_end_matches('/').to_string(),
            cookie: cookie.into(),
            quality,
        }
    }

    /// the configured base URL, for logging
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Search for songs matching `keywords` (type 1 = single songs).
    pub fn search(&self, keywords: &str, limit: u32) -> Result<Vec<Track>> {
        let body = self.get_json(
            "/cloudsearch",
            &[
                ("keywords", keywords.to_string()),
                ("type", "1".to_string()),
                ("limit", limit.to_string()),
                ("offset", "0".to_string()),
            ],
        )?;
        let resp: SearchResp = serde_json::from_str(&body).context("parsing /cloudsearch reply")?;
        Ok(resp.result.songs.into_iter().map(Track::from).collect())
    }

    /// List the tracks of the playlist with NetEase id `playlist_id`.
    ///
    /// The `/playlist/detail` endpoint returns the whole playlist for anonymous
    /// requests; very large playlists may be truncated by the API server, in
    /// which case supplying a login cookie in the config helps.
    pub fn playlist_tracks(&self, playlist_id: u64) -> Result<Vec<Track>> {
        let body = self.get_json("/playlist/detail", &[("id", playlist_id.to_string())])?;
        let resp: PlaylistResp =
            serde_json::from_str(&body).context("parsing /playlist/detail reply")?;
        let tracks = resp
            .playlist
            .context("playlist not found (wrong id, or login required)?")?
            .tracks;
        Ok(tracks.into_iter().map(Track::from).collect())
    }

    /// Resolve a song id to a playable URL, trying `/song/url/v1` first.
    pub fn song_url(&self, song_id: u64) -> Result<SongUrl> {
        if let Some(url) = self.song_url_v1(song_id)? {
            return Ok(url);
        }
        self.song_url_legacy(song_id)
    }

    fn song_url_v1(&self, song_id: u64) -> Result<Option<SongUrl>> {
        let Ok(body) = self.get_json(
            "/song/url/v1",
            &[
                ("id", song_id.to_string()),
                ("level", self.quality.as_str().to_string()),
            ],
        ) else {
            return Ok(None);
        };
        let resp: SongUrlResp = match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        Ok(resp.data.into_iter().find_map(|d| self.to_song_url(d)))
    }

    fn song_url_legacy(&self, song_id: u64) -> Result<SongUrl> {
        let body = self.get_json(
            "/song/url",
            &[
                ("id", song_id.to_string()),
                ("br", self.quality.bitrate().to_string()),
            ],
        )?;
        let resp: SongUrlResp = serde_json::from_str(&body).context("parsing /song/url reply")?;
        resp.data
            .into_iter()
            .find_map(|d| self.to_song_url(d))
            .ok_or_else(|| {
                anyhow!("no playable url for song {song_id} (no copyright, or login/VIP required)")
            })
    }

    fn to_song_url(&self, d: RawSongUrl) -> Option<SongUrl> {
        let url = d.url?;
        if url.is_empty() {
            return None;
        }
        Some(SongUrl {
            id: d.id,
            file_type: d.r#type.unwrap_or_else(|| guess_type(&url)),
            url,
            br: d.br,
            size: d.size,
        })
    }

    /// Open the CDN URL of an already resolved track.
    ///
    /// `range` is forwarded verbatim when the renderer asked for one, so seeking
    /// works and we never download more than needed. `head_only` issues a HEAD
    /// request (used to answer a renderer's probing HEAD with headers only).
    pub fn open_cdn(
        &self,
        url: &str,
        range: Option<&str>,
        head_only: bool,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let mut rq = if head_only {
            self.agent.head(url)
        } else {
            self.agent.get(url)
        };
        // the CDN only serves files to requests that look like the web player's
        rq = rq
            .header("User-Agent", CDN_USER_AGENT)
            .header("Referer", CDN_REFERER);
        if let Some(r) = range {
            rq = rq.header("Range", r);
        }
        rq.call()
            .with_context(|| format!("fetching NetEase audio {url}"))
    }

    /// Perform a GET against the API server and return the response body.
    fn get_json(&self, path: &str, params: &[(&str, String)]) -> Result<String> {
        let url = format!("{}{path}", self.base);
        let mut rq = self.agent.get(&url);
        for (k, v) in params {
            rq = rq.query(*k, v.as_str());
        }
        if !self.cookie.is_empty() {
            rq = rq.header("Cookie", self.cookie.as_str());
        }
        debug!("netease api GET {url} {params:?}");
        let mut resp = rq
            .call()
            .with_context(|| format!("calling NetEase API {url}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!("NetEase API {url} returned HTTP {}", resp.status()));
        }
        resp.body_mut()
            .with_config()
            .limit(8 * 1024 * 1024)
            .read_to_string()
            .with_context(|| format!("reading NetEase API reply from {url}"))
    }
}

/// Fall back to the file extension when the API did not tell us the type.
fn guess_type(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    match path.rsplit('.').next() {
        Some(ext) if ext.len() <= 4 => ext.to_ascii_lowercase(),
        _ => "mp3".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_mapping() {
        assert_eq!(mime_for_type("flac"), "audio/flac");
        assert_eq!(mime_for_type("FLAC"), "audio/flac");
        assert_eq!(mime_for_type("mp3"), "audio/mpeg");
        assert_eq!(mime_for_type("m4a"), "audio/mp4");
        assert_eq!(mime_for_type("weird"), "audio/mpeg");
    }

    #[test]
    fn ext_matches_mime() {
        for t in ["flac", "mp3", "m4a"] {
            let s = SongUrl {
                id: 1,
                url: "http://x/y".into(),
                file_type: t.to_string(),
                br: 0,
                size: 0,
            };
            assert_eq!(mime_for_type(s.ext()), s.mime(), "type {t}");
        }
    }

    #[test]
    fn guess_type_from_url() {
        assert_eq!(guess_type("https://x/y.flac?a=b"), "flac");
        assert_eq!(guess_type("https://x/y.mp3"), "mp3");
        assert_eq!(guess_type("https://x/y"), "mp3");
    }

    #[test]
    fn raw_song_conversion() {
        let raw = RawSong {
            id: 42,
            name: "Song".into(),
            ar: vec![
                RawArtist { name: "A".into() },
                RawArtist { name: "B".into() },
            ],
            al: Some(RawAlbum {
                name: "Album".into(),
            }),
            dt: 1234,
        };
        let t: Track = raw.into();
        assert_eq!(t.id, 42);
        assert_eq!(t.name, "Song");
        assert_eq!(t.artist, "A, B");
        assert_eq!(t.album, "Album");
        assert_eq!(t.duration_millis, 1234);
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let c = NeteaseClient::new("http://127.0.0.1:3000/", "", Quality::Lossless);
        assert_eq!(c.base(), "http://127.0.0.1:3000");
    }
}
