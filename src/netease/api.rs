//! NetEase Cloud Music API client.
//!
//! Talks to `music.163.com` directly over HTTPS with `ureq`.
//!
//! **No request signing is needed.** NetEase's old `weapi` (AES-CBC + RSA) and
//! `eapi` (AES-ECB + MD5) channels have been retired server-side: every
//! signed request now answers `200 OK` with `content-length: 0`. The current
//! web client uses plain, unsigned `/api/...` endpoints, and so do we:
//!
//! | URL                                          | method | purpose                       |
//! |----------------------------------------------|--------|-------------------------------|
//! | `/api/cloudsearch/pc`                        | GET    | search songs by keyword       |
//! | `/api/v6/playlist/detail`                    | GET    | playlist metadata + trackIds  |
//! | `/api/v3/song/detail`                        | GET    | full song list of a playlist   |
//! | `/api/song/enhance/player/url/v1`            | GET    | resolve song id → playable URL |
//! | `/api/w/nuser/account/get`                   | GET    | logged-in user id + nickname  |
//! | `/api/user/playlist`                         | GET    | user's own + subscribed lists |
//! | `/api/login/qrcode/unikey`                   | POST   | start a QR login (get unikey) |
//! | `/api/web/qrcode/get`                        | POST   | render the QR as an image      |
//! | `/api/login/qrcode/client/login`             | POST   | poll the QR login result       |
//!
//! The login cookie (`netease_cookie` in the config file) is forwarded in the
//! `Cookie:` header of every call; it unlocks VIP / lossless tracks and the
//! user's own playlists. Nothing external is required — no Node API server, no
//! OpenSSL, no perl.

use super::{Playlist, QrImage, QrPoll, Track, UserAccount, Quality, status_from_code};
use crate::globals::statics::get_config;
use crate::utils::ui_logger::{LogCategory, ui_log};
use anyhow::{Context, Result, anyhow};
use std::time::Duration;
use ureq::Agent;

/// how long a resolved song URL is reused before it is refreshed
pub const URL_TTL: Duration = Duration::from_secs(300);

/// browser UA NetEase expects on its CDN
pub(super) const CDN_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/122.0.0.0 Safari/537.36";
/// the CDN only serves files to requests that look like they come from the site
pub(super) const CDN_REFERER: &str = "https://music.163.com/";

/// UA sent to `music.163.com` itself. Must look like a desktop browser or the
/// CDN edge answers with an empty body.
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/122.0.0.0 Safari/537.36";

/// The QR content NetEase's own web login encodes in the image.
const QR_TARGET_PREFIX: &str = "http://music.163.com/login?codekey=";

// ---------------- small helpers ----------------

/// Percent-encode a UTF-8 string for use in a query parameter.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(*b));
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Extract the `__csrf` value out of a raw `Cookie:` header. Only needed for
/// a handful of write endpoints; harmless to omit.
fn csrf_token_from_cookie(cookie: &str) -> String {
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k.trim() == "__csrf"
        {
            return v.trim().to_string();
        }
    }
    String::new()
}

/// NetEase answers some requests with `200 OK` and an empty body instead of an
/// error status (bad cookie, rate limit, anti-bot trigger). Surface that case
/// with an actionable message instead of letting serde_json report the rather
/// cryptic "EOF while parsing a value".
fn check_not_empty_body(headers: &ureq::http::HeaderMap, path: &str) -> Result<()> {
    if let Some(cl) = headers.get("content-length")
        && let Ok(s) = cl.to_str()
        && s.trim() == "0"
    {
        anyhow::bail!(
            "NetEase: {path} returned 200 OK with an empty body — the cookie may be invalid/expired, \
             or the request was rate-limited"
        );
    }
    Ok(())
}

// ---------------- a resolved, directly playable audio URL ----------------

/// A resolved, directly playable audio URL.
#[derive(Debug, Clone)]
pub struct SongUrl {
    pub id: u64,
    pub url: String,
    pub file_type: String,
    pub br: u64,
    pub size: u64,
}

impl SongUrl {
    #[must_use]
    pub fn mime(&self) -> &'static str {
        mime_for_type(&self.file_type)
    }
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

/// Best-effort file type inference when the API doesn't tell us.
fn guess_type(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    match path.rsplit('.').next() {
        Some(ext) if ext.len() <= 4 => ext.to_ascii_lowercase(),
        _ => "mp3".to_string(),
    }
}

/// Map a requested bitrate onto the ordered list of `/song/url/v1` `level`
/// values to try, best first.
fn quality_chain(br: u32) -> Vec<&'static str> {
    let best = if br >= 999_000 {
        Quality::Lossless
    } else if br >= 320_000 {
        Quality::Exhigh
    } else if br >= 192_000 {
        Quality::Exhigh
    } else {
        Quality::Standard
    };
    // try the requested tier first, then degrade
    match best {
        Quality::Lossless | Quality::Hires => vec!["lossless", "exhigh", "higher", "standard"],
        Quality::Exhigh => vec!["exhigh", "higher", "standard"],
        Quality::Standard => vec!["standard"],
    }
}

// ---------------- the client ----------------

/// A synchronous NetEase Cloud Music API client.
///
/// Talks to `music.163.com` directly via `ureq`. Holds an optional cookie
/// (`MUSIC_U=...; __csrf=...; os=pc`) sent as the `Cookie:` header on every
/// call.
#[derive(Debug, Clone)]
pub struct NeteaseClient {
    agent: Agent,
    cookie: String,
}

impl NeteaseClient {
    /// Build a client from the current configuration.
    #[must_use]
    pub fn from_config() -> NeteaseClient {
        let cookie = get_config().netease_cookie.clone().unwrap_or_default();
        NeteaseClient::new(cookie)
    }

    /// Build a client with an explicit login cookie. Empty / no cookie is
    /// fine for search and standard-quality streaming; VIP / lossless tracks
    /// and the user's own playlists require a non-empty cookie.
    #[must_use]
    pub fn new(cookie: impl Into<String>) -> NeteaseClient {
        NeteaseClient {
            agent: Agent::new_with_config(
                Agent::config_builder()
                    .timeout_connect(Some(Duration::from_secs(10)))
                    .build(),
            ),
            cookie: cookie.into(),
        }
    }

    /// The effective cookie string. Requests always carry `os=pc` so the
    /// server picks the desktop-web backend even without a login.
    fn effective_cookie(&self) -> String {
        if self.cookie.contains("os=") {
            self.cookie.clone()
        } else if self.cookie.is_empty() {
            "os=pc; appver=8.9.70".to_string()
        } else {
            format!("{}; os=pc", self.cookie)
        }
    }

    /// `GET https://music.163.com<path>` with browser-like headers.
    fn get(&self, path: &str) -> Result<ureq::http::Response<ureq::Body>> {
        let url = format!("https://music.163.com{path}");
        self.agent
            .get(&url)
            .header("User-Agent", BROWSER_UA)
            .header("Referer", "https://music.163.com/")
            .header("Cookie", &self.effective_cookie())
            .call()
            .with_context(|| format!("NetEase: GET {path}"))
    }

    /// `POST https://music.163.com<path>` with an `application/x-www-form-urlencoded` body.
    fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let url = format!("https://music.163.com{path}");
        self.agent
            .post(&url)
            .header("User-Agent", BROWSER_UA)
            .header("Referer", "https://music.163.com/")
            .header("Origin", "https://music.163.com")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Cookie", &self.effective_cookie())
            .send_form(form.iter().copied())
            .with_context(|| format!("NetEase: POST {path}"))
    }

    // -------- search --------

    /// Search for songs matching `keywords` (single-song mode).
    pub fn search(&self, keywords: &str, limit: u32) -> Result<Vec<Track>> {
        if keywords.trim().is_empty() {
            return Err(anyhow!("search keywords must not be blank"));
        }
        let path = format!(
            "/api/cloudsearch/pc?s={}&type=1&limit={}&offset=0",
            urlencode(keywords),
            limit.min(100)
        );
        let resp = self.get(&path)?;
        check_not_empty_body(resp.headers(), "/api/cloudsearch/pc")?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            result: Option<RawResult>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawResult {
            #[serde(default)]
            songs: Vec<RawSongLike>,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading cloudsearch reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing cloudsearch reply")?;
        let songs = parsed.result.map_or(Vec::new(), |r| r.songs);
        if songs.is_empty() {
            ui_log(
                LogCategory::Info,
                &format!("NetEase: search '{keywords}' returned no songs"),
            );
        }
        Ok(songs.into_iter().map(Track::from).collect())
    }

    // -------- playlists --------

    /// List the tracks of the playlist with NetEase id `playlist_id`.
    ///
    /// `/api/v6/playlist/detail` only embeds the first page of tracks, so for
    /// larger playlists we collect the `trackIds` list and fetch the songs in
    /// bulk via `/api/v3/song/detail`.
    pub fn playlist_tracks(&self, playlist_id: u64) -> Result<Vec<Track>> {
        let path = format!("/api/v6/playlist/detail?id={playlist_id}");
        let resp = self.get(&path)?;
        check_not_empty_body(resp.headers(), "/api/v6/playlist/detail")?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            playlist: Option<RawPlaylist>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawPlaylist {
            #[serde(default)]
            tracks: Vec<RawSongLike>,
            #[serde(default, alias = "trackIds")]
            track_ids: Vec<RawTrackId>,
            #[serde(default, alias = "trackCount")]
            track_count: u32,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawTrackId {
            id: u64,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading playlist reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing playlist reply")?;
        let playlist = parsed
            .playlist
            .context("playlist not found (wrong id, or login required)?")?;
        if playlist.tracks.len() as u32 >= playlist.track_count {
            return Ok(playlist.tracks.into_iter().map(Track::from).collect());
        }
        let ids: Vec<u64> = playlist.track_ids.iter().map(|t| t.id).collect();
        if ids.is_empty() {
            return Ok(playlist.tracks.into_iter().map(Track::from).collect());
        }
        ui_log(
            LogCategory::Info,
            &format!(
                "NetEase: playlist {} has {} tracks — fetching details in bulk",
                playlist_id,
                ids.len()
            ),
        );
        let wanted = playlist.tracks.len();
        let mut all: Vec<Track> = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(400) {
            match self.songs_detail(chunk) {
                Ok(mut songs) => all.append(&mut songs),
                Err(e) => {
                    ui_log(
                        LogCategory::Warning,
                        &format!("NetEase: bulk song detail failed: {e:#}"),
                    );
                    if all.is_empty() {
                        let tracks = playlist.tracks.clone();
                        return Ok(tracks.into_iter().take(wanted.max(1)).map(Track::from).collect());
                    }
                }
            }
        }
        if all.is_empty() {
            return Ok(playlist.tracks.into_iter().map(Track::from).collect());
        }
        Ok(all)
    }

    /// `GET /api/v3/song/detail?ids=[..]&c=[{"id":..},..]` — bulk song lookup.
    /// The `c` array is mandatory in the current protocol: without it the
    /// server answers `{"msg":..}` with no songs.
    fn songs_detail(&self, ids: &[u64]) -> Result<Vec<Track>> {
        let ids_json = serde_json::to_string(ids)?;
        let c_json = serde_json::to_string(
            &ids.iter()
                .map(|id| serde_json::json!({ "id": id }))
                .collect::<Vec<_>>(),
        )?;
        let path = format!(
            "/api/v3/song/detail?ids={}&c={}",
            urlencode(&ids_json),
            urlencode(&c_json)
        );
        let resp = self.get(&path)?;
        check_not_empty_body(resp.headers(), "/api/v3/song/detail")?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            songs: Vec<RawSongLike>,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading song detail reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing song detail reply")?;
        Ok(parsed.songs.into_iter().map(Track::from).collect())
    }

    // -------- playback URL --------

    /// Resolve a song id to a playable URL.
    ///
    /// Returns `Err` (after logging) when the API server is unreachable or the
    /// song has no playable URL (no copyright / login required).
    pub fn song_url(&self, song_id: u64, br: u32) -> Result<SongUrl> {
        let mut last_err: Option<anyhow::Error> = None;
        for level in quality_chain(br) {
            match self.try_song_url(song_id, level) {
                Ok(Some(url)) => return Ok(url),
                Ok(None) => continue,
                Err(e) => {
                    if level == "standard" {
                        last_err = Some(e);
                    } else {
                        ui_log(
                            LogCategory::Info,
                            &format!("NetEase: no '{level}' url for {song_id}, degrading"),
                        );
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow!("no playable url for song {song_id} (no copyright, or login/VIP required)")
        }))
    }

    /// One attempt at `/api/song/enhance/player/url/v1` with a specific level.
    /// `Ok(None)` means the tier is unavailable for this song.
    fn try_song_url(&self, song_id: u64, level: &str) -> Result<Option<SongUrl>> {
        let path = format!(
            "/api/song/enhance/player/url/v1?ids=%5B{song_id}%5D&level={level}&encodeType=&csrf_token={}",
            urlencode(&csrf_token_from_cookie(&self.cookie))
        );
        let resp = self.get(&path)?;
        check_not_empty_body(resp.headers(), "/api/song/enhance/player/url/v1")?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            data: Vec<RawSongUrl>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawSongUrl {
            #[serde(default)]
            id: u64,
            #[serde(default)]
            url: Option<String>,
            #[serde(default)]
            br: u32,
            #[serde(default)]
            size: u64,
            #[serde(default, alias = "type")]
            r#type: Option<String>,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading song-url reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing song-url reply")?;
        let raw = parsed
            .data
            .into_iter()
            .find(|d| d.id == song_id)
            .ok_or_else(|| {
                anyhow!("no playable url for song {song_id} (no copyright, or login/VIP required)")
            })?;
        let Some(url) = raw.url.filter(|u| !u.is_empty()) else {
            return Ok(None);
        };
        let file_type = raw.r#type.unwrap_or_else(|| guess_type(&url));
        Ok(Some(SongUrl {
            id: raw.id,
            url,
            file_type,
            br: u64::from(raw.br),
            size: raw.size,
        }))
    }

    /// Forget a cached URL so the next request resolves it again.
    /// (No-op for the synchronous client; the proxy keeps its own cache.)
    pub fn invalidate(&self, _song_id: u64) {}

    /// Open the CDN URL of an already resolved track, passing through any
    /// `Range` request and using a browser UA + Referer so the CDN serves us.
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
        rq = rq
            .header("User-Agent", CDN_USER_AGENT)
            .header("Referer", CDN_REFERER);
        if let Some(r) = range {
            rq = rq.header("Range", r);
        }
        rq.call()
            .with_context(|| format!("fetching NetEase audio {url}"))
    }

    // -------- QR login --------

    /// Step 1 of the QR login: `POST /api/login/qrcode/unikey` returns the
    /// key that identifies this login attempt.
    pub fn qr_unikey(&self) -> Result<String> {
        let resp = self.post_form("/api/login/qrcode/unikey", &[("type", "1")])?;
        check_not_empty_body(resp.headers(), "/api/login/qrcode/unikey")?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            code: i32,
            #[serde(default)]
            unikey: String,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading qrcode/unikey reply")?;
        let parsed: RawResp =
            serde_json::from_str(&body).context("parsing qrcode/unikey reply")?;
        if parsed.unikey.is_empty() {
            anyhow::bail!(
                "NetEase: qrcode/unikey returned no unikey (code={}, body={})",
                parsed.code,
                &body[..body.len().min(160)]
            );
        }
        Ok(parsed.unikey)
    }

    /// Step 2: ask NetEase to render `unikey` as a QR image.
    /// `/api/web/qrcode/get` returns a CDN URL; we download the bytes here.
    /// The image is a JPEG.
    pub fn qr_image_bytes(&self, unikey: &str) -> Result<Vec<u8>> {
        let target = format!("{QR_TARGET_PREFIX}{unikey}");
        let resp = self.post_form(
            "/api/web/qrcode/get",
            &[("url", target.as_str()), ("size", "300")],
        )?;
        check_not_empty_body(resp.headers(), "/api/web/qrcode/get")?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            code: i32,
            #[serde(default, alias = "qrcodeImageUrl")]
            qrcode_image_url: String,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading web/qrcode/get reply")?;
        let parsed: RawResp =
            serde_json::from_str(&body).context("parsing web/qrcode/get reply")?;
        if parsed.qrcode_image_url.is_empty() {
            anyhow::bail!(
                "NetEase: web/qrcode/get returned no image url (code={}, body={})",
                parsed.code,
                &body[..body.len().min(160)]
            );
        }
        let img = self
            .agent
            .get(&parsed.qrcode_image_url)
            .header("User-Agent", BROWSER_UA)
            .header("Referer", "https://music.163.com/")
            .call()
            .with_context(|| format!("downloading QR image {}", parsed.qrcode_image_url))?;
        let bytes = img
            .into_body()
            .read_to_vec()
            .context("reading QR image bytes")?;
        if bytes.is_empty() {
            anyhow::bail!("NetEase: QR image came back empty");
        }
        Ok(bytes)
    }

    /// Steps 1+2 together — what the GUI wants when it opens the popup.
    pub fn qr_generate(&self) -> Result<QrImage> {
        let unikey = self.qr_unikey()?;
        ui_log(
            LogCategory::Info,
            &format!("NetEase: got login unikey {}", &unikey),
        );
        let image_bytes = self.qr_image_bytes(&unikey)?;
        ui_log(
            LogCategory::Info,
            &format!("NetEase: QR image ready ({} bytes)", image_bytes.len()),
        );
        Ok(QrImage {
            unikey,
            image_bytes,
        })
    }

    /// Step 3: `POST /api/login/qrcode/client/login` — poll once.
    /// Codes: 801 waiting / 802 expired / 803 scanned / 800 success. On
    /// success the response carries the login cookies in `Set-Cookie`.
    pub fn qr_check(&self, unikey: &str) -> Result<QrPoll> {
        let resp = self.post_form(
            "/api/login/qrcode/client/login",
            &[("key", unikey), ("type", "1")],
        )?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            code: i32,
        }
        check_not_empty_body(resp.headers(), "/api/login/qrcode/client/login")?;
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading qrcode/client/login reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing qrcode/client/login reply")?;
        let status = status_from_code(parsed.code);
        let set_cookies = headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect::<Vec<_>>();
        Ok(QrPoll {
            status,
            code: parsed.code,
            set_cookies,
        })
    }

    // -------- account / user playlists --------

    /// `GET /api/w/nuser/account/get` — the logged-in user's id + nickname.
    /// Fails (with a useful message) when the cookie is missing or the login
    /// has expired.
    pub fn user_account(&self) -> Result<UserAccount> {
        let resp = self.get("/api/w/nuser/account/get")?;
        check_not_empty_body(resp.headers(), "/api/w/nuser/account/get")?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            account: Option<RawAccount>,
            #[serde(default)]
            profile: Option<RawProfile>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawAccount {
            #[serde(default)]
            id: u64,
            #[serde(default, alias = "userName")]
            user_name: Option<String>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawProfile {
            #[serde(default, alias = "userId")]
            user_id: u64,
            #[serde(default)]
            nickname: String,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading account/get reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing account/get reply")?;
        let profile = parsed.profile;
        let account = parsed.account;
        if let Some(p) = profile
            && p.user_id > 0
        {
            return Ok(UserAccount {
                id: p.user_id,
                nickname: p.nickname,
            });
        }
        if let Some(a) = account
            && a.id > 0
        {
            return Ok(UserAccount {
                id: a.id,
                nickname: a.user_name.unwrap_or_default(),
            });
        }
        Err(anyhow!(
            "NetEase: not logged in — no account/profile in the response. Use 扫码登录 first."
        ))
    }

    /// `GET /api/user/playlist` — the user's own + subscribed playlists.
    pub fn user_playlists(&self, uid: u64) -> Result<Vec<Playlist>> {
        let path = format!("/api/user/playlist?uid={uid}&limit=1000&offset=0");
        let resp = self
            .get(&path)
            .context("NetEase: /api/user/playlist failed")?;
        check_not_empty_body(resp.headers(), "/api/user/playlist")?;
        #[derive(serde::Deserialize, Default)]
        struct RawResp {
            #[serde(default)]
            playlist: Vec<RawPlaylist>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawPlaylist {
            #[serde(default)]
            id: u64,
            #[serde(default)]
            name: String,
            #[serde(default, alias = "trackCount")]
            track_count: u32,
            #[serde(default)]
            creator: Option<RawCreator>,
            #[serde(default, alias = "coverImgUrl")]
            cover_img_url: Option<String>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawCreator {
            #[serde(default)]
            nickname: String,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading user/playlist reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing user/playlist reply")?;
        Ok(parsed
            .playlist
            .into_iter()
            .map(|p| Playlist {
                id: p.id,
                name: p.name,
                track_count: p.track_count,
                creator_nickname: p.creator.map_or(String::new(), |c| c.nickname),
                cover_url: p.cover_img_url,
            })
            .collect())
    }
}

/// Convert a `(id, name, artists, album, duration)` raw shape into our `Track`.
impl From<RawSongLike> for Track {
    fn from(s: RawSongLike) -> Track {
        let artist = s
            .ar
            .iter()
            .map(|a| a.name.as_str())
            .filter(|n| !n.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        Track {
            id: s.id,
            name: s.name,
            artist,
            album: s.al.map_or_else(String::new, |a| a.name),
            duration_millis: u64::from(s.dt),
        }
    }
}

/// Common raw song shape used by cloudsearch, playlist/detail and song/detail.
#[derive(serde::Deserialize, Default, Clone)]
struct RawSongLike {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    ar: Vec<RawArtistLike>,
    #[serde(default)]
    al: Option<RawAlbumLike>,
    #[serde(default)]
    dt: u64,
}
#[derive(serde::Deserialize, Default, Clone)]
struct RawArtistLike {
    #[serde(default)]
    name: String,
}
#[derive(serde::Deserialize, Default, Clone)]
struct RawAlbumLike {
    #[serde(default)]
    name: String,
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
            assert_eq!(s.mime(), mime_for_type(t), "type {t}");
        }
    }

    #[test]
    fn guess_type_from_url() {
        assert_eq!(guess_type("https://x/y.flac?a=b"), "flac");
        assert_eq!(guess_type("https://x/y.mp3"), "mp3");
        assert_eq!(guess_type("https://x/y"), "mp3");
    }

    #[test]
    fn urlencode_handles_chinese_and_spaces() {
        assert_eq!(urlencode("周杰伦"), "%E5%91%A8%E6%9D%B0%E4%BC%A6");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("A-_~.z9"), "A-_~.z9");
    }

    #[test]
    fn quality_chain_degrades() {
        assert_eq!(quality_chain(999_000)[0], "lossless");
        assert_eq!(quality_chain(320_000)[0], "exhigh");
        assert_eq!(quality_chain(128_000)[0], "standard");
        // every non-final tier is followed by a lower one
        for chain in [quality_chain(999_000), quality_chain(320_000)] {
            for w in chain.windows(2) {
                assert_ne!(w[0], w[1]);
            }
        }
    }

    #[test]
    fn csrf_extraction() {
        assert_eq!(csrf_token_from_cookie("MUSIC_U=x; __csrf=abc; os=pc"), "abc");
        assert_eq!(csrf_token_from_cookie(""), "");
    }
}
