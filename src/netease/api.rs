//! NetEase Cloud Music API client.
//!
//! Talks to `music.163.com` directly and signs every request itself with the
//! standard weapi / eapi crypto (AES-CBC + RSA for weapi, AES-ECB + MD5 for
//! eapi). The signing is implemented in pure Rust on top of `aes`, `cbc`,
//! `num-bigint`, `md-5`, `base64`, `rand` — **no native OpenSSL / perl
//! required**, which matters because the only viable way to get OpenSSL on
//! this machine was the `openssl-sys` vendored feature, and that needs
//! `perl` to drive OpenSSL's `Configure` script (not installed).
//!
//! Endpoints used:
//!
//! | URL                                      | crypto | purpose                                  |
//! |------------------------------------------|--------|------------------------------------------|
//! | `/weapi/cloudsearch`                     | weapi  | search songs by keyword                  |
//! | `/weapi/v6/playlist/detail`             | weapi  | list the tracks of a playlist            |
//! | `/eapi/song/enhance/player/url/v1`      | eapi   | resolve a song id to a playable URL      |

use super::{Playlist, QrImage, QrPoll, Track, UserAccount, status_from_code};
use crate::globals::statics::get_config;
use crate::utils::ui_logger::{LogCategory, ui_log};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::Agent;

/// how long a resolved song URL is reused before it is refreshed
pub const URL_TTL: Duration = Duration::from_secs(300);

/// browser UA NetEase expects on its CDN
pub(super) const CDN_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/122.0.0.0 Safari/537.36";
/// the CDN only serves files to requests that look like they come from the site
pub(super) const CDN_REFERER: &str = "https://music.163.com/";

// ---------------- crypto constants (the boring part) ----------------

/// AES-CBC IV for weapi. Hardcoded by NetEase, unchanged for years.
const WEAPI_IV: [u8; 16] = *b"0102030405060708";
/// First-layer AES key for weapi.
const WEAPI_PRESET_KEY: &[u8; 16] = b"0CoJUm6Qyw8W8jud";
/// AES-ECB key for eapi.
const EAPI_KEY: &[u8; 16] = b"e82ckenh8dichen8";
/// Salt delimiters used by eapi (literal substring, not a value).
const EAPI_SALT: &str = "36cd479b6b5";
/// Alphabet used to generate the weapi per-request key.
const BASE62: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
/// RSA public modulus (128 bytes, hex).
const RSA_MODULUS_HEX: &str = "00e0b509f6259a86498de06f6e278fe5934fe28d349f7af63f8d3c8b8c8f8e0f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f";
const RSA_EXPONENT: u32 = 0x010001; // 65537

// ---------------- low-level crypto helpers ----------------

fn aes_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    // PKCS#7 pad to a 16-byte multiple (cbc::Encryptor itself doesn't pad).
    let pad = 16 - (data.len() % 16);
    let mut buf: Vec<u8> = data
        .iter()
        .copied()
        .chain(std::iter::repeat(pad as u8).take(pad))
        .collect();
    let mut enc = cbc::Encryptor::<Aes128>::new(key.into(), iv.into());
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        enc.encrypt_block_mut(&mut block);
        chunk.copy_from_slice(&block);
    }
    buf
}

fn aes_ecb_encrypt_padded(data: &[u8], key: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    let cipher = Aes128::new(key.into());
    // PKCS#7 pad to a 16-byte multiple, then encrypt each block.
    let pad = 16 - (data.len() % 16);
    let mut buf = data.to_vec();
    buf.extend(std::iter::repeat(pad as u8).take(pad));
    let mut out = Vec::with_capacity(buf.len());
    for chunk in buf.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

fn md5_hex(input: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(input);
    let bytes = h.finalize();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Textbook RSA: `m^e mod n`, output zero-padded to 128 bytes, hex.
/// NetEase deliberately uses *no* PKCS#1 padding here (see the DeepWiki writeup
/// of their crypto scheme), so we compute it ourselves with `num-bigint`.
fn rsa_encrypt_raw(input_be: &[u8]) -> String {
    let m = BigUint::from_bytes_be(input_be);
    let n = BigUint::parse_bytes(RSA_MODULUS_HEX.as_bytes(), 16).expect("hardcoded RSA modulus");
    let e = BigUint::from(RSA_EXPONENT);
    let c = m.modpow(&e, &n);
    let mut bytes = c.to_bytes_be();
    while bytes.len() < 128 {
        bytes.insert(0, 0);
    }
    hex::encode(bytes)
}

/// Extract the `__csrf` value out of a raw `Cookie:` header. NetEase returns
/// `200 OK` with an empty body if `csrf_token` is missing or wrong, so the
/// search/playlist calls need it.
fn csrf_token_from_cookie(cookie: &str) -> &str {
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k.trim() == "__csrf"
        {
            return v.trim();
        }
    }
    ""
}

fn random_base62_key() -> String {
    let mut rng = StdRng::from_entropy();
    (0..16)
        .map(|_| BASE62[rng.gen_range(0..BASE62.len())] as char)
        .collect()
}

// ---------------- weapi / eapi signers ----------------

/// Sign a weapi payload and return `(params, encSecKey)` — the two form
/// fields NetEase expects.
fn weapi_sign(payload_json: &str) -> (String, String) {
    // 1) AES-CBC encrypt payload with the preset key, base64.
    let once = aes_cbc_encrypt(payload_json.as_bytes(), WEAPI_PRESET_KEY, &WEAPI_IV);
    let once_b64 = B64.encode(&once);
    // 2) Random 16-char base62 key, AES-CBC encrypt again, base64.
    let rkey = random_base62_key();
    let twice = aes_cbc_encrypt(once_b64.as_bytes(), rkey.as_bytes(), &WEAPI_IV);
    let params = B64.encode(&twice);
    // 3) Reverse the random key bytes and RSA-encrypt.
    let mut reversed = rkey.into_bytes();
    reversed.reverse();
    let enc_sec_key = rsa_encrypt_raw(&reversed);
    (params, enc_sec_key)
}

/// Sign an eapi body and return the hex `eparams` query string.
fn eapi_sign(url_path: &str, text: &str) -> String {
    // hash = md5("nobody" + url + "use" + text + "md5forencrypt")
    let mut pre = Vec::new();
    pre.extend_from_slice(b"nobody");
    pre.extend_from_slice(url_path.as_bytes());
    pre.extend_from_slice(b"use");
    pre.extend_from_slice(text.as_bytes());
    pre.extend_from_slice(b"md5forencrypt");
    let digest = md5_hex(&pre);
    // body = url + "-" + SALT + "-" + text + "-" + SALT + "-" + digest
    let mut body = String::with_capacity(url_path.len() + text.len() + 32);
    body.push_str(url_path);
    body.push('-');
    body.push_str(EAPI_SALT);
    body.push('-');
    body.push_str(text);
    body.push('-');
    body.push_str(EAPI_SALT);
    body.push('-');
    body.push_str(&digest);
    let ct = aes_ecb_encrypt_padded(body.as_bytes(), EAPI_KEY);
    ct.iter().map(|b| format!("{b:02X}")).collect()
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

// ---------------- the client ----------------

/// A synchronous NetEase Cloud Music API client.
///
/// Talks to `music.163.com` directly via `ureq`, signing every request with
/// the weapi / eapi helpers above. Holds an optional cookie (`MUSIC_U=...;
/// __csrf=...`) sent as the `Cookie:` header on every call.
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
    /// require a non-empty cookie.
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

    fn post<I, K, V>(&self, path: &str, form: I) -> Result<ureq::http::Response<ureq::Body>>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let url = format!("https://music.163.com{path}");
        self.agent
            .post(&url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            )
            .header("Referer", "https://music.163.com/")
            .header("Origin", "https://music.163.com")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Cookie", &self.cookie)
            .send_form(form)
            .with_context(|| format!("NetEase: POST {path}"))
    }

    /// `GET https://music.163.com<path>` with the same browser-like headers
    /// as `post()`. Used by the unauthenticated QR-login endpoints.
    fn get(&self, path: &str) -> Result<ureq::http::Response<ureq::Body>> {
        let url = format!("https://music.163.com{path}");
        self.agent
            .get(&url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            )
            .header("Referer", "https://music.163.com/")
            .header("Origin", "https://music.163.com")
            .header("Cookie", &self.cookie)
            .call()
            .with_context(|| format!("NetEase: GET {path}"))
    }

    /// Search for songs matching `keywords` (single-song mode).
    pub fn search(&self, keywords: &str, limit: u32) -> Result<Vec<Track>> {
        if keywords.trim().is_empty() {
            return Err(anyhow!("search keywords must not be blank"));
        }
        let csrf = csrf_token_from_cookie(&self.cookie);
        if csrf.is_empty() {
            ui_log(
                LogCategory::Warning,
                "NetEase: cookie is missing __csrf — search will return an empty body",
            );
        }
        ui_log(
            LogCategory::Info,
            &format!(
                "NetEase: search '{}' cookie_len={} csrf8={}",
                keywords,
                self.cookie.len(),
                &csrf[..csrf.len().min(8)]
            ),
        );
        let payload = serde_json::json!({
            "s": keywords,
            "type": 1,
            "limit": limit.min(100),
            "offset": 0,
            "csrf_token": csrf,
        })
        .to_string();
        let (params, enc_sec_key) = weapi_sign(&payload);
        let resp = self
            .post(
                "/weapi/cloudsearch/get",
                [
                    ("params", params.as_str()),
                    ("encSecKey", enc_sec_key.as_str()),
                ],
            )
            .context("NetEase: /weapi/cloudsearch/get failed")?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            result: RawResult,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawResult {
            #[serde(default)]
            songs: Vec<RawSongLike>,
        }
        check_not_empty_body(resp.headers(), "/weapi/cloudsearch/get")?;
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading cloudsearch reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing cloudsearch reply")?;
        Ok(parsed.result.songs.into_iter().map(Track::from).collect())
    }

    /// List the tracks of the playlist with NetEase id `playlist_id`.
    pub fn playlist_tracks(&self, playlist_id: u64) -> Result<Vec<Track>> {
        let csrf = csrf_token_from_cookie(&self.cookie);
        if csrf.is_empty() {
            ui_log(
                LogCategory::Warning,
                "NetEase: cookie is missing __csrf — playlist lookup will return an empty body",
            );
        }
        let payload = serde_json::json!({
            "id": playlist_id,
            "n": 1000,
            "s": 0,
            "csrf_token": csrf,
        })
        .to_string();
        let (params, enc_sec_key) = weapi_sign(&payload);
        let resp = self
            .post(
                "/weapi/v6/playlist/detail",
                [
                    ("params", params.as_str()),
                    ("encSecKey", enc_sec_key.as_str()),
                ],
            )
            .context("NetEase: /weapi/v6/playlist/detail failed")?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            playlist: Option<RawPlaylist>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawPlaylist {
            #[serde(default)]
            tracks: Vec<RawSongLike>,
        }
        check_not_empty_body(resp.headers(), "/weapi/v6/playlist/detail")?;
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading playlist reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing playlist reply")?;
        let tracks = parsed
            .playlist
            .context("playlist not found (wrong id, or login required)?")?
            .tracks;
        Ok(tracks.into_iter().map(Track::from).collect())
    }

    /// Resolve a song id to a playable URL.
    ///
    /// Returns `Err` (after logging) when the API server is unreachable or the
    /// song has no playable URL (no copyright / login required).
    pub fn song_url(&self, song_id: u64, br: u32) -> Result<SongUrl> {
        let payload = serde_json::json!({
            "ids": [song_id],
            "br": br,
        })
        .to_string();
        let path = "/api/song/enhance/player/url/v1";
        let eparams = eapi_sign(path, &payload);
        let url = format!("https://music.163.com{path}?eparams={eparams}");
        let resp = self
            .agent
            .post(&url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            )
            .header("Referer", "https://music.163.com/")
            .header("Cookie", &self.cookie)
            .send_form([("os", "pc")])
            .context("NetEase: POST song/enhance/player/url/v1")?;
        #[derive(serde::Deserialize)]
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
            #[serde(default)]
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
        let url = raw.url.filter(|u| !u.is_empty()).ok_or_else(|| {
            anyhow!("no playable url for song {song_id} (no copyright, or login/VIP required)")
        })?;
        let file_type = raw.r#type.unwrap_or_else(|| guess_type(&url));
        Ok(SongUrl {
            id: raw.id,
            url,
            file_type,
            br: u64::from(raw.br),
            size: raw.size,
        })
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

    /// GET `/api/login/qrcode/generate?type=1&realtype=1`. The `qrimg` field
    /// is a `data:image/png;base64,...` data URI; we strip the prefix and
    /// return the raw PNG bytes so the GUI can decode them straight into a
    /// `PngImage`.
    pub fn qr_generate(&self) -> Result<QrImage> {
        let resp = self.get("/api/login/qrcode/generate?type=1&realtype=1")?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            data: Option<RawQrData>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawQrData {
            #[serde(default)]
            unikey: String,
            #[serde(default)]
            qrimg: String,
        }
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading qrcode/generate reply")?;
        let parsed: RawResp =
            serde_json::from_str(&body).context("parsing qrcode/generate reply")?;
        let data = parsed
            .data
            .context("NetEase: qrcode/generate response missing `data`")?;
        if data.unikey.is_empty() {
            anyhow::bail!("NetEase: qrcode/generate returned empty unikey");
        }
        let png_bytes =
            crate::netease::login::decode_qr_data_uri(&data.qrimg).context("qrcode qrimg")?;
        Ok(QrImage {
            unikey: data.unikey,
            png_bytes,
        })
    }

    /// GET `/api/login/qrcode/check?type=1&key=<unikey>&timestamp=<ms>`.
    /// Returns the numeric code + Set-Cookie headers (only populated on
    /// success).
    pub fn qr_check(&self, unikey: &str) -> Result<QrPoll> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let path = format!("/api/login/qrcode/check?type=1&key={unikey}&timestamp={ts}");
        let resp = self.get(&path)?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            code: i32,
        }
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading qrcode/check reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing qrcode/check reply")?;
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

    /// POST `/weapi/nuser/account/get` — returns the logged-in user's id +
    /// nickname. Fails (with a useful message) when the cookie is missing or
    /// the login has expired.
    pub fn user_account(&self) -> Result<UserAccount> {
        let payload = serde_json::json!({
            "csrf_token": csrf_token_from_cookie(&self.cookie),
        })
        .to_string();
        let (params, enc_sec_key) = weapi_sign(&payload);
        let resp = self
            .post(
                "/weapi/nuser/account/get",
                [
                    ("params", params.as_str()),
                    ("encSecKey", enc_sec_key.as_str()),
                ],
            )
            .context("NetEase: /weapi/nuser/account/get failed")?;
        #[derive(serde::Deserialize)]
        struct RawResp {
            #[serde(default)]
            profile: Option<RawProfile>,
        }
        #[derive(serde::Deserialize, Default)]
        struct RawProfile {
            #[serde(default, alias = "userId")]
            user_id: u64,
            #[serde(default)]
            nickname: String,
        }
        check_not_empty_body(resp.headers(), "/weapi/nuser/account/get")?;
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading account/get reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing account/get reply")?;
        let profile = parsed
            .profile
            .context("NetEase: account/get returned no profile — not logged in?")?;
        Ok(UserAccount {
            id: profile.user_id,
            nickname: profile.nickname,
        })
    }

    /// POST `/weapi/user/playlist` — returns the user's own + subscribed
    /// playlists.
    pub fn user_playlists(&self, uid: u64) -> Result<Vec<Playlist>> {
        let payload = serde_json::json!({
            "uid": uid,
            "offset": 0,
            "limit": 1000,
            "csrf_token": csrf_token_from_cookie(&self.cookie),
        })
        .to_string();
        let (params, enc_sec_key) = weapi_sign(&payload);
        let resp = self
            .post(
                "/weapi/user/playlist",
                [
                    ("params", params.as_str()),
                    ("encSecKey", enc_sec_key.as_str()),
                ],
            )
            .context("NetEase: /weapi/user/playlist failed")?;
        #[derive(serde::Deserialize)]
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
        check_not_empty_body(resp.headers(), "/weapi/user/playlist")?;
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

/// NetEase returns 200 OK with `content-length: 0` when something about the
/// request is wrong (missing csrf_token, bad signature, anti-bot trigger).
/// Surface that case as a specific, actionable error before serde_json
/// chokes on an empty string with the unhelpful "EOF while parsing" message.
fn check_not_empty_body(headers: &ureq::http::HeaderMap, path: &str) -> Result<()> {
    if let Some(cl) = headers.get("content-length")
        && let Ok(s) = cl.to_str()
        && s.trim() == "0"
    {
        anyhow::bail!(
            "NetEase: {path} returned 200 OK with empty body — cookie is invalid, expired, or missing __csrf"
        );
    }
    Ok(())
}

/// Convert a `(id, name, artists, album, duration)` raw shape into our `Track`.
impl From<RawSongLike> for Track {
    fn from(s: RawSongLike) -> Track {
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
            duration_millis: u64::from(s.dt),
        }
    }
}

/// Common raw song shape used by both cloudsearch and playlist/detail.
#[derive(serde::Deserialize, Default)]
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
#[derive(serde::Deserialize, Default)]
struct RawArtistLike {
    #[serde(default)]
    name: String,
}
#[derive(serde::Deserialize, Default)]
struct RawAlbumLike {
    #[serde(default)]
    name: String,
}

/// Best-effort file type inference when the API doesn't tell us.
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
    fn rsa_textbook_encryption_is_deterministic() {
        // Same input -> same ciphertext. Verifies our BigUint modpow path is
        // wired up correctly (the modpow itself is well-tested upstream; this
        // catches accidental byte-order / n-parsing mistakes here).
        let a = rsa_encrypt_raw(b"hello-world-key1");
        let b = rsa_encrypt_raw(b"hello-world-key1");
        let c = rsa_encrypt_raw(b"hello-world-key2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 256); // 128 bytes hex
    }
}
