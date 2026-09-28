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

use super::Track;
use crate::globals::statics::get_config;
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::time::Duration;
use ureq::Agent;

/// how long a resolved song URL is reused before it is refreshed
pub const URL_TTL: Duration = Duration::from_secs(300);

/// browser UA NetEase expects on its CDN
pub(super) const CDN_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
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

    /// Search for songs matching `keywords` (single-song mode).
    pub fn search(&self, keywords: &str, limit: u32) -> Result<Vec<Track>> {
        if keywords.trim().is_empty() {
            return Err(anyhow!("search keywords must not be blank"));
        }
        let payload = serde_json::json!({
            "s": keywords,
            "type": 1,
            "limit": limit.min(100),
            "offset": 0,
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
        let body = resp
            .into_body()
            .read_to_string()
            .context("reading cloudsearch reply")?;
        let parsed: RawResp = serde_json::from_str(&body).context("parsing cloudsearch reply")?;
        Ok(parsed.result.songs.into_iter().map(Track::from).collect())
    }

    /// List the tracks of the playlist with NetEase id `playlist_id`.
    pub fn playlist_tracks(&self, playlist_id: u64) -> Result<Vec<Track>> {
        let payload = serde_json::json!({
            "id": playlist_id,
            "n": 1000,
            "s": 0,
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
        let url = raw
            .url
            .filter(|u| !u.is_empty())
            .ok_or_else(|| anyhow!("no playable url for song {song_id} (no copyright, or login/VIP required)"))?;
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
        rq.call().with_context(|| format!("fetching NetEase audio {url}"))
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