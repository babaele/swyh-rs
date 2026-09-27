//! HTTP relay that serves NetEase audio to a renderer **without transcoding**.
//!
//! The renderer is pointed at `http://<swyh-rs>:<port>/netease/<song-id>.<ext>`.
//! On every request the song id is resolved to a NetEase CDN URL (see
//! [`super::api`]) and the upstream bytes are piped straight through: no
//! decoding, no re-encoding, no sample-rate or bit-depth conversion.
//!
//! `Range` requests are forwarded upstream so a renderer can seek, and `HEAD`
//! is answered with headers only.

use super::api::{NeteaseClient, SongUrl, URL_TTL};
use crate::utils::ui_logger::{LogCategory, ui_log};
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{LazyLock, RwLock},
    time::Instant,
};
use tiny_http_dh::{Header, Method, Request, Response, StatusCode};

/// URL prefix under which NetEase tracks are served
pub const NETEASE_PATH_PREFIX: &str = "/netease/";

/// Resolved song URLs, keyed by song id, with the instant they were resolved.
///
/// NetEase URLs are signed and expire (roughly 20 minutes), so they are cached
/// for [`URL_TTL`] only — short enough to stay valid, long enough that a
/// renderer's `HEAD` + `GET` pair costs a single API call.
static URL_CACHE: LazyLock<RwLock<HashMap<u64, (Instant, SongUrl)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Parse a request path like `/netease/1815628781.flac` into its song id.
///
/// The optional suffix (the file extension) is ignored — it is only there so
/// renderers that sniff the URL extension get the right hint. A path carrying
/// anything else after the id (a query string or another path segment) is
/// rejected, so a caller that forgot to strip the query string can't silently
/// get a song id it did not ask for.
#[must_use]
pub fn parse_netease_path(path: &str) -> Option<u64> {
    let rest = path.strip_prefix(NETEASE_PATH_PREFIX)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let tail = &rest[digits.len()..];
    if !tail.is_empty() && !tail.starts_with('.') {
        return None;
    }
    if tail.contains(['/', '\\', '?']) {
        return None;
    }
    digits.parse().ok()
}

/// Build the URL a renderer should be pointed at for `id`.
#[must_use]
pub fn netease_track_url(local_addr: IpAddr, server_port: u16, id: u64, ext: &str) -> String {
    format!("http://{local_addr}:{server_port}{NETEASE_PATH_PREFIX}{id}.{ext}")
}

/// Resolve the CDN URL for `song_id`, memoised for [`URL_TTL`].
///
/// Returns `None` (after logging) when the API server is unreachable or the
/// song has no playable URL (no copyright / login required).
#[must_use]
pub fn resolve_track(song_id: u64) -> Option<SongUrl> {
    {
        let Ok(cache) = URL_CACHE.read() else {
            return None;
        };
        if let Some((resolved_at, song)) = cache.get(&song_id)
            && resolved_at.elapsed() < URL_TTL
        {
            return Some(song.clone());
        }
    }
    let client = NeteaseClient::from_config();
    match client.song_url(song_id) {
        Ok(song) => {
            if let Ok(mut cache) = URL_CACHE.write() {
                cache.insert(song_id, (Instant::now(), song.clone()));
            }
            Some(song)
        }
        Err(e) => {
            ui_log(LogCategory::Error, &format!("NetEase: {e:#}"));
            None
        }
    }
}

/// Forget a cached URL so the next request resolves it again.
///
/// Used when an upstream fetch fails: a signed URL can expire or be revoked
/// while it is still inside its cache window.
pub fn invalidate(song_id: u64) {
    if let Ok(mut cache) = URL_CACHE.write() {
        cache.remove(&song_id);
    }
}

/// Serve one `/netease/<id>` request. Consumes `rq`.
pub fn serve_netease_track(rq: Request, song_id: u64) {
    let head_only = matches!(*rq.method(), Method::Head);
    if !head_only && !matches!(*rq.method(), Method::Get) {
        respond_error(rq, 405, "only GET and HEAD are supported");
        return;
    }
    let Some(song) = resolve_track(song_id) else {
        respond_error(rq, 404, &format!("no playable url for song {song_id}"));
        return;
    };
    let range = rq
        .headers()
        .iter()
        .find(|h| h.field.equiv("range"))
        .map(|h| h.value.as_str().to_string());
    relay(rq, &song, range.as_deref(), head_only);
}

/// Pipe the upstream audio through to the renderer, unmodified; consumes `rq`.
fn relay(rq: Request, song: &SongUrl, range: Option<&str>, head_only: bool) {
    let client = NeteaseClient::from_config();
    let resp = match client.open_cdn(&song.url, range, head_only) {
        Ok(r) => r,
        Err(e) => {
            ui_log(LogCategory::Error, &format!("NetEase: {e:#}"));
            invalidate(song.id);
            respond_error(rq, 502, &format!("{e:#}"));
            return;
        }
    };
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        ui_log(
            LogCategory::Error,
            &format!("NetEase CDN returned HTTP {status} for song {}", song.id),
        );
        invalidate(song.id);
        respond_error(rq, 502, &format!("NetEase CDN returned HTTP {status}"));
        return;
    }
    // copy the headers we forward before the body is moved out of `resp`
    let content_type = header_str(&resp, "content-type").unwrap_or_else(|| song.mime().to_string());
    let content_length = header_str(&resp, "content-length").and_then(|s| s.parse::<usize>().ok());
    let content_range = header_str(&resp, "content-range");

    let mut headers = std_headers();
    push(&mut headers, "Content-Type", &content_type);
    // Safe here (unlike on the live-capture endpoint, which announced a fake
    // Content-Length): this is a real, seekable file with a real length, so
    // advertising range support cannot send a client into a GET loop.
    push(&mut headers, "Accept-Ranges", "bytes");
    if let Some(cr) = &content_range {
        push(&mut headers, "Content-Range", cr);
    } else if status == 206
        && let Some(len) = content_length
    {
        // upstream honoured the range but did not echo Content-Range
        push(&mut headers, "Content-Range", &full_range(range, len));
    }
    // no `TransferMode.dlna.org: Streaming`: this is a seekable file, not a
    // live stream, and claiming Streaming would tell renderers not to seek

    let result = if head_only {
        let response = Response::new(StatusCode(status), headers, io::empty(), Some(0), None);
        rq.respond(response)
    } else {
        let reader = resp.into_body().into_reader();
        let response = Response::new(StatusCode(status), headers, reader, content_length, None);
        rq.respond(response)
    };
    if let Err(e) = result {
        ui_log(
            LogCategory::Error,
            &format!("NetEase: sending song {} failed: {e}", song.id),
        );
    }
}

/// Read a response header as a `String`, if present and valid UTF-8.
fn header_str(resp: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string)
}

/// `bytes <start>-<start+len-1>/<start+len>` for a `bytes=<start>-` request
fn full_range(range: Option<&str>, len: usize) -> String {
    let start = range
        .and_then(|r| r.strip_prefix("bytes="))
        .and_then(|r| r.split_once('-'))
        .and_then(|(s, _)| s.parse::<u64>().ok())
        .unwrap_or(0);
    let total = start + len as u64;
    format!("bytes {start}-{}/{total}", total - 1)
}

/// The headers every response carries.
fn std_headers() -> Vec<Header> {
    let mut headers = Vec::with_capacity(8);
    push(&mut headers, "Server", "swyh-rs tiny-http");
    push(&mut headers, "Connection", "close");
    headers
}

/// Build a header; skipped if the value cannot be encoded as a header field
/// (never happens for the ASCII values used here).
fn push(headers: &mut Vec<Header>, name: &str, value: &str) {
    if let Ok(h) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
        headers.push(h);
    }
}

/// Reply with a status code and an empty body, logging `reason`.
fn respond_error(rq: Request, status: u16, reason: &str) {
    ui_log(
        LogCategory::Error,
        &format!("NetEase: HTTP {status} - {reason}"),
    );
    let mut headers = std_headers();
    push(&mut headers, "Content-Type", "text/plain; charset=utf-8");
    let response = Response::new(StatusCode(status), headers, io::empty(), Some(0), None);
    if let Err(e) = rq.respond(response) {
        ui_log(
            LogCategory::Error,
            &format!("NetEase: error sending HTTP {status}: {e}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_track_paths() {
        assert_eq!(parse_netease_path("/netease/12345.flac"), Some(12345));
        assert_eq!(parse_netease_path("/netease/12345"), Some(12345));
        assert_eq!(parse_netease_path("/netease/12345.mp3?x=1"), None);
        assert_eq!(parse_netease_path("/netease/"), None);
        assert_eq!(parse_netease_path("/netease/abc"), None);
        assert_eq!(parse_netease_path("/stream/swyh.flac"), None);
        assert_eq!(parse_netease_path("/netease"), None);
    }

    #[test]
    fn builds_track_url() {
        let addr: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(
            netease_track_url(addr, 5901, 42, "flac"),
            "http://192.168.1.5:5901/netease/42.flac"
        );
    }

    #[test]
    fn content_range_of_open_ended_request() {
        assert_eq!(full_range(Some("bytes=0-"), 100), "bytes 0-99/100");
        assert_eq!(full_range(Some("bytes=10-"), 100), "bytes 10-109/110");
        assert_eq!(full_range(None, 100), "bytes 0-99/100");
    }
}
