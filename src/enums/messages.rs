//! Inter-thread message types carried over the application's crossbeam channel.

use crate::{
    netease::{Playlist, UserAccount},
    rendercontrol::{PlayOutcome, Renderer},
    server::streaming_server::StreamerFeedBack,
    slimproto::types::SlimRenderer,
};
use ecow::EcoString;

#[derive(Debug, Clone)]
pub enum MessageType {
    SsdpMessage(Box<Renderer>), // boxed to reduce enum size
    PlayerMessage(StreamerFeedBack),
    /// outcome of a `Renderer::spawn_play()` attempt, see [`PlayOutcome`]
    PlayResult(PlayOutcome),
    LogMessage(String),
    CaptureAborted,
    /// a SlimProto (squeezelite) client sent its `HELO` handshake
    SlimHelo(Box<SlimRenderer>), // boxed to reduce enum size
    /// a SlimProto client's TCP connection dropped; `remote_addr` identifies
    /// which `SLIM_RENDERERS` entry to mark not-playing / turn its button
    /// off. `peer_port` is that connection's source port: a reconnect from
    /// the same IP refreshes the renderer's `peer_port` in place before this
    /// message is (necessarily racily) processed, so the handler must check
    /// `peer_port` still matches before clearing state — otherwise a stale
    /// disconnect notification for an already-superseded connection can
    /// clobber a newer one's `playing`/button state.
    SlimDisconnected {
        remote_addr: EcoString,
        peer_port: u16,
    },
    /// an event from the NetEase tab — QR login / playlist refresh workers
    /// post these back to the main thread, which routes them through
    /// `MainForm::on_netease_event`.
    NeteaseEvent(NeteaseEvent),
}

/// Events delivered by the NetEase tab's background workers.
#[derive(Debug, Clone)]
pub enum NeteaseEvent {
    /// QR-code login: the worker fetched the QR PNG and is now polling.
    /// The GUI should render the PNG into the popup window.
    QrImageReady { image_bytes: Vec<u8> },
    /// QR-code login: a non-terminal poll tick (waiting or scanned).
    /// The GUI should update the status label.
    QrPollTick { message: String },
    /// QR-code login: scan + confirm succeeded on the phone. The cookie is
    /// already saved to config by the worker (via `persist_login_cookie`);
    /// the GUI should hide the popup, update the user label, and trigger a
    /// playlist refresh.
    QrSuccess { nickname: Option<String> },
    /// QR-code login: QR code expired; the GUI should show the expired
    /// status and stop polling.
    QrExpired,
    /// QR-code login: transport / parse / server error.
    QrError(String),
    /// User-info fetch succeeded after a login. The GUI should show the
    /// nickname and refresh the playlist dropdown.
    UserAccountLoaded(UserAccount),
    /// User-playlists fetch succeeded. The GUI should populate the dropdown.
    PlaylistsLoaded(Vec<Playlist>),
    /// User-playlists fetch failed.
    PlaylistsFailed(String),
}
