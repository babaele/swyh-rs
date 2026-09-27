//! Sequential playback of a list of NetEase tracks on one renderer.
//!
//! [`start_netease_queue`] pushes the first track to the renderer (via
//! `SetAVTransportURI`/OpenHome `Insert`) and then waits for it to finish before
//! pushing the next one, so a whole playlist plays without any user interaction.
//! The renderer pulls the audio from [`super::proxy`], which relays the original
//! file unmodified.
//!
//! "Finished" is decided by polling the renderer's `GetPositionInfo` and falling
//! back to wall-clock time when the renderer does not report a position.

use super::{
    Track, format_duration,
    proxy::{netease_track_url, resolve_track},
};
use crate::{
    globals::statics::THREAD_STACK,
    rendercontrol::{PositionInfo, Renderer, UriPlayInfo},
    utils::ui_logger::{LogCategory, ui_log},
};
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use std::{
    net::IpAddr,
    sync::{Arc, LazyLock, Mutex},
    thread,
    time::{Duration, Instant},
};

/// Commands the UI can send to the running queue thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeteaseCmd {
    /// skip to the next track
    Next,
    /// stop playback and end the queue
    Stop,
}

/// how often the queue thread polls the renderer while a track plays
const POLL_INTERVAL: Duration = Duration::from_millis(1000);
/// grace period before the wall-clock fallback declares a track finished
const END_GRACE_SECS: f64 = 3.0;

/// Handle to the currently running queue, if any.
struct QueueHandle {
    cmd_tx: Sender<NeteaseCmd>,
}

/// Only one NetEase queue can run at a time (one renderer, one playlist).
static CURRENT: LazyLock<Mutex<Option<QueueHandle>>> = LazyLock::new(|| Mutex::new(None));

/// Start playing `tracks` (from `start_index`) on `renderer`, one after another.
///
/// The renderer is not moved into the queue thread (FLTK widget handles make
/// `Renderer` `!Send` in GUI builds), only its `Send` + `Sync` `Controller`.
pub fn start_netease_queue(
    renderer: &Renderer,
    local_addr: IpAddr,
    server_port: u16,
    tracks: Vec<Track>,
    start_index: usize,
) {
    if tracks.is_empty() {
        ui_log(LogCategory::Warning, "NetEase: nothing to play");
        return;
    }
    let (cmd_tx, cmd_rx) = unbounded::<NeteaseCmd>();
    {
        let Ok(mut current) = CURRENT.lock() else {
            ui_log(LogCategory::Error, "NetEase: queue lock poisoned");
            return;
        };
        *current = Some(QueueHandle { cmd_tx });
    }
    let controller = renderer.controller.clone();
    let start = start_index.min(tracks.len() - 1);
    let spawned = thread::Builder::new()
        .name("netease_queue".into())
        .stack_size(THREAD_STACK)
        .spawn(move || {
            run_queue(controller, local_addr, server_port, tracks, start, &cmd_rx);
        });
    if let Err(e) = spawned {
        ui_log(
            LogCategory::Error,
            &format!("NetEase: failed to spawn queue thread: {e}"),
        );
        if let Ok(mut current) = CURRENT.lock() {
            *current = None;
        }
    }
}

/// Skip to the next track of the running queue (no-op when nothing plays).
pub fn netease_next() {
    send(NeteaseCmd::Next);
}

/// Stop the running queue (no-op when nothing plays).
pub fn netease_stop() {
    send(NeteaseCmd::Stop);
}

/// Is a queue currently running?
#[must_use]
pub fn queue_running() -> bool {
    CURRENT.lock().map(|c| c.is_some()).unwrap_or(false)
}

fn send(cmd: NeteaseCmd) {
    let Ok(current) = CURRENT.lock() else {
        return;
    };
    if let Some(handle) = current.as_ref() {
        let _ = handle.cmd_tx.send(cmd);
    }
}

/// The queue thread's main loop: push one track, wait for it, repeat.
fn run_queue(
    controller: Arc<crate::rendercontrol::Controller>,
    local_addr: IpAddr,
    server_port: u16,
    tracks: Vec<Track>,
    start_index: usize,
    cmd_rx: &Receiver<NeteaseCmd>,
) {
    let mut index = start_index;
    while index < tracks.len() {
        let track = &tracks[index];
        let Some(song) = resolve_track(track.id) else {
            index += 1;
            continue;
        };
        let info = UriPlayInfo {
            uri: netease_track_url(local_addr, server_port, track.id, song.ext()),
            title: track.name.clone(),
            artist: track.artist.clone(),
            album: track.album.clone(),
            duration: format_duration(track.duration_secs()),
            mime: song.mime().to_string(),
        };
        ui_log(
            LogCategory::Info,
            &format!(
                "NetEase: [{}] {} - {} ({}) {}",
                index + 1,
                track.name,
                track.artist,
                song.file_type,
                info.uri
            ),
        );
        match controller.play_uri(&info) {
            Ok(()) => (),
            Err(e) => {
                ui_log(
                    LogCategory::Error,
                    &format!("NetEase: play failed on {}: {e}", controller.dev_name),
                );
                break;
            }
        }
        match wait_for_end(&controller, track.duration_secs(), cmd_rx) {
            WaitResult::Next | WaitResult::Ended => index += 1,
            WaitResult::Stop => {
                controller.stop_play();
                break;
            }
        }
    }
    if let Ok(mut current) = CURRENT.lock() {
        *current = None;
    }
    ui_log(LogCategory::Info, "NetEase: queue finished");
}

/// Why [`wait_for_end`] returned.
enum WaitResult {
    /// the track finished playing
    Ended,
    /// the user asked for the next track
    Next,
    /// the user asked to stop
    Stop,
}

/// Block until the current track has finished or a command arrives.
fn wait_for_end(
    controller: &crate::rendercontrol::Controller,
    duration_secs: f64,
    cmd_rx: &Receiver<NeteaseCmd>,
) -> WaitResult {
    // give the renderer a moment to pick up the URI before trusting it
    thread::sleep(POLL_INTERVAL);
    let started = Instant::now();
    loop {
        match cmd_rx.try_recv() {
            Ok(NeteaseCmd::Stop) => return WaitResult::Stop,
            Ok(NeteaseCmd::Next) => return WaitResult::Next,
            Err(TryRecvError::Disconnected) => return WaitResult::Stop,
            Err(TryRecvError::Empty) => {}
        }
        let elapsed = started.elapsed().as_secs_f64();
        let pos: Option<PositionInfo> = controller.position_info();
        if duration_secs > 0.0 {
            if let Some(p) = &pos {
                let stopped = p.transport_state.eq_ignore_ascii_case("STOPPED");
                if stopped && elapsed > END_GRACE_SECS {
                    return WaitResult::Ended;
                }
                if p.rel_time > 0.5 && p.rel_time >= duration_secs - 1.0 {
                    return WaitResult::Ended;
                }
            }
            // wall-clock fallback: the renderer may not report a position at all
            if elapsed > duration_secs + END_GRACE_SECS {
                return WaitResult::Ended;
            }
        } else if elapsed > END_GRACE_SECS
            && pos.is_some_and(|p| p.transport_state.eq_ignore_ascii_case("STOPPED"))
        {
            // unknown duration: only the renderer can tell us it is done
            return WaitResult::Ended;
        }
        thread::sleep(POLL_INTERVAL);
    }
}
