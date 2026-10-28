//! `Debug` for the messages that carry a secret (resume tokens), user text
//! (client info, custom status) or other bytes a peer fills freely (error text,
//! signed device-list bodies): the shape and lengths only. ARCHITECTURE § 6.2
//! and § 6.3 say these are never logged; this keeps a stray `{:?}` from doing so.
//!
//! The messages are listed in `redacted_debug.txt` (read by build.rs), and
//! `tests/wire_surface.rs` fails on any text field that is neither redacted nor
//! listed as public. Each impl destructures its message without `..`, so a new
//! field is a compile error here rather than a silent omission.

use std::fmt;

use crate::v1::{
    ClientInfo, Error, ErrorCode, PresenceStatus, PresenceUpdate, Resume, SetPresence,
    SignedDeviceList, Welcome, welcome,
};

/// Stands in for a redacted value: shows only how long it was.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

fn redacted<T: AsRef<[u8]>>(value: &Option<T>) -> Option<Redacted> {
    value.as_ref().map(|v| Redacted(v.as_ref().len()))
}

/// A status as received: a value from a newer peer shows as its number.
struct Status(i32);

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match PresenceStatus::try_from(self.0) {
            Ok(status) => status.fmt(f),
            Err(_) => write!(f, "Unknown({})", self.0),
        }
    }
}

/// An error code as received: a value from a newer peer shows as its number.
struct Code(i32);

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match ErrorCode::try_from(self.0) {
            Ok(code) => code.fmt(f),
            Err(_) => write!(f, "Unknown({})", self.0),
        }
    }
}

// A decoded Error's text comes from the peer, not from `Error::new`'s
// `&'static str`: it is redacted like any other peer text.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            code,
            message,
            retry_after_ms,
            device_list,
        } = self;
        f.debug_struct("Error")
            .field("code", &Code(*code))
            .field("message", &Redacted(message.len()))
            .field("retry_after_ms", retry_after_ms)
            .field("device_list", device_list)
            .finish()
    }
}

impl fmt::Debug for SignedDeviceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { body, signature } = self;
        f.debug_struct("SignedDeviceList")
            .field("body", &Redacted(body.len()))
            .field("signature", signature)
            .finish()
    }
}

impl fmt::Debug for Resume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { token, last_seq } = self;
        f.debug_struct("Resume")
            .field("token", &Redacted(token.len()))
            .field("last_seq", last_seq)
            .finish()
    }
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            session_id,
            account_id,
            membership,
            resume_token,
            device_list,
            state,
        } = self;
        f.debug_struct("Welcome")
            .field("session_id", session_id)
            .field("account_id", account_id)
            .field("membership", membership)
            .field("resume_token", &redacted(resume_token))
            .field("device_list", device_list)
            .field("state", state)
            .finish()
    }
}

impl fmt::Debug for welcome::State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(snapshot) => f.debug_tuple("Snapshot").field(snapshot).finish(),
            Self::Resumed(resumed) => f.debug_tuple("Resumed").field(resumed).finish(),
        }
    }
}

impl fmt::Debug for ClientInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { name, version } = self;
        f.debug_struct("ClientInfo")
            .field("name", &Redacted(name.len()))
            .field("version", &Redacted(version.len()))
            .finish()
    }
}

impl fmt::Debug for PresenceUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            account_id,
            status,
            custom_status,
        } = self;
        f.debug_struct("PresenceUpdate")
            .field("account_id", account_id)
            .field("status", &Status(*status))
            .field("custom_status", &Redacted(custom_status.len()))
            .finish()
    }
}

impl fmt::Debug for SetPresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            status,
            afk,
            custom_status,
        } = self;
        f.debug_struct("SetPresence")
            .field("status", &status.map(Status))
            .field("afk", afk)
            .field("custom_status", &redacted(custom_status))
            .finish()
    }
}
