//! `Debug` for the messages that carry a secret (resume tokens) or user text
//! (client info, custom status): the shape and lengths only. ARCHITECTURE § 6.2
//! and § 6.3 say these are never logged; this keeps a stray `{:?}` from doing so.

use std::fmt;

use crate::v1::{ClientInfo, PresenceUpdate, Resume, SetPresence, Welcome, welcome};

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

impl fmt::Debug for Resume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resume")
            .field("token", &Redacted(self.token.len()))
            .field("last_seq", &self.last_seq)
            .finish()
    }
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Welcome")
            .field("session_id", &self.session_id)
            .field("account_id", &self.account_id)
            .field("membership", &self.membership)
            .field("resume_token", &redacted(&self.resume_token))
            .field("device_list", &self.device_list)
            .field("state", &self.state)
            .finish()
    }
}

impl fmt::Debug for ClientInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientInfo")
            .field("name", &Redacted(self.name.len()))
            .field("version", &Redacted(self.version.len()))
            .finish()
    }
}

impl fmt::Debug for PresenceUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresenceUpdate")
            .field("account_id", &self.account_id)
            .field("status", &self.status())
            .field("custom_status", &Redacted(self.custom_status.len()))
            .finish()
    }
}

impl fmt::Debug for SetPresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetPresence")
            .field("status", &self.status.map(|_| self.status()))
            .field("afk", &self.afk)
            .field("custom_status", &redacted(&self.custom_status))
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
