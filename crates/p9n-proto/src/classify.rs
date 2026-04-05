//! Message classification for QUIC datagram/stream routing.

use crate::types::MsgType;

/// Classification of a 9P message for transport routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    /// Low-latency metadata: sent via QUIC datagrams.
    Metadata,
    /// Data operations: sent on independent QUIC bidirectional streams.
    Data,
    /// Server-push: arrives on a dedicated unidirectional stream (tag=0xFFFF).
    Push,
}

/// Classify a message type for QUIC routing.
///
/// Strategy: metadata operations (small, control-plane) go via datagrams for
/// minimum latency; data operations (potentially large, need ordering) go via
/// streams; server-push messages go on a dedicated unidirectional stream.
pub fn classify(t: MsgType) -> MessageClass {
    use MsgType::*;
    match t {
        // ── Push: server-initiated, tag=0xFFFF ──
        Rnotify | Rleasebreak | Rstreamdata => MessageClass::Push,

        // ── Reserved: never sent on the wire ──
        Tnotify | Tleasebreak => MessageClass::Metadata,

        // ── Metadata: small control-plane messages → datagrams ──
        Tversion | Rversion |
        Tcaps | Rcaps |
        Tstartls | Rstartls |
        Tauthneg | Rauthneg |
        Tcapgrant | Rcapgrant |
        Tcapuse | Rcapuse |
        Tauditctl | Rauditctl |
        TstartlsSpiffe | RstartlsSpiffe |
        Tfetchbundle | Rfetchbundle |
        Tspiffeverify | Rspiffeverify |
        Tsession | Rsession |
        Twatch | Rwatch |
        Tunwatch | Runwatch |
        Tlease | Rlease |
        Tleaserenew | Rleaserenew |
        Tleaseack | Rleaseack |
        Tconsistency | Rconsistency |
        Ttopology | Rtopology |
        Ttraceattr | Rtraceattr |
        Thealth | Rhealth |
        Tserverstats | Rserverstats |
        Tgetquota | Rgetquota |
        Tsetquota | Rsetquota |
        Tratelimit | Rratelimit |
        Tquicstream | Rquicstream |
        Tcxlmap | Rcxlmap |
        Tcxlcoherence | Rcxlcoherence |
        Trdmatoken | Rrdmatoken |
        Trdmanotify | Rrdmanotify |
        Tcompress | Rcompress |
        Tflush | Rflush |
        Rerror |
        Rlerror => MessageClass::Metadata,

        // ── Data: everything else (I/O, walk, stat, compound, etc.) → streams ──
        _ => MessageClass::Data,
    }
}
