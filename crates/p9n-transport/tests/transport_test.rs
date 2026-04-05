//! Unit tests for p9n-transport: framing and router.

use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;

// ═══════════════════ Framing: encode/decode ═══════════════════

mod framing_tests {
    use super::*;
    use p9n_transport::framing;

    #[test]
    fn test_encode_decode_round_trip() {
        let fc = Fcall {
            size: 0,
            msg_type: MsgType::Tversion,
            tag: 1,
            msg: Msg::Version { msize: 65536, version: "9P2000.N".into() },
        };
        let wire = framing::encode(&fc).unwrap();
        let decoded = framing::decode(&wire).unwrap();
        assert_eq!(decoded.msg_type, MsgType::Tversion);
        assert_eq!(decoded.tag, 1);
        match decoded.msg {
            Msg::Version { msize, version } => {
                assert_eq!(msize, 65536);
                assert_eq!(version, "9P2000.N");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_encode_decode_read() {
        let fc = Fcall {
            size: 0,
            msg_type: MsgType::Tread,
            tag: 42,
            msg: Msg::Read { fid: 7, offset: 1024, count: 4096 },
        };
        let wire = framing::encode(&fc).unwrap();
        let decoded = framing::decode_owned(wire).unwrap();
        match decoded.msg {
            Msg::Read { fid, offset, count } => {
                assert_eq!(fid, 7);
                assert_eq!(offset, 1024);
                assert_eq!(count, 4096);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_encode_decode_write_with_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let fc = Fcall {
            size: 0,
            msg_type: MsgType::Twrite,
            tag: 5,
            msg: Msg::Write { fid: 3, offset: 0, data: data.clone() },
        };
        let wire = framing::encode(&fc).unwrap();
        let decoded = framing::decode_owned(wire).unwrap();
        match decoded.msg {
            Msg::Write { fid, offset, data: d } => {
                assert_eq!(fid, 3);
                assert_eq!(offset, 0);
                assert_eq!(d, data);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_encode_decode_lerror() {
        let fc = Fcall {
            size: 0,
            msg_type: MsgType::Rlerror,
            tag: 10,
            msg: Msg::Lerror { ecode: 2 },
        };
        let wire = framing::encode(&fc).unwrap();
        let decoded = framing::decode(&wire).unwrap();
        match decoded.msg {
            Msg::Lerror { ecode } => assert_eq!(ecode, 2),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_encode_decode_empty_msg() {
        let fc = Fcall {
            size: 0,
            msg_type: MsgType::Rclunk,
            tag: 99,
            msg: Msg::Empty,
        };
        let wire = framing::encode(&fc).unwrap();
        let decoded = framing::decode_owned(wire).unwrap();
        assert_eq!(decoded.msg_type, MsgType::Rclunk);
        assert!(matches!(decoded.msg, Msg::Empty));
    }
}

// ═══════════════════ Framing: async read/write ═══════════════════

mod framing_async_tests {
    use super::*;
    use p9n_transport::framing;

    #[tokio::test]
    async fn test_write_then_read_message() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let fc = Fcall {
            size: 0,
            msg_type: MsgType::Tattach,
            tag: 3,
            msg: Msg::Attach {
                fid: 0, afid: NO_FID, uname: "user".into(), aname: "/export".into(),
            },
        };

        framing::write_message(&mut client, &fc).await.unwrap();
        let decoded = framing::read_message(&mut server).await.unwrap();

        assert_eq!(decoded.msg_type, MsgType::Tattach);
        assert_eq!(decoded.tag, 3);
        match decoded.msg {
            Msg::Attach { fid, afid, uname, aname } => {
                assert_eq!(fid, 0);
                assert_eq!(afid, NO_FID);
                assert_eq!(uname, "user");
                assert_eq!(aname, "/export");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn test_multiple_messages_in_sequence() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        for i in 0..5u16 {
            let fc = Fcall {
                size: 0,
                msg_type: MsgType::Tread,
                tag: i,
                msg: Msg::Read { fid: i as u32, offset: 0, count: 1024 },
            };
            framing::write_message(&mut client, &fc).await.unwrap();
        }

        for i in 0..5u16 {
            let decoded = framing::read_message(&mut server).await.unwrap();
            assert_eq!(decoded.tag, i);
            match decoded.msg {
                Msg::Read { fid, .. } => assert_eq!(fid, i as u32),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[tokio::test]
    async fn test_read_message_too_small() {
        let (mut client, mut server) = tokio::io::duplex(64);
        // Write a size field that claims only 3 bytes (below HEADER_SIZE=7)
        use tokio::io::AsyncWriteExt;
        client.write_all(&3u32.to_le_bytes()).await.unwrap();
        // Also write some padding so read_exact for size doesn't hang
        client.write_all(&[0u8; 4]).await.unwrap();

        let result = framing::read_message(&mut server).await;
        assert!(result.is_err(), "should reject message smaller than header");
    }
}

// ═══════════════════ Router ═══════════════════

mod router_tests {
    use super::*;
    use p9n_transport::quic::router::should_use_datagram;

    fn make_fc(msg_type: MsgType) -> Fcall {
        Fcall { size: 0, msg_type, tag: 1, msg: Msg::Empty }
    }

    #[test]
    fn test_metadata_uses_datagram() {
        assert!(should_use_datagram(&make_fc(MsgType::Tversion), 1200));
        assert!(should_use_datagram(&make_fc(MsgType::Tcaps), 1200));
        assert!(should_use_datagram(&make_fc(MsgType::Tsession), 1200));
        assert!(should_use_datagram(&make_fc(MsgType::Thealth), 1200));
        assert!(should_use_datagram(&make_fc(MsgType::Tflush), 1200));
    }

    #[test]
    fn test_data_uses_stream() {
        assert!(!should_use_datagram(&make_fc(MsgType::Twalk), 1200));
        assert!(!should_use_datagram(&make_fc(MsgType::Tread), 1200));
        assert!(!should_use_datagram(&make_fc(MsgType::Twrite), 1200));
        assert!(!should_use_datagram(&make_fc(MsgType::Tgetattr), 1200));
        assert!(!should_use_datagram(&make_fc(MsgType::Treaddir), 1200));
    }

    #[test]
    fn test_push_uses_stream() {
        assert!(!should_use_datagram(&make_fc(MsgType::Rnotify), 1200));
        assert!(!should_use_datagram(&make_fc(MsgType::Rleasebreak), 1200));
    }
}
