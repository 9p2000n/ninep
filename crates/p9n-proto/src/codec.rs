//! Marshal/unmarshal for all 9P2000.N messages.

use crate::buf::Buf;
use crate::types::*;
use crate::wire::*;
use crate::fcall::*;
use crate::error::WireError;

type Result<T> = std::result::Result<T, WireError>;

fn msg_begin(buf: &mut Buf, t: MsgType, tag: u16) -> usize {
    let off = buf.len();
    buf.put_u32(0); // placeholder for size
    buf.put_u8(t as u8);
    buf.put_u16(tag);
    off
}

fn msg_finish(buf: &mut Buf, off: usize) {
    let size = (buf.len() - off) as u32;
    buf.patch_u32(off, size);
}

/// Encode an Fcall to wire format.
pub fn marshal(buf: &mut Buf, fc: &Fcall) -> Result<()> {
    let off = msg_begin(buf, fc.msg_type, fc.tag);

    match &fc.msg {
        // ── Empty-payload messages ──
        Msg::Empty => {}

        // ── 9P2000 core base messages ──
        Msg::Version { msize, version } => {
            buf.put_u32(*msize);
            buf.put_str(version);
        }
        Msg::Auth { afid, uname, aname } => {
            buf.put_u32(*afid);
            buf.put_str(uname);
            buf.put_str(aname);
        }
        Msg::Rauth { aqid } => {
            buf.put_qid(aqid);
        }
        Msg::Attach { fid, afid, uname, aname } => {
            buf.put_u32(*fid);
            buf.put_u32(*afid);
            buf.put_str(uname);
            buf.put_str(aname);
        }
        Msg::Rattach { qid } => {
            buf.put_qid(qid);
        }
        Msg::Error { ename } => {
            buf.put_str(ename);
        }
        Msg::Lerror { ecode } => {
            buf.put_u32(*ecode);
        }
        Msg::Flush { oldtag } => {
            buf.put_u16(*oldtag);
        }
        Msg::Walk { fid, newfid, wnames } => {
            buf.put_u32(*fid);
            buf.put_u32(*newfid);
            buf.put_u16(wnames.len() as u16);
            for w in wnames { buf.put_str(w); }
        }
        Msg::Rwalk { qids } => {
            buf.put_u16(qids.len() as u16);
            for q in qids { buf.put_qid(q); }
        }
        Msg::Read { fid, offset, count } => {
            buf.put_u32(*fid);
            buf.put_u64(*offset);
            buf.put_u32(*count);
        }
        Msg::Rread { data } => {
            buf.put_data(data);
        }
        Msg::Write { fid, offset, data } => {
            buf.put_u32(*fid);
            buf.put_u64(*offset);
            buf.put_data(data);
        }
        Msg::Rwrite { count } => {
            buf.put_u32(*count);
        }
        Msg::Clunk { fid } => {
            buf.put_u32(*fid);
        }
        Msg::Remove { fid } => {
            buf.put_u32(*fid);
        }
        Msg::Lopen { fid, flags } => {
            buf.put_u32(*fid);
            buf.put_u32(*flags);
        }
        Msg::Rlopen { qid, iounit } => {
            buf.put_qid(qid);
            buf.put_u32(*iounit);
        }
        Msg::Lcreate { fid, name, flags, mode, gid } => {
            buf.put_u32(*fid);
            buf.put_str(name);
            buf.put_u32(*flags);
            buf.put_u32(*mode);
            buf.put_u32(*gid);
        }
        Msg::Rlcreate { qid, iounit } => {
            buf.put_qid(qid);
            buf.put_u32(*iounit);
        }
        Msg::Symlink { fid, name, symtgt, gid } => {
            buf.put_u32(*fid);
            buf.put_str(name);
            buf.put_str(symtgt);
            buf.put_u32(*gid);
        }
        Msg::Rsymlink { qid } => {
            buf.put_qid(qid);
        }
        Msg::Mknod { dfid, name, mode, major, minor, gid } => {
            buf.put_u32(*dfid);
            buf.put_str(name);
            buf.put_u32(*mode);
            buf.put_u32(*major);
            buf.put_u32(*minor);
            buf.put_u32(*gid);
        }
        Msg::Rmknod { qid } => {
            buf.put_qid(qid);
        }
        Msg::Rename { fid, dfid, name } => {
            buf.put_u32(*fid);
            buf.put_u32(*dfid);
            buf.put_str(name);
        }
        Msg::Readlink { fid } => {
            buf.put_u32(*fid);
        }
        Msg::Rreadlink { target } => {
            buf.put_str(target);
        }
        Msg::Getattr { fid, mask } => {
            buf.put_u32(*fid);
            buf.put_u64(*mask);
        }
        Msg::Rgetattr { valid, qid, stat } => {
            buf.put_u64(*valid);
            buf.put_qid(qid);
            buf.put_u32(stat.mode);
            buf.put_u32(stat.uid);
            buf.put_u32(stat.gid);
            buf.put_u64(stat.nlink);
            buf.put_u64(stat.rdev);
            buf.put_u64(stat.size);
            buf.put_u64(stat.blksize);
            buf.put_u64(stat.blocks);
            buf.put_u64(stat.atime_sec);
            buf.put_u64(stat.atime_nsec);
            buf.put_u64(stat.mtime_sec);
            buf.put_u64(stat.mtime_nsec);
            buf.put_u64(stat.ctime_sec);
            buf.put_u64(stat.ctime_nsec);
            buf.put_u64(stat.btime_sec);
            buf.put_u64(stat.btime_nsec);
            buf.put_u64(stat.gen);
            buf.put_u64(stat.data_version);
        }
        Msg::Setattr { fid, attr } => {
            buf.put_u32(*fid);
            buf.put_u32(attr.valid);
            buf.put_u32(attr.mode);
            buf.put_u32(attr.uid);
            buf.put_u32(attr.gid);
            buf.put_u64(attr.size);
            buf.put_u64(attr.atime_sec);
            buf.put_u64(attr.atime_nsec);
            buf.put_u64(attr.mtime_sec);
            buf.put_u64(attr.mtime_nsec);
        }
        Msg::Xattrwalk { fid, newfid, name } => {
            buf.put_u32(*fid);
            buf.put_u32(*newfid);
            buf.put_str(name);
        }
        Msg::Rxattrwalk { size } => {
            buf.put_u64(*size);
        }
        Msg::Xattrcreate { fid, name, attr_size, flags } => {
            buf.put_u32(*fid);
            buf.put_str(name);
            buf.put_u64(*attr_size);
            buf.put_u32(*flags);
        }
        Msg::Readdir { fid, offset, count } => {
            buf.put_u32(*fid);
            buf.put_u64(*offset);
            buf.put_u32(*count);
        }
        Msg::Rreaddir { data } => {
            buf.put_data(data);
        }
        Msg::Fsync { fid } => {
            buf.put_u32(*fid);
        }
        Msg::Lock { fid, lock_type, flags, start, length, proc_id, client_id } => {
            buf.put_u32(*fid);
            buf.put_u8(*lock_type);
            buf.put_u32(*flags);
            buf.put_u64(*start);
            buf.put_u64(*length);
            buf.put_u32(*proc_id);
            buf.put_str(client_id);
        }
        Msg::Rlock { status } => {
            buf.put_u8(*status);
        }
        Msg::GetlockReq { fid, lock_type, start, length, proc_id, client_id } => {
            buf.put_u32(*fid);
            buf.put_u8(*lock_type);
            buf.put_u64(*start);
            buf.put_u64(*length);
            buf.put_u32(*proc_id);
            buf.put_str(client_id);
        }
        Msg::RgetlockResp { lock_type, start, length, proc_id, client_id } => {
            buf.put_u8(*lock_type);
            buf.put_u64(*start);
            buf.put_u64(*length);
            buf.put_u32(*proc_id);
            buf.put_str(client_id);
        }
        Msg::Link { dfid, fid, name } => {
            buf.put_u32(*dfid);
            buf.put_u32(*fid);
            buf.put_str(name);
        }
        Msg::Mkdir { dfid, name, mode, gid } => {
            buf.put_u32(*dfid);
            buf.put_str(name);
            buf.put_u32(*mode);
            buf.put_u32(*gid);
        }
        Msg::Rmkdir { qid } => {
            buf.put_qid(qid);
        }
        Msg::Renameat { olddirfid, oldname, newdirfid, newname } => {
            buf.put_u32(*olddirfid);
            buf.put_str(oldname);
            buf.put_u32(*newdirfid);
            buf.put_str(newname);
        }
        Msg::Unlinkat { dirfid, name, flags } => {
            buf.put_u32(*dirfid);
            buf.put_str(name);
            buf.put_u32(*flags);
        }
        Msg::Statfs { fid } => {
            buf.put_u32(*fid);
        }
        Msg::Rstatfs { stat } => {
            buf.put_u32(stat.fs_type);
            buf.put_u32(stat.bsize);
            buf.put_u64(stat.blocks);
            buf.put_u64(stat.bfree);
            buf.put_u64(stat.bavail);
            buf.put_u64(stat.files);
            buf.put_u64(stat.ffree);
            buf.put_u64(stat.fsid);
            buf.put_u32(stat.namelen);
        }

        // ── 9P2000.N extension messages ──
        Msg::Caps { caps } => {
            buf.put_u16(caps.len() as u16);
            for c in caps { buf.put_str(c); }
        }
        Msg::Authneg { mechs } => {
            buf.put_u16(mechs.len() as u16);
            for m in mechs { buf.put_str(m); }
        }
        Msg::Rauthneg { mech, challenge } => {
            buf.put_str(mech);
            buf.put_data(challenge);
        }
        Msg::Capgrant { fid, rights, expiry, depth } => {
            buf.put_u32(*fid);
            buf.put_u64(*rights);
            buf.put_u64(*expiry);
            buf.put_u16(*depth);
        }
        Msg::Rcapgrant { token } => {
            buf.put_str(token);
        }
        Msg::Capuse { fid, token } => {
            buf.put_u32(*fid);
            buf.put_str(token);
        }
        Msg::Rcapuse { qid } => {
            buf.put_qid(qid);
        }
        Msg::Auditctl { fid, flags } => {
            buf.put_u32(*fid);
            buf.put_u32(*flags);
        }
        Msg::StartlsSpiffe { spiffe_id, trust_domain } => {
            buf.put_str(spiffe_id);
            buf.put_str(trust_domain);
        }
        Msg::Fetchbundle { trust_domain, format } => {
            buf.put_str(trust_domain);
            buf.put_u8(*format);
        }
        Msg::Rfetchbundle { trust_domain, format, bundle } => {
            buf.put_str(trust_domain);
            buf.put_u8(*format);
            buf.put_data(bundle);
        }
        Msg::Spiffeverify { svid_type, spiffe_id, svid } => {
            buf.put_u8(*svid_type);
            buf.put_str(spiffe_id);
            buf.put_data(svid);
        }
        Msg::Rspiffeverify { status, spiffe_id, expiry } => {
            buf.put_u8(*status);
            buf.put_str(spiffe_id);
            buf.put_u64(*expiry);
        }
        Msg::Rdmatoken { fid, direction, rkey, addr, length } => {
            buf.put_u32(*fid);
            buf.put_u8(*direction);
            buf.put_u32(*rkey);
            buf.put_u64(*addr);
            buf.put_u32(*length);
        }
        Msg::Rrdmatoken { rkey, addr, length } => {
            buf.put_u32(*rkey);
            buf.put_u64(*addr);
            buf.put_u32(*length);
        }
        Msg::Rdmanotify { rkey, addr, length, slots } => {
            buf.put_u32(*rkey);
            buf.put_u64(*addr);
            buf.put_u32(*length);
            buf.put_u16(*slots);
        }
        Msg::Quicstream { stream_type, stream_id } => {
            buf.put_u8(*stream_type);
            buf.put_u64(*stream_id);
        }
        Msg::Rquicstream { stream_id } => {
            buf.put_u64(*stream_id);
        }
        Msg::Cxlmap { fid, offset, length, prot, flags } => {
            buf.put_u32(*fid);
            buf.put_u64(*offset);
            buf.put_u64(*length);
            buf.put_u32(*prot);
            buf.put_u32(*flags);
        }
        Msg::Rcxlmap { hpa, length, granularity, coherence } => {
            buf.put_u64(*hpa);
            buf.put_u64(*length);
            buf.put_u32(*granularity);
            buf.put_u8(*coherence);
        }
        Msg::Cxlcoherence { fid, mode } => {
            buf.put_u32(*fid);
            buf.put_u8(*mode);
        }
        Msg::Rcxlcoherence { mode, snoop_id } => {
            buf.put_u8(*mode);
            buf.put_u32(*snoop_id);
        }
        Msg::Compound { ops } => {
            marshal_subops(buf, ops);
        }
        Msg::Rcompound { results } => {
            marshal_subops(buf, results);
        }
        Msg::Compress { algo, level } => {
            buf.put_u8(*algo);
            buf.put_u8(*level);
        }
        Msg::Rcompress { algo } => {
            buf.put_u8(*algo);
        }
        Msg::Copyrange { src_fid, src_off, dst_fid, dst_off, count, flags } => {
            buf.put_u32(*src_fid);
            buf.put_u64(*src_off);
            buf.put_u32(*dst_fid);
            buf.put_u64(*dst_off);
            buf.put_u64(*count);
            buf.put_u32(*flags);
        }
        Msg::Rcopyrange { count } => {
            buf.put_u64(*count);
        }
        Msg::Allocate { fid, mode, offset, length } => {
            buf.put_u32(*fid);
            buf.put_u32(*mode);
            buf.put_u64(*offset);
            buf.put_u64(*length);
        }
        Msg::Seekhole { fid, seek_type, offset } => {
            buf.put_u32(*fid);
            buf.put_u8(*seek_type);
            buf.put_u64(*offset);
        }
        Msg::Rseekhole { offset } => {
            buf.put_u64(*offset);
        }
        Msg::Mmaphint { fid, offset, length, prot } => {
            buf.put_u32(*fid);
            buf.put_u64(*offset);
            buf.put_u64(*length);
            buf.put_u32(*prot);
        }
        Msg::Rmmaphint { granted } => {
            buf.put_u8(*granted);
        }
        Msg::Watch { fid, mask, flags } => {
            buf.put_u32(*fid);
            buf.put_u32(*mask);
            buf.put_u32(*flags);
        }
        Msg::Rwatch { watch_id } => {
            buf.put_u32(*watch_id);
        }
        Msg::Unwatch { watch_id } => {
            buf.put_u32(*watch_id);
        }
        Msg::Notify { watch_id, event, name, qid } => {
            buf.put_u32(*watch_id);
            buf.put_u32(*event);
            buf.put_str(name);
            buf.put_qid(qid);
        }
        Msg::Getacl { fid, acl_type } => {
            buf.put_u32(*fid);
            buf.put_u8(*acl_type);
        }
        Msg::Rgetacl { data } => {
            buf.put_data(data);
        }
        Msg::Setacl { fid, acl_type, data } => {
            buf.put_u32(*fid);
            buf.put_u8(*acl_type);
            buf.put_data(data);
        }
        Msg::Snapshot { fid, name, flags } => {
            buf.put_u32(*fid);
            buf.put_str(name);
            buf.put_u32(*flags);
        }
        Msg::Rsnapshot { qid } => {
            buf.put_qid(qid);
        }
        Msg::Clone { src_fid, dst_fid, name, flags } => {
            buf.put_u32(*src_fid);
            buf.put_u32(*dst_fid);
            buf.put_str(name);
            buf.put_u32(*flags);
        }
        Msg::Rclone { qid } => {
            buf.put_qid(qid);
        }
        Msg::Xattrget { fid, name } => {
            buf.put_u32(*fid);
            buf.put_str(name);
        }
        Msg::Rxattrget { data } => {
            buf.put_data(data);
        }
        Msg::Xattrset { fid, name, data, flags } => {
            buf.put_u32(*fid);
            buf.put_str(name);
            buf.put_data(data);
            buf.put_u32(*flags);
        }
        Msg::Xattrlist { fid, cookie, count } => {
            buf.put_u32(*fid);
            buf.put_u64(*cookie);
            buf.put_u32(*count);
        }
        Msg::Rxattrlist { cookie, names } => {
            buf.put_u64(*cookie);
            buf.put_u16(names.len() as u16);
            for n in names { buf.put_str(n); }
        }
        Msg::Lease { fid, lease_type, duration } => {
            buf.put_u32(*fid);
            buf.put_u8(*lease_type);
            buf.put_u32(*duration);
        }
        Msg::Rlease { lease_id, lease_type, duration } => {
            buf.put_u64(*lease_id);
            buf.put_u8(*lease_type);
            buf.put_u32(*duration);
        }
        Msg::Leaserenew { lease_id, duration } => {
            buf.put_u64(*lease_id);
            buf.put_u32(*duration);
        }
        Msg::Rleaserenew { duration } => {
            buf.put_u32(*duration);
        }
        Msg::Leasebreak { lease_id, new_type } => {
            buf.put_u64(*lease_id);
            buf.put_u8(*new_type);
        }
        Msg::Leaseack { lease_id } => {
            buf.put_u64(*lease_id);
        }
        Msg::Session { key, flags } => {
            buf.put_bytes(key);
            buf.put_u32(*flags);
        }
        Msg::Rsession { flags } => {
            buf.put_u32(*flags);
        }
        Msg::Consistency { fid, level } => {
            buf.put_u32(*fid);
            buf.put_u8(*level);
        }
        Msg::Rconsistency { level } => {
            buf.put_u8(*level);
        }
        Msg::Topology { fid } => {
            buf.put_u32(*fid);
        }
        Msg::Rtopology { replicas } => {
            buf.put_u16(replicas.len() as u16);
            for r in replicas {
                buf.put_str(&r.addr);
                buf.put_u8(r.role);
                buf.put_u32(r.latency_us);
            }
        }
        Msg::Traceattr { attrs } => {
            buf.put_u16(attrs.len() as u16);
            for (k, v) in attrs {
                buf.put_str(k);
                buf.put_str(v);
            }
        }
        Msg::Rhealth { status, load, metrics } => {
            buf.put_u8(*status);
            buf.put_u32(*load);
            buf.put_u16(metrics.len() as u16);
            for m in metrics {
                buf.put_str(&m.name);
                buf.put_u64(m.value);
            }
        }
        Msg::ServerstatsReq { mask } => {
            buf.put_u64(*mask);
        }
        Msg::Rserverstats { stats } => {
            buf.put_u16(stats.len() as u16);
            for s in stats {
                buf.put_str(&s.name);
                buf.put_u8(s.stat_type);
                buf.put_u64(s.value);
            }
        }
        Msg::Getquota { fid, quota_type } => {
            buf.put_u32(*fid);
            buf.put_u8(*quota_type);
        }
        Msg::Rgetquota { bytes_used, bytes_limit, files_used, files_limit, grace } => {
            buf.put_u64(*bytes_used);
            buf.put_u64(*bytes_limit);
            buf.put_u64(*files_used);
            buf.put_u64(*files_limit);
            buf.put_u32(*grace);
        }
        Msg::Setquota { fid, quota_type, bytes_limit, files_limit, grace } => {
            buf.put_u32(*fid);
            buf.put_u8(*quota_type);
            buf.put_u64(*bytes_limit);
            buf.put_u64(*files_limit);
            buf.put_u32(*grace);
        }
        Msg::Ratelimit { fid, iops, bps } => {
            buf.put_u32(*fid);
            buf.put_u32(*iops);
            buf.put_u64(*bps);
        }
        Msg::Rratelimit { iops, bps } => {
            buf.put_u32(*iops);
            buf.put_u64(*bps);
        }
        Msg::Async { inner_type, payload } => {
            buf.put_u8(*inner_type as u8);
            buf.put_bytes(payload);
        }
        Msg::Rasync { op_id, status } => {
            buf.put_u64(*op_id);
            buf.put_u8(*status);
        }
        Msg::Poll { op_id } => {
            buf.put_u64(*op_id);
        }
        Msg::Rpoll { status, progress, payload } => {
            buf.put_u8(*status);
            buf.put_u32(*progress);
            buf.put_bytes(payload);
        }
        Msg::Streamopen { fid, direction, offset, count } => {
            buf.put_u32(*fid);
            buf.put_u8(*direction);
            buf.put_u64(*offset);
            buf.put_u64(*count);
        }
        Msg::Rstreamopen { stream_id } => {
            buf.put_u32(*stream_id);
        }
        Msg::Streamdata { stream_id, seq, data } => {
            buf.put_u32(*stream_id);
            buf.put_u32(*seq);
            buf.put_data(data);
        }
        Msg::Streamclose { stream_id } => {
            buf.put_u32(*stream_id);
        }
        Msg::Search { fid, query, flags, max_results, cookie } => {
            buf.put_u32(*fid);
            buf.put_str(query);
            buf.put_u32(*flags);
            buf.put_u32(*max_results);
            buf.put_u64(*cookie);
        }
        Msg::Rsearch { cookie, entries } => {
            buf.put_u64(*cookie);
            buf.put_u16(entries.len() as u16);
            for e in entries {
                buf.put_qid(&e.qid);
                buf.put_str(&e.name);
                buf.put_u32(e.score);
            }
        }
        Msg::Hash { fid, algo, offset, length } => {
            buf.put_u32(*fid);
            buf.put_u8(*algo);
            buf.put_u64(*offset);
            buf.put_u64(*length);
        }
        Msg::Rhash { algo, hash } => {
            buf.put_u8(*algo);
            buf.put_u16(hash.len() as u16);
            buf.put_bytes(hash);
        }
    }

    msg_finish(buf, off);
    Ok(())
}

fn marshal_subops(buf: &mut Buf, ops: &[SubOp]) {
    buf.put_u16(ops.len() as u16);
    for op in ops {
        let opsize = (SUBOP_HDR_SZ + op.payload.len()) as u32;
        buf.put_u32(opsize);
        buf.put_u8(op.msg_type as u8);
        buf.put_bytes(&op.payload);
    }
}

/// Decode a single Fcall from buf.
pub fn unmarshal(buf: &mut Buf) -> Result<Fcall> {
    let size = buf.get_u32()?;
    let t = buf.get_u8()?;
    let tag = buf.get_u16()?;
    let msg_type = MsgType::from_u8(t)
        .ok_or(WireError::UnknownType(t))?;

    let msg = match msg_type {
        // ── empty-payload responses ──
        MsgType::Rflush | MsgType::Rclunk | MsgType::Rremove |
        MsgType::Rrename | MsgType::Rsetattr | MsgType::Rfsync |
        MsgType::Rlink | MsgType::Rrenameat | MsgType::Runlinkat |
        MsgType::Rxattrcreate |
        // ── 9P2000.N empty-payload messages ──
        MsgType::Tstartls | MsgType::Rstartls | MsgType::Rauditctl |
        MsgType::Runwatch | MsgType::Rsetacl | MsgType::Rxattrset |
        MsgType::Rallocate | MsgType::Rleaseack | MsgType::Rrdmanotify |
        MsgType::Rtraceattr | MsgType::Thealth | MsgType::Rsetquota |
        MsgType::Rstreamclose => Msg::Empty,

        // ── 9P2000 core messages ──
        MsgType::Tversion | MsgType::Rversion => {
            Msg::Version { msize: buf.get_u32()?, version: buf.get_str()? }
        }
        MsgType::Tauth => {
            Msg::Auth { afid: buf.get_u32()?, uname: buf.get_str()?, aname: buf.get_str()? }
        }
        MsgType::Rauth => {
            Msg::Rauth { aqid: buf.get_qid()? }
        }
        MsgType::Tattach => {
            Msg::Attach {
                fid: buf.get_u32()?, afid: buf.get_u32()?,
                uname: buf.get_str()?, aname: buf.get_str()?,
            }
        }
        MsgType::Rattach => {
            Msg::Rattach { qid: buf.get_qid()? }
        }
        MsgType::Rerror => {
            Msg::Error { ename: buf.get_str()? }
        }
        MsgType::Tlerror | MsgType::Rlerror => {
            Msg::Lerror { ecode: buf.get_u32()? }
        }
        MsgType::Tflush => {
            Msg::Flush { oldtag: buf.get_u16()? }
        }
        MsgType::Twalk => {
            let fid = buf.get_u32()?;
            let newfid = buf.get_u32()?;
            let nwnames = buf.get_u16()? as usize;
            let mut wnames = Vec::with_capacity(nwnames);
            for _ in 0..nwnames { wnames.push(buf.get_str()?); }
            Msg::Walk { fid, newfid, wnames }
        }
        MsgType::Rwalk => {
            let nqids = buf.get_u16()? as usize;
            let mut qids = Vec::with_capacity(nqids);
            for _ in 0..nqids { qids.push(buf.get_qid()?); }
            Msg::Rwalk { qids }
        }
        MsgType::Tread => {
            Msg::Read { fid: buf.get_u32()?, offset: buf.get_u64()?, count: buf.get_u32()? }
        }
        MsgType::Rread => {
            Msg::Rread { data: buf.get_data()? }
        }
        MsgType::Twrite => {
            Msg::Write { fid: buf.get_u32()?, offset: buf.get_u64()?, data: buf.get_data()? }
        }
        MsgType::Rwrite => {
            Msg::Rwrite { count: buf.get_u32()? }
        }
        MsgType::Tclunk => {
            Msg::Clunk { fid: buf.get_u32()? }
        }
        MsgType::Tremove => {
            Msg::Remove { fid: buf.get_u32()? }
        }

        // ── base messages ──
        MsgType::Tlopen => {
            Msg::Lopen { fid: buf.get_u32()?, flags: buf.get_u32()? }
        }
        MsgType::Rlopen => {
            Msg::Rlopen { qid: buf.get_qid()?, iounit: buf.get_u32()? }
        }
        MsgType::Tlcreate => {
            Msg::Lcreate {
                fid: buf.get_u32()?, name: buf.get_str()?,
                flags: buf.get_u32()?, mode: buf.get_u32()?, gid: buf.get_u32()?,
            }
        }
        MsgType::Rlcreate => {
            Msg::Rlcreate { qid: buf.get_qid()?, iounit: buf.get_u32()? }
        }
        MsgType::Tsymlink => {
            Msg::Symlink {
                fid: buf.get_u32()?, name: buf.get_str()?,
                symtgt: buf.get_str()?, gid: buf.get_u32()?,
            }
        }
        MsgType::Rsymlink => {
            Msg::Rsymlink { qid: buf.get_qid()? }
        }
        MsgType::Tmknod => {
            Msg::Mknod {
                dfid: buf.get_u32()?, name: buf.get_str()?,
                mode: buf.get_u32()?, major: buf.get_u32()?,
                minor: buf.get_u32()?, gid: buf.get_u32()?,
            }
        }
        MsgType::Rmknod => {
            Msg::Rmknod { qid: buf.get_qid()? }
        }
        MsgType::Trename => {
            Msg::Rename { fid: buf.get_u32()?, dfid: buf.get_u32()?, name: buf.get_str()? }
        }
        MsgType::Treadlink => {
            Msg::Readlink { fid: buf.get_u32()? }
        }
        MsgType::Rreadlink => {
            Msg::Rreadlink { target: buf.get_str()? }
        }
        MsgType::Tgetattr => {
            Msg::Getattr { fid: buf.get_u32()?, mask: buf.get_u64()? }
        }
        MsgType::Rgetattr => {
            let valid = buf.get_u64()?;
            let qid = buf.get_qid()?;
            let stat = Stat {
                valid,
                qid: qid.clone(),
                mode: buf.get_u32()?,
                uid: buf.get_u32()?,
                gid: buf.get_u32()?,
                nlink: buf.get_u64()?,
                rdev: buf.get_u64()?,
                size: buf.get_u64()?,
                blksize: buf.get_u64()?,
                blocks: buf.get_u64()?,
                atime_sec: buf.get_u64()?,
                atime_nsec: buf.get_u64()?,
                mtime_sec: buf.get_u64()?,
                mtime_nsec: buf.get_u64()?,
                ctime_sec: buf.get_u64()?,
                ctime_nsec: buf.get_u64()?,
                btime_sec: buf.get_u64()?,
                btime_nsec: buf.get_u64()?,
                gen: buf.get_u64()?,
                data_version: buf.get_u64()?,
            };
            Msg::Rgetattr { valid, qid, stat }
        }
        MsgType::Tsetattr => {
            let fid = buf.get_u32()?;
            let attr = SetAttr {
                valid: buf.get_u32()?,
                mode: buf.get_u32()?,
                uid: buf.get_u32()?,
                gid: buf.get_u32()?,
                size: buf.get_u64()?,
                atime_sec: buf.get_u64()?,
                atime_nsec: buf.get_u64()?,
                mtime_sec: buf.get_u64()?,
                mtime_nsec: buf.get_u64()?,
            };
            Msg::Setattr { fid, attr }
        }
        MsgType::Txattrwalk => {
            Msg::Xattrwalk { fid: buf.get_u32()?, newfid: buf.get_u32()?, name: buf.get_str()? }
        }
        MsgType::Rxattrwalk => {
            Msg::Rxattrwalk { size: buf.get_u64()? }
        }
        MsgType::Txattrcreate => {
            Msg::Xattrcreate {
                fid: buf.get_u32()?, name: buf.get_str()?,
                attr_size: buf.get_u64()?, flags: buf.get_u32()?,
            }
        }
        MsgType::Treaddir => {
            Msg::Readdir { fid: buf.get_u32()?, offset: buf.get_u64()?, count: buf.get_u32()? }
        }
        MsgType::Rreaddir => {
            Msg::Rreaddir { data: buf.get_data()? }
        }
        MsgType::Tfsync => {
            Msg::Fsync { fid: buf.get_u32()? }
        }
        MsgType::Tlock => {
            Msg::Lock {
                fid: buf.get_u32()?, lock_type: buf.get_u8()?,
                flags: buf.get_u32()?, start: buf.get_u64()?,
                length: buf.get_u64()?, proc_id: buf.get_u32()?,
                client_id: buf.get_str()?,
            }
        }
        MsgType::Rlock => {
            Msg::Rlock { status: buf.get_u8()? }
        }
        MsgType::Tgetlock => {
            Msg::GetlockReq {
                fid: buf.get_u32()?, lock_type: buf.get_u8()?,
                start: buf.get_u64()?, length: buf.get_u64()?,
                proc_id: buf.get_u32()?, client_id: buf.get_str()?,
            }
        }
        MsgType::Rgetlock => {
            Msg::RgetlockResp {
                lock_type: buf.get_u8()?, start: buf.get_u64()?,
                length: buf.get_u64()?, proc_id: buf.get_u32()?,
                client_id: buf.get_str()?,
            }
        }
        MsgType::Tlink => {
            Msg::Link { dfid: buf.get_u32()?, fid: buf.get_u32()?, name: buf.get_str()? }
        }
        MsgType::Tmkdir => {
            Msg::Mkdir {
                dfid: buf.get_u32()?, name: buf.get_str()?,
                mode: buf.get_u32()?, gid: buf.get_u32()?,
            }
        }
        MsgType::Rmkdir => {
            Msg::Rmkdir { qid: buf.get_qid()? }
        }
        MsgType::Trenameat => {
            Msg::Renameat {
                olddirfid: buf.get_u32()?, oldname: buf.get_str()?,
                newdirfid: buf.get_u32()?, newname: buf.get_str()?,
            }
        }
        MsgType::Tunlinkat => {
            Msg::Unlinkat { dirfid: buf.get_u32()?, name: buf.get_str()?, flags: buf.get_u32()? }
        }
        MsgType::Tstatfs => {
            Msg::Statfs { fid: buf.get_u32()? }
        }
        MsgType::Rstatfs => {
            Msg::Rstatfs {
                stat: StatFs {
                    fs_type: buf.get_u32()?,
                    bsize: buf.get_u32()?,
                    blocks: buf.get_u64()?,
                    bfree: buf.get_u64()?,
                    bavail: buf.get_u64()?,
                    files: buf.get_u64()?,
                    ffree: buf.get_u64()?,
                    fsid: buf.get_u64()?,
                    namelen: buf.get_u32()?,
                },
            }
        }

        // ── 9P2000.N extension messages ──
        MsgType::Tcaps | MsgType::Rcaps => {
            let n = buf.get_u16()?;
            let mut caps = Vec::with_capacity(n as usize);
            for _ in 0..n { caps.push(buf.get_str()?); }
            Msg::Caps { caps }
        }
        MsgType::Tauthneg => {
            let n = buf.get_u16()?;
            let mut mechs = Vec::with_capacity(n as usize);
            for _ in 0..n { mechs.push(buf.get_str()?); }
            Msg::Authneg { mechs }
        }
        MsgType::Rauthneg => {
            Msg::Rauthneg { mech: buf.get_str()?, challenge: buf.get_data()? }
        }
        MsgType::Tcapgrant => {
            Msg::Capgrant {
                fid: buf.get_u32()?, rights: buf.get_u64()?,
                expiry: buf.get_u64()?, depth: buf.get_u16()?,
            }
        }
        MsgType::Rcapgrant => {
            Msg::Rcapgrant { token: buf.get_str()? }
        }
        MsgType::Tcapuse => {
            Msg::Capuse { fid: buf.get_u32()?, token: buf.get_str()? }
        }
        MsgType::Rcapuse => {
            Msg::Rcapuse { qid: buf.get_qid()? }
        }
        MsgType::Tauditctl => {
            Msg::Auditctl { fid: buf.get_u32()?, flags: buf.get_u32()? }
        }
        MsgType::TstartlsSpiffe | MsgType::RstartlsSpiffe => {
            Msg::StartlsSpiffe { spiffe_id: buf.get_str()?, trust_domain: buf.get_str()? }
        }
        MsgType::Tfetchbundle => {
            Msg::Fetchbundle { trust_domain: buf.get_str()?, format: buf.get_u8()? }
        }
        MsgType::Rfetchbundle => {
            Msg::Rfetchbundle {
                trust_domain: buf.get_str()?, format: buf.get_u8()?,
                bundle: buf.get_data()?,
            }
        }
        MsgType::Tspiffeverify => {
            Msg::Spiffeverify {
                svid_type: buf.get_u8()?, spiffe_id: buf.get_str()?,
                svid: buf.get_data()?,
            }
        }
        MsgType::Rspiffeverify => {
            Msg::Rspiffeverify {
                status: buf.get_u8()?, spiffe_id: buf.get_str()?,
                expiry: buf.get_u64()?,
            }
        }
        MsgType::Tcxlmap => {
            Msg::Cxlmap {
                fid: buf.get_u32()?, offset: buf.get_u64()?,
                length: buf.get_u64()?, prot: buf.get_u32()?, flags: buf.get_u32()?,
            }
        }
        MsgType::Rcxlmap => {
            Msg::Rcxlmap {
                hpa: buf.get_u64()?, length: buf.get_u64()?,
                granularity: buf.get_u32()?, coherence: buf.get_u8()?,
            }
        }
        MsgType::Tcxlcoherence => {
            Msg::Cxlcoherence { fid: buf.get_u32()?, mode: buf.get_u8()? }
        }
        MsgType::Rcxlcoherence => {
            Msg::Rcxlcoherence { mode: buf.get_u8()?, snoop_id: buf.get_u32()? }
        }
        MsgType::Trdmatoken => {
            Msg::Rdmatoken {
                fid: buf.get_u32()?, direction: buf.get_u8()?,
                rkey: buf.get_u32()?, addr: buf.get_u64()?, length: buf.get_u32()?,
            }
        }
        MsgType::Rrdmatoken => {
            Msg::Rrdmatoken { rkey: buf.get_u32()?, addr: buf.get_u64()?, length: buf.get_u32()? }
        }
        MsgType::Trdmanotify => {
            Msg::Rdmanotify {
                rkey: buf.get_u32()?, addr: buf.get_u64()?,
                length: buf.get_u32()?, slots: buf.get_u16()?,
            }
        }
        MsgType::Tquicstream => {
            Msg::Quicstream { stream_type: buf.get_u8()?, stream_id: buf.get_u64()? }
        }
        MsgType::Rquicstream => {
            Msg::Rquicstream { stream_id: buf.get_u64()? }
        }
        MsgType::Tcompound => {
            Msg::Compound { ops: unmarshal_subops(buf)? }
        }
        MsgType::Rcompound => {
            Msg::Rcompound { results: unmarshal_subops(buf)? }
        }
        MsgType::Tcompress => {
            Msg::Compress { algo: buf.get_u8()?, level: buf.get_u8()? }
        }
        MsgType::Rcompress => {
            Msg::Rcompress { algo: buf.get_u8()? }
        }
        MsgType::Tcopyrange => {
            Msg::Copyrange {
                src_fid: buf.get_u32()?, src_off: buf.get_u64()?,
                dst_fid: buf.get_u32()?, dst_off: buf.get_u64()?,
                count: buf.get_u64()?, flags: buf.get_u32()?,
            }
        }
        MsgType::Rcopyrange => {
            Msg::Rcopyrange { count: buf.get_u64()? }
        }
        MsgType::Tallocate => {
            Msg::Allocate {
                fid: buf.get_u32()?, mode: buf.get_u32()?,
                offset: buf.get_u64()?, length: buf.get_u64()?,
            }
        }
        MsgType::Tseekhole => {
            Msg::Seekhole { fid: buf.get_u32()?, seek_type: buf.get_u8()?, offset: buf.get_u64()? }
        }
        MsgType::Rseekhole => {
            Msg::Rseekhole { offset: buf.get_u64()? }
        }
        MsgType::Tmmaphint => {
            Msg::Mmaphint {
                fid: buf.get_u32()?, offset: buf.get_u64()?,
                length: buf.get_u64()?, prot: buf.get_u32()?,
            }
        }
        MsgType::Rmmaphint => {
            Msg::Rmmaphint { granted: buf.get_u8()? }
        }
        MsgType::Twatch => {
            Msg::Watch { fid: buf.get_u32()?, mask: buf.get_u32()?, flags: buf.get_u32()? }
        }
        MsgType::Rwatch => {
            Msg::Rwatch { watch_id: buf.get_u32()? }
        }
        MsgType::Tunwatch => {
            Msg::Unwatch { watch_id: buf.get_u32()? }
        }
        MsgType::Rnotify => {
            Msg::Notify {
                watch_id: buf.get_u32()?, event: buf.get_u32()?,
                name: buf.get_str()?, qid: buf.get_qid()?,
            }
        }
        MsgType::Tgetacl => {
            Msg::Getacl { fid: buf.get_u32()?, acl_type: buf.get_u8()? }
        }
        MsgType::Rgetacl => {
            Msg::Rgetacl { data: buf.get_data()? }
        }
        MsgType::Tsetacl => {
            Msg::Setacl { fid: buf.get_u32()?, acl_type: buf.get_u8()?, data: buf.get_data()? }
        }
        MsgType::Tsnapshot => {
            Msg::Snapshot { fid: buf.get_u32()?, name: buf.get_str()?, flags: buf.get_u32()? }
        }
        MsgType::Rsnapshot => {
            Msg::Rsnapshot { qid: buf.get_qid()? }
        }
        MsgType::Tclone => {
            Msg::Clone {
                src_fid: buf.get_u32()?, dst_fid: buf.get_u32()?,
                name: buf.get_str()?, flags: buf.get_u32()?,
            }
        }
        MsgType::Rclone => {
            Msg::Rclone { qid: buf.get_qid()? }
        }
        MsgType::Txattrget => {
            Msg::Xattrget { fid: buf.get_u32()?, name: buf.get_str()? }
        }
        MsgType::Rxattrget => {
            Msg::Rxattrget { data: buf.get_data()? }
        }
        MsgType::Txattrset => {
            Msg::Xattrset {
                fid: buf.get_u32()?, name: buf.get_str()?,
                data: buf.get_data()?, flags: buf.get_u32()?,
            }
        }
        MsgType::Txattrlist => {
            Msg::Xattrlist { fid: buf.get_u32()?, cookie: buf.get_u64()?, count: buf.get_u32()? }
        }
        MsgType::Rxattrlist => {
            let cookie = buf.get_u64()?;
            let n = buf.get_u16()?;
            let mut names = Vec::with_capacity(n as usize);
            for _ in 0..n { names.push(buf.get_str()?); }
            Msg::Rxattrlist { cookie, names }
        }
        MsgType::Tlease => {
            Msg::Lease { fid: buf.get_u32()?, lease_type: buf.get_u8()?, duration: buf.get_u32()? }
        }
        MsgType::Rlease => {
            Msg::Rlease {
                lease_id: buf.get_u64()?, lease_type: buf.get_u8()?,
                duration: buf.get_u32()?,
            }
        }
        MsgType::Tleaserenew => {
            Msg::Leaserenew { lease_id: buf.get_u64()?, duration: buf.get_u32()? }
        }
        MsgType::Rleaserenew => {
            Msg::Rleaserenew { duration: buf.get_u32()? }
        }
        MsgType::Rleasebreak => {
            Msg::Leasebreak { lease_id: buf.get_u64()?, new_type: buf.get_u8()? }
        }
        MsgType::Tleaseack => {
            Msg::Leaseack { lease_id: buf.get_u64()? }
        }
        MsgType::Tsession => {
            let key: [u8; 16] = buf.get_fixed(16)?.try_into().unwrap();
            Msg::Session { key, flags: buf.get_u32()? }
        }
        MsgType::Rsession => {
            Msg::Rsession { flags: buf.get_u32()? }
        }
        MsgType::Tconsistency => {
            Msg::Consistency { fid: buf.get_u32()?, level: buf.get_u8()? }
        }
        MsgType::Rconsistency => {
            Msg::Rconsistency { level: buf.get_u8()? }
        }
        MsgType::Ttopology => {
            Msg::Topology { fid: buf.get_u32()? }
        }
        MsgType::Rtopology => {
            let n = buf.get_u16()?;
            let mut replicas = Vec::with_capacity(n as usize);
            for _ in 0..n {
                replicas.push(Replica {
                    addr: buf.get_str()?,
                    role: buf.get_u8()?,
                    latency_us: buf.get_u32()?,
                });
            }
            Msg::Rtopology { replicas }
        }
        MsgType::Ttraceattr => {
            let n = buf.get_u16()?;
            let mut attrs = Vec::with_capacity(n as usize);
            for _ in 0..n { attrs.push((buf.get_str()?, buf.get_str()?)); }
            Msg::Traceattr { attrs }
        }
        MsgType::Rhealth => {
            let status = buf.get_u8()?;
            let load = buf.get_u32()?;
            let n = buf.get_u16()?;
            let mut metrics = Vec::with_capacity(n as usize);
            for _ in 0..n {
                metrics.push(Metric { name: buf.get_str()?, value: buf.get_u64()? });
            }
            Msg::Rhealth { status, load, metrics }
        }
        MsgType::Tserverstats => {
            Msg::ServerstatsReq { mask: buf.get_u64()? }
        }
        MsgType::Rserverstats => {
            let n = buf.get_u16()?;
            let mut stats = Vec::with_capacity(n as usize);
            for _ in 0..n {
                stats.push(ServerStat {
                    name: buf.get_str()?,
                    stat_type: buf.get_u8()?,
                    value: buf.get_u64()?,
                });
            }
            Msg::Rserverstats { stats }
        }
        MsgType::Tgetquota => {
            Msg::Getquota { fid: buf.get_u32()?, quota_type: buf.get_u8()? }
        }
        MsgType::Rgetquota => {
            Msg::Rgetquota {
                bytes_used: buf.get_u64()?, bytes_limit: buf.get_u64()?,
                files_used: buf.get_u64()?, files_limit: buf.get_u64()?,
                grace: buf.get_u32()?,
            }
        }
        MsgType::Tsetquota => {
            Msg::Setquota {
                fid: buf.get_u32()?, quota_type: buf.get_u8()?,
                bytes_limit: buf.get_u64()?, files_limit: buf.get_u64()?,
                grace: buf.get_u32()?,
            }
        }
        MsgType::Tratelimit => {
            Msg::Ratelimit { fid: buf.get_u32()?, iops: buf.get_u32()?, bps: buf.get_u64()? }
        }
        MsgType::Rratelimit => {
            Msg::Rratelimit { iops: buf.get_u32()?, bps: buf.get_u64()? }
        }
        MsgType::Tasync => {
            let it = buf.get_u8()?;
            let rem = size as usize - HEADER_SIZE - 1;
            let payload = if rem > 0 { buf.get_fixed(rem)? } else { vec![] };
            Msg::Async {
                inner_type: MsgType::from_u8(it).unwrap_or(MsgType::Tcaps),
                payload,
            }
        }
        MsgType::Rasync => {
            Msg::Rasync { op_id: buf.get_u64()?, status: buf.get_u8()? }
        }
        MsgType::Tpoll => {
            Msg::Poll { op_id: buf.get_u64()? }
        }
        MsgType::Rpoll => {
            let status = buf.get_u8()?;
            let progress = buf.get_u32()?;
            let rem = size as usize - HEADER_SIZE - 5;
            let payload = if rem > 0 { buf.get_fixed(rem)? } else { vec![] };
            Msg::Rpoll { status, progress, payload }
        }
        MsgType::Tstreamopen => {
            Msg::Streamopen {
                fid: buf.get_u32()?, direction: buf.get_u8()?,
                offset: buf.get_u64()?, count: buf.get_u64()?,
            }
        }
        MsgType::Rstreamopen => {
            Msg::Rstreamopen { stream_id: buf.get_u32()? }
        }
        MsgType::Tstreamdata | MsgType::Rstreamdata => {
            Msg::Streamdata { stream_id: buf.get_u32()?, seq: buf.get_u32()?, data: buf.get_data()? }
        }
        MsgType::Tstreamclose => {
            Msg::Streamclose { stream_id: buf.get_u32()? }
        }
        MsgType::Tsearch => {
            Msg::Search {
                fid: buf.get_u32()?, query: buf.get_str()?,
                flags: buf.get_u32()?, max_results: buf.get_u32()?,
                cookie: buf.get_u64()?,
            }
        }
        MsgType::Rsearch => {
            let cookie = buf.get_u64()?;
            let n = buf.get_u16()?;
            let mut entries = Vec::with_capacity(n as usize);
            for _ in 0..n {
                entries.push(SearchEntry {
                    qid: buf.get_qid()?,
                    name: buf.get_str()?,
                    score: buf.get_u32()?,
                });
            }
            Msg::Rsearch { cookie, entries }
        }
        MsgType::Thash => {
            Msg::Hash {
                fid: buf.get_u32()?, algo: buf.get_u8()?,
                offset: buf.get_u64()?, length: buf.get_u64()?,
            }
        }
        MsgType::Rhash => {
            let algo = buf.get_u8()?;
            let hl = buf.get_u16()?;
            Msg::Rhash { algo, hash: buf.get_fixed(hl as usize)? }
        }

        // Reserved types that are never sent by peers
        MsgType::Tnotify | MsgType::Tleasebreak => Msg::Empty,
    };

    Ok(Fcall { size, msg_type, tag, msg })
}

fn unmarshal_subops(buf: &mut Buf) -> Result<Vec<SubOp>> {
    let n = buf.get_u16()?;
    let mut ops = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let opsize = buf.get_u32()? as usize;
        let t = buf.get_u8()?;
        let plen = opsize - SUBOP_HDR_SZ;
        let payload = if plen > 0 { buf.get_fixed(plen)? } else { vec![] };
        ops.push(SubOp {
            msg_type: MsgType::from_u8(t).unwrap_or(MsgType::Tcaps),
            payload,
        });
    }
    Ok(ops)
}
