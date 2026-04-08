//! Minimal FFI bindings for libibverbs.
//!
//! Only the functions and types needed by this project are declared here.
//! This avoids the `rdma-sys` + `bindgen` dependency entirely.
//!
//! Link: `cargo:rustc-link-lib=ibverbs`

#![allow(non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_uint, c_void};

// ── Opaque types ──────────────────────────────────────────────────

// We declare these as opaque structs since we only pass pointers.
#[repr(C)]
pub struct ibv_device {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct ibv_context {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct ibv_pd {
    _opaque: [u8; 0],
}

// ── Transparent types (we read fields) ────────────────────────────

#[repr(C)]
pub struct ibv_comp_channel {
    pub fd: c_int,
}

#[repr(C)]
pub struct ibv_cq {
    _opaque: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_mr {
    pub context: *mut ibv_context,
    pub pd: *mut ibv_pd,
    pub addr: *mut c_void,
    pub length: usize,
    pub handle: u32,
    pub lkey: u32,
    pub rkey: u32,
}

#[repr(C)]
pub struct ibv_qp {
    _priv1: *mut c_void,     // context
    _priv2: *mut c_void,     // qp_context
    _priv3: *mut c_void,     // pd
    _priv4: *mut c_void,     // send_cq
    _priv5: *mut c_void,     // recv_cq
    _priv6: *mut c_void,     // srq
    _priv7: u32,             // handle
    pub qp_num: u32,
    _priv8: u32,             // state (ibv_qp_state)
    pub qp_type: u32,
    // ... more fields follow but we don't access them
}

// ── GID ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub union ibv_gid {
    pub raw: [u8; 16],
    pub global: ibv_gid_global,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_gid_global {
    pub subnet_prefix: u64,
    pub interface_id: u64,
}

impl Default for ibv_gid {
    fn default() -> Self {
        Self { raw: [0u8; 16] }
    }
}

// ── Work completions ──────────────────────────────────────────────

pub const IBV_WC_SUCCESS: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_wc {
    pub wr_id: u64,
    pub status: u32,
    pub opcode: u32,
    pub vendor_err: u32,
    pub byte_len: u32,
    pub imm_data: u32,
    pub qp_num: u32,
    pub src_qp: u32,
    pub wc_flags: c_uint,
    pub pkey_index: u16,
    pub slid: u16,
    pub sl: u8,
    pub dlid_path_bits: u8,
}

impl Default for ibv_wc {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// ── Scatter/gather entry ──────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ibv_sge {
    pub addr: u64,
    pub length: u32,
    pub lkey: u32,
}

// ── Send work request ─────────────────────────────────────────────

pub const IBV_WR_SEND: u32 = 0;
pub const IBV_WR_RDMA_WRITE: u32 = 1;
pub const IBV_WR_RDMA_READ: u32 = 3;

pub const IBV_SEND_SIGNALED: c_uint = 1 << 0;

#[repr(C)]
pub struct ibv_send_wr {
    pub wr_id: u64,
    pub next: *mut ibv_send_wr,
    pub sg_list: *mut ibv_sge,
    pub num_sge: c_int,
    pub opcode: u32,
    pub send_flags: c_uint,
    pub imm_data: u32,
    // Union for RDMA/atomic — we use a flat struct with the RDMA fields.
    pub wr_rdma_rkey: u32,
    pub wr_rdma_remote_addr: u64,
    // Remaining fields we don't use.
    _pad: [u8; 32],
}

// ── Receive work request ──────────────────────────────────────────

#[repr(C)]
pub struct ibv_recv_wr {
    pub wr_id: u64,
    pub next: *mut ibv_recv_wr,
    pub sg_list: *mut ibv_sge,
    pub num_sge: c_int,
}

// ── QP init attributes ────────────────────────────────────────────

pub const IBV_QPT_RC: u32 = 2;

#[repr(C)]
pub struct ibv_qp_cap {
    pub max_send_wr: u32,
    pub max_recv_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_inline_data: u32,
}

#[repr(C)]
pub struct ibv_qp_init_attr {
    pub qp_context: *mut c_void,
    pub send_cq: *mut ibv_cq,
    pub recv_cq: *mut ibv_cq,
    pub srq: *mut c_void, // ibv_srq*
    pub cap: ibv_qp_cap,
    pub qp_type: u32,
    pub sq_sig_all: c_int,
}

// ── QP modify attributes ──────────────────────────────────────────

// ibv_qp_state
pub const IBV_QPS_RESET: u32 = 0;
pub const IBV_QPS_INIT: u32 = 1;
pub const IBV_QPS_RTR: u32 = 2;
pub const IBV_QPS_RTS: u32 = 3;
pub const IBV_QPS_ERR: u32 = 6;

// ibv_qp_attr_mask
pub const IBV_QP_STATE: c_int = 1 << 0;
pub const IBV_QP_CUR_STATE: c_int = 1 << 1;
pub const IBV_QP_EN_SQD_ASYNC_NOTIFY: c_int = 1 << 2;
pub const IBV_QP_ACCESS_FLAGS: c_int = 1 << 3;
pub const IBV_QP_PKEY_INDEX: c_int = 1 << 4;
pub const IBV_QP_PORT: c_int = 1 << 5;
pub const IBV_QP_QKEY: c_int = 1 << 6;
pub const IBV_QP_AV: c_int = 1 << 7;
pub const IBV_QP_PATH_MTU: c_int = 1 << 8;
pub const IBV_QP_TIMEOUT: c_int = 1 << 9;
pub const IBV_QP_RETRY_CNT: c_int = 1 << 10;
pub const IBV_QP_RNR_RETRY: c_int = 1 << 11;
pub const IBV_QP_RQ_PSN: c_int = 1 << 12;
pub const IBV_QP_MAX_QP_RD_ATOMIC: c_int = 1 << 13;
pub const IBV_QP_ALT_PATH: c_int = 1 << 14;
pub const IBV_QP_MIN_RNR_TIMER: c_int = 1 << 15;
pub const IBV_QP_SQ_PSN: c_int = 1 << 16;
pub const IBV_QP_MAX_DEST_RD_ATOMIC: c_int = 1 << 17;
pub const IBV_QP_DEST_QPN: c_int = 1 << 20;

// ibv_mtu
pub const IBV_MTU_1024: u32 = 3;

// ibv_access_flags
pub const IBV_ACCESS_LOCAL_WRITE: c_int = 1 << 0;
pub const IBV_ACCESS_REMOTE_WRITE: c_int = 1 << 1;
pub const IBV_ACCESS_REMOTE_READ: c_int = 1 << 2;

#[repr(C)]
pub struct ibv_global_route {
    pub dgid: ibv_gid,
    pub flow_label: u32,
    pub sgid_index: u8,
    pub hop_limit: u8,
    pub traffic_class: u8,
}

#[repr(C)]
pub struct ibv_ah_attr {
    pub grh: ibv_global_route,
    pub dlid: u16,
    pub sl: u8,
    pub src_path_bits: u8,
    pub static_rate: u8,
    pub is_global: u8,
    pub port_num: u8,
}

#[repr(C)]
pub struct ibv_qp_attr {
    pub qp_state: u32,
    pub cur_qp_state: u32,
    pub path_mtu: u32,
    pub path_mig_state: u32,
    pub qkey: u32,
    pub rq_psn: u32,
    pub sq_psn: u32,
    pub dest_qp_num: u32,
    pub qp_access_flags: c_int,
    pub cap: ibv_qp_cap,
    pub ah_attr: ibv_ah_attr,
    pub alt_ah_attr: ibv_ah_attr,
    pub pkey_index: u16,
    pub alt_pkey_index: u16,
    pub en_sqd_async_notify: u8,
    pub sq_draining: u8,
    pub max_rd_atomic: u8,
    pub max_dest_rd_atomic: u8,
    pub min_rnr_timer: u8,
    pub port_num: u8,
    pub timeout: u8,
    pub retry_cnt: u8,
    pub rnr_retry: u8,
    pub alt_port_num: u8,
    pub alt_timeout: u8,
    pub rate_limit: u32,
}

// ── Port attributes ───────────────────────────────────────────────

#[repr(C)]
pub struct ibv_port_attr {
    pub state: u32,
    pub max_mtu: u32,
    pub active_mtu: u32,
    pub gid_tbl_len: c_int,
    pub port_cap_flags: u32,
    pub max_msg_sz: u32,
    pub bad_pkey_cntr: u32,
    pub qkey_viol_cntr: u32,
    pub pkey_tbl_len: u16,
    pub lid: u16,
    pub sm_lid: u16,
    pub lmc: u8,
    pub max_vl_num: u8,
    pub sm_sl: u8,
    pub subnet_timeout: u8,
    pub init_type_reply: u8,
    pub active_width: u8,
    pub active_speed: u8,
    pub phys_state: u8,
    pub link_layer: u8,
    pub flags: u8,
    pub port_cap_flags2: u16,
}

// ── Functions ─────────────────────────────────────────────────────

extern "C" {
    // Device management
    pub fn ibv_get_device_list(num_devices: *mut c_int) -> *mut *mut ibv_device;
    pub fn ibv_free_device_list(list: *mut *mut ibv_device);
    pub fn ibv_get_device_name(device: *mut ibv_device) -> *const c_char;
    pub fn ibv_open_device(device: *mut ibv_device) -> *mut ibv_context;
    pub fn ibv_close_device(context: *mut ibv_context) -> c_int;

    // Protection domain
    pub fn ibv_alloc_pd(context: *mut ibv_context) -> *mut ibv_pd;
    pub fn ibv_dealloc_pd(pd: *mut ibv_pd) -> c_int;

    // Completion channel
    pub fn ibv_create_comp_channel(context: *mut ibv_context) -> *mut ibv_comp_channel;
    pub fn ibv_destroy_comp_channel(channel: *mut ibv_comp_channel) -> c_int;

    // Completion queue
    pub fn ibv_create_cq(
        context: *mut ibv_context,
        cqe: c_int,
        cq_context: *mut c_void,
        channel: *mut ibv_comp_channel,
        comp_vector: c_int,
    ) -> *mut ibv_cq;
    pub fn ibv_destroy_cq(cq: *mut ibv_cq) -> c_int;
    pub fn ibv_poll_cq(cq: *mut ibv_cq, num_entries: c_int, wc: *mut ibv_wc) -> c_int;
    pub fn ibv_req_notify_cq(cq: *mut ibv_cq, solicited_only: c_int) -> c_int;
    pub fn ibv_get_cq_event(
        channel: *mut ibv_comp_channel,
        cq: *mut *mut ibv_cq,
        cq_context: *mut *mut c_void,
    ) -> c_int;
    pub fn ibv_ack_cq_events(cq: *mut ibv_cq, nevents: c_uint);

    // Queue pair
    pub fn ibv_create_qp(pd: *mut ibv_pd, qp_init_attr: *mut ibv_qp_init_attr) -> *mut ibv_qp;
    pub fn ibv_destroy_qp(qp: *mut ibv_qp) -> c_int;
    pub fn ibv_modify_qp(qp: *mut ibv_qp, attr: *mut ibv_qp_attr, attr_mask: c_int) -> c_int;

    // Memory region
    pub fn ibv_reg_mr(
        pd: *mut ibv_pd,
        addr: *mut c_void,
        length: usize,
        access: c_int,
    ) -> *mut ibv_mr;
    pub fn ibv_dereg_mr(mr: *mut ibv_mr) -> c_int;

    // Post work requests
    pub fn ibv_post_send(
        qp: *mut ibv_qp,
        wr: *mut ibv_send_wr,
        bad_wr: *mut *mut ibv_send_wr,
    ) -> c_int;
    pub fn ibv_post_recv(
        qp: *mut ibv_qp,
        wr: *mut ibv_recv_wr,
        bad_wr: *mut *mut ibv_recv_wr,
    ) -> c_int;

    // Query
    pub fn ibv_query_gid(
        context: *mut ibv_context,
        port_num: u8,
        index: c_int,
        gid: *mut ibv_gid,
    ) -> c_int;
    pub fn ibv_query_port(
        context: *mut ibv_context,
        port_num: u8,
        port_attr: *mut ibv_port_attr,
    ) -> c_int;
}
