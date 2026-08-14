//! 文件传输模块：**先确认、后分片、分批并发、ACK 确认、缺失重发、完整性校验**。
//!
//! # 传输流程（画个时间线方便理解）
//! ```text
//! 发送端                                          接收端
//!   |  1. 发 Offer(文件名/大小/哈希预览) ------>   显示聊天页一行"想发文件"
//!   |                                              用户点[接受]/[拒绝]
//!   |  <---- OfferReply(ok) 立刻应答（邀请已收到）--|
//!   |  若用户接受：<---- OfferAccept ---            （用户点击后发出）
//!   |  2. 切分并分片发送 Chunk ------>     存下每个分片并回 ChunkAck
//!   |  <---- ChunkAck（逐片确认，可同时 4 片在途）--|
//!   |  全部发完后发 Check ----------->    统计缺失的分片
//!   |  <---- Missing[缺失索引] ------------|
//!   |  若缺失：把缺失分片重新入队重发，再 Check（循环）
//!   |  若为空：发 Done(含整文件SHA-256) -> 拼接 + 校验哈希 + 写盘
//!   |  <---- Result(成功/失败) ------------|
//! ```
//!
//! # 关键设计点（学习重点）
//! 1. **先确认再传**：发送方只是"发出邀请"，对方点[接受]后才真正开始传分片，
//!    避免不必要地占用带宽，也让接收方明确同意（文件涉及隐私）。
//! 2. **分片（chunking）**：大文件一次装不下一条消息，拆成小块逐块传。
//! 3. **分批并发发送**：每批最多 MAX_IN_FLIGHT(4) 片同时在途，收到 ACK 再补发。
//! 4. **ACK 确认 + 超时重发**：每个分片要求对方确认（ChunkAck）；超时就重新入队。
//! 5. **缺失重发**：全部发完后发 Check，接收端把真正缺失的索引通过 Missing 返回，
//!    发送端只重发缺失的那些——最终的兜底保障。
//! 6. **包完整校验**：文件层再做一次整体 SHA-256 校验（Done 消息里带上）。
//! 7. **中断即失败**：如果网络断开，正在传输的所有文件都被标记为失败，
//!    并在聊天记录里留下一句"传输中断"（见 on_peer_disconnect）。

use crate::chat::ChatRecord;
use crate::crypto;
use crate::protocol::Envelope;
use crate::tui;
use crate::{AppState, MyBehaviour};
use base64::Engine;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::Swarm;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// 分片大小：64KB（JSON 编解码器对单条请求有 1MB 上限，64KB 兼顾数量与体积）。
pub const CHUNK_SIZE: usize = 64 * 1024;
/// 分批并发：同一时刻最多多少片在途。
pub const MAX_IN_FLIGHT: usize = 4;

/// 文件协议的消息（会被加密后装入 Envelope）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileMsg {
    /// 传输邀请（第一步）：发送方先问"我能不能给你这个文件？"
    Offer {
        file_id: u64,
        filename: String,
        /// 文件字节数。
        size: u64,
        /// 总分片数。
        total: u32,
        /// 整文件 SHA-256（hex），供接收方做最终校验。
        file_hash: String,
    },
    /// 接收方"接受"第 file_id 个文件（用户点[接受]后发出）。
    OfferAccept { file_id: u64 },
    /// 接收方"拒绝"第 file_id 个文件（用户点[拒绝]后发出）。
    OfferReject { file_id: u64 },
    /// 一个数据分片。
    Chunk {
        file_id: u64,
        filename: String,
        total: u32,
        index: u32,
        data: String,
    },
    /// 发送端发起的"查漏"：我全部发完了，请告诉我哪些片没收到。
    Check { file_id: u64, total: u32 },
    /// 传送完成：带整文件 SHA-256，接收端据此做完整性校验。
    Done {
        file_id: u64,
        filename: String,
        total: u32,
        file_hash: String,
    },
}

/// 文件协议的消息应答。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileResp {
    /// 对邀请的"受理"应答：总是立刻回 ok:true（表示收到邀请，并不等于接受）。
    OfferReply { file_id: u64, ok: bool },
    /// 分片确认（ACK）。
    ChunkAck { file_id: u64, index: u32 },
    /// 查漏应答：missing 是缺失的分片索引列表。
    Missing { file_id: u64, missing: Vec<u32> },
    /// 最终结果。
    Result { file_id: u64, ok: bool, msg: String },
}

/// 发送阶段：
/// Offering（已发邀请，等对方点击）-> Sending（发分片）-> Checking（等查漏）-> Done
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Phase {
    Offering,
    Sending,
    Checking,
    Done,
}

/// 发送端正在进行的文件传输状态。
pub struct OutgoingTransfer {
    pub peer: PeerId,
    pub file_id: u64,
    pub filename: String,
    pub file_hash: String,
    pub chunks: Vec<Vec<u8>>,
    pub pending: VecDeque<u32>,
    pub in_flight: usize,
    pub phase: Phase,
    pub checked: bool,
}

/// 接收端正在接收的文件状态。
pub struct IncomingTransfer {
    pub filename: String,
    pub total: u32,
    pub chunks: HashMap<u32, Vec<u8>>,
}

/// 一个已发出的请求（用于失败时定位是哪个分片 / 哪次查漏 / 邀请）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutboundReq {
    Offer,
    Chunk(u32),
    Check,
    Done,
}

/// 接收端"待决定"的传输邀请（显示在聊天页等用户点[接受]）。
#[derive(Debug, Clone)]
pub struct PendingOffer {
    pub file_id: u64,
    pub filename: String,
    /// 文件字节数。
    pub size: u64,
}

/// 把文件字节切成若干 CHUNK_SIZE 的分片。
fn chunk_file(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect()
}

/// 计算缺失分片索引。
fn compute_missing(chunks: &HashMap<u32, Vec<u8>>, total: u32) -> Vec<u32> {
    (0..total).filter(|i| !chunks.contains_key(i)).collect()
}

/// 当前时间戳（只用于记录排序）。
fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 用户发送文件：读文件、切分、为**每个已连接节点**发邀请。
pub fn start_file_send(swarm: &mut Swarm<MyBehaviour>, state: &mut AppState, path: &str) {
    let peers: Vec<PeerId> = state.connected.iter().copied().collect();
    if peers.is_empty() {
        state.log("[文件] 当前没有任何已连接的节点，无法发送".to_string());
        return;
    }

    // 1. 读取文件并切分 + 哈希（发送邀请需要大小/哈希做预览）
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            state.log(format!("[文件] 读取 {path} 失败: {e}"));
            return;
        }
    };
    let chunks = chunk_file(&data);
    let file_hash = crypto::sha256_hex(&data);
    let filename = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    state.log(format!(
        "[文件] 已读入 {path}：{} 字节，切为 {} 片",
        data.len(),
        chunks.len()
    ));
    // 弹出提示：正在发送文件
    tui::set_toast(&format!("正在发送文件：{filename}"));

    // 2. 为每个已连接节点各建一个传输任务，进入 Offering 阶段，发邀请
    for peer in peers {
        let file_id = state.next_file_id;
        state.next_file_id += 1;
        let pending: VecDeque<u32> = (0..chunks.len() as u32).collect();
        state.outgoing_files.insert(
            file_id,
            OutgoingTransfer {
                peer,
                file_id,
                filename: filename.clone(),
                file_hash: file_hash.clone(),
                chunks: chunks.clone(),
                pending,
                in_flight: 0,
                phase: Phase::Offering,
                checked: false,
            },
        );

        // 发邀请（Offer），并登记这个请求
        let Some(key) = state.sessions.get(&peer).copied() else {
            continue;
        };
        let offer = FileMsg::Offer {
            file_id,
            filename: filename.clone(),
            size: data.len() as u64,
            total: chunks.len() as u32,
            file_hash: file_hash.clone(),
        };
        let env = crypto::encrypt_json(&key, &offer).expect("序列化+加密不应失败");
        let req_id = swarm.behaviour_mut().file.send_request(&peer, env);
        state
            .file_outstanding
            .insert(req_id, (file_id, OutboundReq::Offer));

        // 在聊天记录里留一条"我正在发送文件"的提示
        let nick = state
            .peers
            .get(&peer)
            .map(|i| i.nickname.clone())
            .unwrap_or_default();
        state.record_to_peer(
            peer,
            ChatRecord::file(
                true,
                &filename,
                &format!("我正在发送 {filename} 给 {nick}"),
                now_ts(),
            ),
        );
    }
}

/// 驱动发送端所有传输：送分片 -> 查漏 -> 重发。
pub fn drive_outgoing(swarm: &mut Swarm<MyBehaviour>, state: &mut AppState) {
    let ids: Vec<u64> = state.outgoing_files.keys().copied().collect();
    for file_id in ids {
        let Some(t) = state.outgoing_files.get_mut(&file_id) else {
            continue;
        };
        // Offering 阶段等对方点按钮，什么都不做
        if t.phase == Phase::Offering {
            continue;
        }
        let Some(key) = state.sessions.get(&t.peer).copied() else {
            continue;
        };

        match t.phase {
            Phase::Sending => {
                while t.in_flight < MAX_IN_FLIGHT {
                    let Some(index) = t.pending.pop_front() else {
                        break;
                    };
                    let total = t.chunks.len() as u32;
                    let msg = FileMsg::Chunk {
                        file_id: t.file_id,
                        filename: t.filename.clone(),
                        total,
                        index,
                        data: base64::engine::general_purpose::STANDARD
                            .encode(&t.chunks[index as usize]),
                    };
                    let env = crypto::encrypt_json(&key, &msg).expect("序列化+加密不应失败");
                    let req_id = swarm.behaviour_mut().file.send_request(&t.peer, env);
                    state
                        .file_outstanding
                        .insert(req_id, (t.file_id, OutboundReq::Chunk(index)));
                    t.in_flight += 1;
                }

                if t.pending.is_empty() && t.in_flight == 0 && !t.checked {
                    let total = t.chunks.len() as u32;
                    let msg = FileMsg::Check { file_id: t.file_id, total };
                    let env = crypto::encrypt_json(&key, &msg).expect("序列化+加密不应失败");
                    let req_id = swarm.behaviour_mut().file.send_request(&t.peer, env);
                    state
                        .file_outstanding
                        .insert(req_id, (t.file_id, OutboundReq::Check));
                    t.checked = true;
                    t.phase = Phase::Checking;
                }
            }
            Phase::Offering | Phase::Checking | Phase::Done => {}
        }
    }
}

/// 处理"对端换来的文件协议应答"（OfferReply / ChunkAck / Missing / Result）。
pub fn on_file_response(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    request_id: OutboundRequestId,
    response: FileResp,
) {
    match response {
        FileResp::OfferReply { file_id: _, ok } => {
            // 对方收到了邀请。真正的"接受/拒绝"由 OfferAccept/Reject 决定，
            // 这里只是知道邀请已送达。
            let _ = ok;
            state.file_outstanding.remove(&request_id);
        }
        FileResp::ChunkAck { file_id, index: _ } => {
            if let Some(t) = state.outgoing_files.get_mut(&file_id) {
                t.in_flight = t.in_flight.saturating_sub(1);
            }
            state.file_outstanding.remove(&request_id);
        }
        FileResp::Missing { file_id, missing } => {
            let Some(t) = state.outgoing_files.get_mut(&file_id) else {
                return;
            };
            t.in_flight = 0;
            t.checked = false;
            t.phase = Phase::Sending;

            if missing.is_empty() {
                t.phase = Phase::Done;
                let Some(key) = state.sessions.get(&t.peer).copied() else {
                    return;
                };
                let total = t.chunks.len() as u32;
                let msg = FileMsg::Done {
                    file_id,
                    filename: t.filename.clone(),
                    total,
                    file_hash: t.file_hash.clone(),
                };
                let env = crypto::encrypt_json(&key, &msg).expect("序列化+加密不应失败");
                let req_id = swarm.behaviour_mut().file.send_request(&t.peer, env);
                state
                    .file_outstanding
                    .insert(req_id, (file_id, OutboundReq::Done));
            } else {
                let missing_count = missing.len();
                for idx in missing {
                    t.pending.push_back(idx);
                }
                t.phase = Phase::Sending;
                state.log(format!(
                    "[文件] 传输 {} 缺失 {} 个分片，正在重发…",
                    file_id, missing_count
                ));
            }
        }
        FileResp::Result { file_id, ok, msg } => {
            let text = format!(
                "[文件] 传输 {file_id} {}：{msg}",
                if ok { "成功" } else { "失败" }
            );
            state.log(text.clone());
            // 把传输结果写进与那个对端的聊天记录
            let (peer, filename) = match state.outgoing_files.get(&file_id) {
                Some(t) => (t.peer, t.filename.clone()),
                None => {
                    state.file_outstanding.retain(|_, (fid, _)| *fid != file_id);
                    state.outgoing_files.remove(&file_id);
                    return;
                }
            };
            state.record_to_peer(peer, ChatRecord::file(true, &filename, &text, now_ts()));
            state.file_outstanding.retain(|_, (fid, _)| *fid != file_id);
            state.outgoing_files.remove(&file_id);
            state.file_outstanding.retain(|_, (fid, _)| *fid != file_id);
            state.outgoing_files.remove(&file_id);
        }
    }
}

/// 处理"请求失败/超时"：定位是邀请/分片/查漏，决定补发或标记失败。
pub fn on_file_outbound_failure(state: &mut AppState, request_id: OutboundRequestId) {
    let Some((file_id, req)) = state.file_outstanding.remove(&request_id) else {
        return;
    };
    let Some(t) = state.outgoing_files.get_mut(&file_id) else {
        return;
    };
    match req {
        OutboundReq::Offer => {
            // 邀请本身失败/超时：对方没反应，标记失败并收尾
            let filename = t.filename.clone();
            let peer = t.peer;
            state.log(format!("[文件] 邀请(传输 {file_id}) 失败：对方无应答"));
            state.record_to_peer(
                peer,
                ChatRecord::file(true, &filename, "[文件] 发送邀请失败（对方无应答）", now_ts()),
            );
            state.outgoing_files.remove(&file_id);
        }
        OutboundReq::Chunk(index) => {
            t.pending.push_back(index);
            t.in_flight = t.in_flight.saturating_sub(1);
            t.phase = Phase::Sending;
            state.log(format!("[文件] 分片 {index} 发送失败，待重发"));
        }
        OutboundReq::Check | OutboundReq::Done => {
            t.checked = false;
            t.phase = Phase::Sending;
        }
    }
}

/// 对端断开连接：把它相关的所有传输标记为失败，并留档。
pub fn on_peer_disconnect(state: &mut AppState, peer: PeerId) {
    let ids: Vec<u64> = state.outgoing_files.keys().copied().collect();
    for file_id in ids {
        let Some(t) = state.outgoing_files.get_mut(&file_id) else {
            continue;
        };
        if t.peer == peer && t.phase != Phase::Done {
            let filename = t.filename.clone();
            state.log(format!("[文件] 与 {peer} 连接中断，传输 {file_id} 标记为失败"));
            state.record_to_peer(
                peer,
                ChatRecord::file(true, &filename, "[文件] 传输中断（连接断开），标记为失败", now_ts()),
            );
        }
    }
    state.outgoing_files.retain(|_, t| t.peer != peer || t.phase == Phase::Done);
    state.file_outstanding.retain(|_, (fid, _)| {
        state
            .outgoing_files
            .get(fid)
            .map_or(false, |t| t.peer != peer)
    });
}

/// 处理"对端发来的文件协议请求"（Offer / OfferAccept / OfferReject / Chunk / Check / Done）。
pub fn on_file_request(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    peer: PeerId,
    envelope: Envelope,
    channel: request_response::ResponseChannel<FileResp>,
) {
    let Some(key) = state.sessions.get(&peer).copied() else {
        let _ = swarm
            .behaviour_mut()
            .file
            .send_response(channel, FileResp::Result { file_id: 0, ok: false, msg: "尚未完成密钥协商".into() });
        return;
    };

    let msg: FileMsg = match crypto::decrypt_json(&key, &envelope) {
        Ok(m) => m,
        Err(e) => {
            state.log(format!("[文件] 收到无法通过完整性校验的消息: {e}"));
            let _ = swarm.behaviour_mut().file.send_response(
                channel,
                FileResp::Result { file_id: 0, ok: false, msg: "解密/完整性校验失败".into() },
            );
            return;
        }
    };

    match msg {
        // 情况 1：对方想发文件给我 -> 存进"待决定"列表，并在聊天页提示
        FileMsg::Offer { file_id, filename, size, .. } => {
            state.pending_offers.entry(peer).or_default().push(PendingOffer {
                file_id,
                filename: filename.clone(),
                size,
            });
            state.log(format!("[文件] {peer} 想发送文件：{filename}（{} 字节）", size));
            state.record_to_peer(
                peer,
                ChatRecord::file(
                    false,
                    &filename,
                    &format!("[文件] 对方想给你发送：{filename}（{} 字节）→ 请点击【接受】", size),
                    now_ts(),
                ),
            );
            // 立刻应答：告诉对方"收到邀请"，但接受与否等用户点按钮
            let _ = swarm
                .behaviour_mut()
                .file
                .send_response(channel, FileResp::OfferReply { file_id, ok: true });
        }
        // 情况 2：对方接受了 -> 我这边开始真正发分片
        FileMsg::OfferAccept { file_id } => {
            let accepted = state
                .outgoing_files
                .get(&file_id)
                .map(|t| t.phase == Phase::Offering)
                .unwrap_or(false);
            let _ = swarm
                .behaviour_mut()
                .file
                .send_response(channel, FileResp::OfferReply { file_id, ok: accepted });
            if accepted {
                if let Some(t) = state.outgoing_files.get_mut(&file_id) {
                    t.phase = Phase::Sending;
                    state.log(format!("[文件] {peer} 已接受文件，开始发送…"));
                }
                drive_outgoing(swarm, state);
            }
        }
        // 情况 3：对方拒绝了
        FileMsg::OfferReject { file_id } => {
            let _ = swarm
                .behaviour_mut()
                .file
                .send_response(channel, FileResp::OfferReply { file_id, ok: false });
            if let Some(t) = state.outgoing_files.get_mut(&file_id) {
                let filename = t.filename.clone();
                state.log(format!("[文件] {peer} 拒绝了文件 {file_id}"));
                state.record_to_peer(
                    peer,
                    ChatRecord::file(true, &filename, "[文件] 对方拒绝了该文件发送", now_ts()),
                );
            }
            state.outgoing_files.remove(&file_id);
            state.file_outstanding.retain(|_, (fid, _)| *fid != file_id);
        }
        // 情况 4：数据分片
        FileMsg::Chunk { file_id, filename, total, index, data } => {
            let inc = state
                .incoming_files
                .entry(file_id)
                .or_insert_with(|| IncomingTransfer { filename, total, chunks: HashMap::new() });
            let chunk = base64::engine::general_purpose::STANDARD
                .decode(&data)
                .expect("base64 解码失败，说明数据异常");
            inc.chunks.insert(index, chunk);
            let _ = swarm
                .behaviour_mut()
                .file
                .send_response(channel, FileResp::ChunkAck { file_id, index });
        }
        // 情况 5：查漏
        FileMsg::Check { file_id, total } => {
            let missing = state
                .incoming_files
                .get(&file_id)
                .map(|inc| compute_missing(&inc.chunks, total))
                .unwrap_or_else(|| (0..total).collect());
            let _ = swarm
                .behaviour_mut()
                .file
                .send_response(channel, FileResp::Missing { file_id, missing });
        }
        // 情况 6：完成，拼装 + 校验 + 写盘
        FileMsg::Done { file_id, filename, total: _, file_hash } => {
            let (ok, msg) = match state.incoming_files.get_mut(&file_id) {
                None => (false, "没有收到任何分片".to_string()),
                Some(inc) => {
                    if inc.chunks.len() != inc.total as usize {
                        let missing = compute_missing(&inc.chunks, inc.total);
                        (false, format!("分片不完整({}), 缺 {missing:?}", inc.filename))
                    } else {
                        let mut buf = Vec::new();
                        for i in 0..inc.total {
                            buf.extend_from_slice(&inc.chunks[&i]);
                        }
                        let actual = crypto::sha256_hex(&buf);
                        if actual != file_hash {
                            (false, format!("SHA-256 校验失败: 期望 {file_hash} 实际 {actual}"))
                        } else {
                            let dir = "downloads";
                            if let Err(e) = std::fs::create_dir_all(dir) {
                                (false, format!("创建 {dir} 目录失败: {e}"))
                            } else {
                                let path = format!("{dir}/{}", inc.filename);
                                match std::fs::write(&path, &buf) {
                                    Ok(_) => {
                                        state.log(format!(
                                            "[文件] 签收完成：{path}（{} 字节）",
                                            buf.len()
                                        ));
                                        (true, format!("完整收到并已保存为 {path}（{} 字节）", buf.len()))
                                    }
                                    Err(e) => (false, format!("写入失败: {e}")),
                                }
                            }
                        }
                    }
                }
            };
            // 从"待决定"里移除（如果还在的话），清理接收缓存，并留档到聊天
            if let Some(offers) = state.pending_offers.get_mut(&peer) {
                offers.retain(|o| o.file_id != file_id);
            }
            state.incoming_files.remove(&file_id);
            let text = format!(
                "[文件] 接收{}{}：{msg}",
                if ok { "成功" } else { "失败" },
                if ok {
                    format!("（{filename}）")
                } else {
                    String::new()
                }
            );
            state.log(text.clone());
            state.record_to_peer(
                peer,
                ChatRecord::file(false, &filename, &text, now_ts()),
            );
            let _ = swarm
                .behaviour_mut()
                .file
                .send_response(channel, FileResp::Result { file_id, ok, msg });
        }
    }
}

/// 用户点[接受]：把待决定邀请标记为接受，并通知对方真正开始发。
pub fn accept_file(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    peer: PeerId,
    file_id: u64,
) {
    let Some(key) = state.sessions.get(&peer).copied() else {
        state.log("[文件] 尚无法接受（未完成密钥协商）".to_string());
        return;
    };
    if let Some(offers) = state.pending_offers.get_mut(&peer) {
        offers.retain(|o| o.file_id != file_id);
    }
    state.record_to_peer(
        peer,
        ChatRecord::file(false, &file_id.to_string(), "[文件] 你已接受该文件，等待接收…", now_ts()),
    );
    let msg = FileMsg::OfferAccept { file_id };
    let env = crypto::encrypt_json(&key, &msg).expect("序列化+加密不应失败");
    let _ = swarm.behaviour_mut().file.send_request(&peer, env);
}

/// 用户点[拒绝]：通知对方我会拒绝，并移除邀请。
pub fn reject_file(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    peer: PeerId,
    file_id: u64,
) {
    let Some(key) = state.sessions.get(&peer).copied() else {
        return;
    };
    if let Some(offers) = state.pending_offers.get_mut(&peer) {
        offers.retain(|o| o.file_id != file_id);
    }
    state.record_to_peer(
        peer,
        ChatRecord::file(false, &file_id.to_string(), "[文件] 你已拒绝该文件", now_ts()),
    );
    let msg = FileMsg::OfferReject { file_id };
    let env = crypto::encrypt_json(&key, &msg).expect("序列化+加密不应失败");
    let _ = swarm.behaviour_mut().file.send_request(&peer, env);
}