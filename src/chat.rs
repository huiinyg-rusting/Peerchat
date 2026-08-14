//! 聊天协议模块：消息与确认的结构定义，以及可用于持久化的聊天记录。
//!
//! # ACK（确认）机制
//! 聊天虽然消息本身不要求可靠重传，但为了让发送方知道"对方确实收到了"，
//! 接收方会对每条消息回一个 ChatAck（ACK，Acknowledge）。
//! 这样发送方可以看到自己的消息是否送达成功，属于最基础的可靠通信保障，
//! 与文件传输里对每个分片做 ACK 的思路一致。

use serde::{Deserialize, Serialize};

/// 一条聊天消息（会被加密后装进 Envelope 再发送）。
/// 发送链路：ChatMsg --(JSON)--> 明文 --(ChaCha20-Poly1305 加密)--> Envelope --> 网络。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMsg {
    /// 消息 ID：每条消息唯一，用于对上 ACK（确认哪一条被收到）。
    pub msg_id: u64,
    /// 发送方昵称。
    pub nickname: String,
    /// 聊天文本内容。
    pub text: String,
}

/// 对一条聊天消息的确认（ACK = Acknowledge，网络术语里指"我已收到"）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatAck {
    /// 确认的是哪一条消息（对应 ChatMsg::msg_id）。
    pub msg_id: u64,
    /// 是否成功收到并解密。false 常见原因：对方尚未完成密钥协商。
    pub ok: bool,
}

/// 当前本地时间（时:分:秒），用于聊天记录展示发送时刻。
fn now_time() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// 聊天页里的一行记录（可持久化到 conversations/<peer>.json）。
/// 用 "kind" 字符串区分三类行，避免枚举的字段不统一：
/// - "text"  ：普通聊天消息（text=内容，nickname=说话人）
/// - "system"：系统提示（例如：昵称变更、对方离线、传输中断）
/// - "file"  ：文件传输记录（text=一句人话描述）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRecord {
    /// true = 我发出的；false = 别人发给我的。
    pub outbound: bool,
    /// "text" / "system" / "file"
    pub kind: String,
    /// record 里需要保存的名字（text:说话人昵称；file:文件名；system:忽略）。
    pub name: String,
    /// 展示内容。
    pub text: String,
    /// 单调递增的时间戳（只用于排序，不需要绝对准确）。
    pub ts: u64,
    /// 发送时刻（本地时:分:秒），用于界面展示。旧记录缺此字段时为 ""。
    #[serde(default)]
    pub time: String,
}

impl ChatRecord {
    /// 一条普通聊天文本。
    pub fn text(outbound: bool, nickname: &str, text: &str, ts: u64) -> Self {
        Self {
            outbound,
            kind: "text".into(),
            name: nickname.to_string(),
            text: text.to_string(),
            ts,
            time: now_time(),
        }
    }

    /// 一条系统提示（不区分方向，纯提示用）。
    pub fn system(text: &str, ts: u64) -> Self {
        Self {
            outbound: false,
            kind: "system".into(),
            name: String::new(),
            text: text.to_string(),
            ts,
            time: now_time(),
        }
    }

    /// 一条文件传输记录。
    pub fn file(outbound: bool, filename: &str, text: &str, ts: u64) -> Self {
        Self {
            outbound,
            kind: "file".into(),
            name: filename.to_string(),
            text: text.to_string(),
            ts,
            time: now_time(),
        }
    }
}