//! 持久化模块：把"自己"和"聊天记录"保存成 JSON，重启后不丢。
//!
//! # 保存哪些东西？
//! 1. **config.json**（工作目录）：本节点昵称 + 持久化的 libp2p 密钥对。
//!    保存密钥对的目的：PeerId（节点 ID）是从密钥对算出来的，密钥固定 => ID 固定。
//!    如果每次启动都随机生成密钥，那每次重启 ID 都会变，别人就"找不到你了"。
//! 2. **conversations/ 目录**：每个对端一个 JSON 文件，记录和它的聊天记录、
//!    昵称、最近 IP。文件名用 PeerId（对端 ID），这样无论对方改什么昵称都能对上。
//!
//! # 为什么用 JSON 而不是数据库？
//! 学习项目尽量简单透明：JSON 是人类可读的文本文件，用记事本就能打开看内容，
//! 也方便演示"数据到底存在哪、长什么样"。

use crate::chat::ChatRecord;
use crate::crypto::{appkey_from_b64, appkey_to_b64, AppCrypto};
use base64::Engine;
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

/// config.json 的内容。
#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    /// 本节点昵称（用户可改，改完写回文件）。
    pub nickname: String,
    /// libp2p 密钥对的序列化字节（base64 编码保存）。
    /// 有它 => PeerId 稳定；丢了 => ID 变化，相当于"换了个身份"。
    pub keypair_b64: String,
    /// 应用层 X25519 密钥（base64 编码保存），用于第二层加密的密钥协商。
    /// 持久化它 => 重启后应用层身份不变，与对端已缓存的会话密钥仍一致。
    #[serde(default)]
    pub appkey_b64: String,
    /// 通过 TUI「+加好友」直连过的对端地址（含 /p2p/<id>），重启后自动重新拨号。
    #[serde(default)]
    pub friends: Vec<String>,
    /// 通过 TUI「+加好友」添加的 DHT 引导站点（含 /p2p/<id>），重启后自动加入 DHT。
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,
}

/// 读取（或首次生成）config.json。
/// - 文件存在：反序列化并还原 libp2p 密钥对 + 应用层密钥；
/// - 文件不存在：新生成两套密钥并写盘（同时生成默认昵称）。
///
/// 返回：`(配置, libp2p 身份密钥, 应用层加密密钥)`。
pub fn load_or_create_config(
    nickname_arg: Option<String>,
) -> (AppConfig, Keypair, AppCrypto) {
    let path = "config.json";
    // 1. 尝试读取已有配置
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(cfg) = serde_json::from_str::<AppConfig>(&text) {
            // 命令行 --nick 优先：传了就覆盖文件里的昵称并写回
            let mut cfg = cfg;
            let mut dirty = false;
            if let Some(ref n) = nickname_arg {
                cfg.nickname = n.to_string();
                dirty = true;
            }
            // 还原 libp2p 密钥对（失败就说明文件坏了，降级为重新生成）
            if let Ok(kp) = keypair_from_b64(&cfg.keypair_b64) {
                // 还原应用层密钥；缺失/损坏则新生成一个（并写回文件）
                let app = match appkey_from_b64(&cfg.appkey_b64) {
                    Ok(a) => a,
                    Err(_) => {
                        let a = AppCrypto::new();
                        cfg.appkey_b64 = appkey_to_b64(&a);
                        dirty = true;
                        a
                    }
                };
                if dirty {
                    let _ = save_config(&cfg);
                }
                return (cfg, kp, app);
            }
        }
    }
    // 2. 首次运行：生成新密钥对 + 默认昵称
    let keypair = Keypair::generate_ed25519();
    let app = AppCrypto::new();
    let cfg = AppConfig {
        nickname: nickname_arg.unwrap_or_else(|| "匿名用户".to_string()),
        keypair_b64: keypair_to_b64(&keypair),
        appkey_b64: appkey_to_b64(&app),
        friends: Vec::new(),
        bootstrap_nodes: Vec::new(),
    };
    let _ = save_config(&cfg);
    (cfg, keypair, app)
}

/// 把 AppConfig 写回 config.json。
pub fn save_config(cfg: &AppConfig) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(cfg).expect("config 一定能序列化");
    std::fs::write("config.json", json)
}

/// 更新 config.json 里的昵称（改名时调用）。
pub fn save_nickname(new_nickname: &str) {
    if let Some(mut cfg) = load_config_struct() {
        cfg.nickname = new_nickname.to_string();
        let _ = save_config(&cfg);
    }
}

/// 仅读取 config.json（不涉及密钥还原），改个名用。
fn load_config_struct() -> Option<AppConfig> {
    let text = std::fs::read_to_string("config.json").ok()?;
    serde_json::from_str(&text).ok()
}

/// 追加一个直连好友地址（去重后写回 config.json）。
pub fn add_friend(addr: &str) {
    if let Some(mut cfg) = load_config_struct() {
        if !cfg.friends.iter().any(|f| f == addr) {
            cfg.friends.push(addr.to_string());
            let _ = save_config(&cfg);
        }
    }
}

/// 追加一个 DHT 引导站点地址（去重后写回 config.json）。
pub fn add_bootstrap_node(addr: &str) {
    if let Some(mut cfg) = load_config_struct() {
        if !cfg.bootstrap_nodes.iter().any(|f| f == addr) {
            cfg.bootstrap_nodes.push(addr.to_string());
            let _ = save_config(&cfg);
        }
    }
}

/// 密钥对 -> base64 字符串（存盘）。
pub fn keypair_to_b64(kp: &Keypair) -> String {
    let bytes = kp.to_protobuf_encoding().expect("密钥编码不应失败");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// base64 字符串 -> 密钥对（还原身份）。
pub fn keypair_from_b64(s: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
    Ok(Keypair::from_protobuf_encoding(&bytes)?)
}

/// conversations/ 目录里每个对端一个文件。文件名 = 对端 PeerId。
fn conv_dir() -> String {
    "conversations".to_string()
}

fn conv_path(peer_id: &str) -> String {
    format!("{}/{}.json", conv_dir(), peer_id)
}

/// 一个对端的全部聊天记录（存 conversations/<peer_id>.json）。
#[derive(Debug, Serialize, Deserialize)]
pub struct ConversationFile {
    /// 对端 PeerId（字符串形式，因为文件路径要用它）。
    pub peer_id: String,
    /// 对端最近一次知道的昵称。
    pub nickname: String,
    /// 对端最近一次知道的地址（IP:port，仅用于展示）。
    pub last_addr: Option<String>,
    /// 聊天记录（聊天/文件传输记录等）。
    pub records: Vec<ChatRecord>,
}

/// 加载某个对端的聊天记录；文件不存在则返回空记录（新对话）。
pub fn load_conversation(peer_id: &libp2p::PeerId) -> ConversationFile {
    let id = peer_id.to_string();
    match std::fs::read_to_string(conv_path(&id)) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| empty_conv(&id)),
        Err(_) => empty_conv(&id),
    }
}

/// 空会话：PeerId 已知，昵称/地址/记录都是空的（等网络事件填充）。
fn empty_conv(id: &str) -> ConversationFile {
    ConversationFile {
        peer_id: id.to_string(),
        nickname: String::new(),
        last_addr: None,
        records: Vec::new(),
    }
}

/// 把聊天记录写回 conversations/<peer_id>.json（覆盖写，简单可靠）。
pub fn save_conversation(conv: &ConversationFile) {
    let _ = std::fs::create_dir_all(conv_dir());
    let json = serde_json::to_string_pretty(conv).expect("会话一定能序列化");
    // peer_id 是文件里存的、我们写入时一定是合法字符串，这里解析失败就跳过写盘
    let path = conv_path(&conv.peer_id);
    if conv.peer_id.parse::<libp2p::PeerId>().is_ok() {
        let _ = std::fs::write(path, json);
    }
}

/// 扫描 conversations/ 目录，返回所有对端的 PeerId（启动时恢复联系人列表）。
pub fn list_known_peers() -> Vec<libp2p::PeerId> {
    let mut peers = Vec::new();
    if let Ok(rd) = std::fs::read_dir(conv_dir()) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                if let Ok(pid) = name.trim_end_matches(".json").parse::<libp2p::PeerId>() {
                    peers.push(pid);
                }
            }
        }
    }
    peers
}