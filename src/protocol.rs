//! 网络协议定义：协议名常量、通信信封、密钥协商消息。
//!
//! 三个 request-response 协议分工：
//! - KEY：应用层密钥协商（ECDH 公钥交换）——发生在第一层 Noise 的保护之下
//! - CHAT：聊天消息（负载被第二层加密装在 Envelope 里）
//! - FILE：文件分片传输（负载同样装在 Envelope 里）
//! 之所以让聊天和文件各占一条协议，是因为不同业务应该使用不同的协议标识，
//! 便于扩展和维护（这也是模块拆分的意义）。

use serde::{Deserialize, Serialize};

// 网络常识小贴士：libp2p 里"协议"是一串字符串 ID（也叫协议名/协议ID）。
// 连接建立后，双方用 multistream-select 机制互相说"我支持这些协议，你支持哪些？"，
// 只有双方都支持的协议才能使用。给不同的业务用不同的协议名，
// 就像 HTTP 有 GET/POST、TCP 有不同端口一样，是为了区分"这条子流在传什么"。

/// 密钥协商协议名（multistream-select 的协议 ID）。
pub const KEY_PROTOCOL: &str = "/peerchat/key/1.0.0";
/// 聊天协议名。
pub const CHAT_PROTOCOL: &str = "/peerchat/chat/1.0.0";
/// 文件传输协议名。
pub const FILE_PROTOCOL: &str = "/peerchat/file/1.0.0";

/// 密钥协商消息：双方交换昵称与应用层公钥。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHello {
    /// 发送方昵称（每个客户端可自定义、可重复使用的昵称）。
    pub nickname: String,
    /// 发送方应用层 X25519 公钥（32 字节）。
    pub pubkey: [u8; 32],
}

/// 加密信封：request-response 里真正在网络上传输的"外壳"。
///
/// 内部（明文部分）是 JSON 序列化后的业务消息（聊天 / 文件分片……），
/// 外部用应用层会话密钥进行 ChaCha20-Poly1305 加密。
/// 也就是说网络上同时有两层保护：Noise（第一层）+ 本信封（第二层）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// 随机 nonce（base64 编码，12 字节），每条消息唯一。
    pub nonce: String,
    /// 密文 + AEAD 认证标签（base64 编码）。
    pub ciphertext: String,
}