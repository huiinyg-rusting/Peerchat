//! 应用层加密模块（第二层加密 / 双层加密的下层语义）。
//!
//! # 先认识三个密码学词汇（只用到这么多）
//! - **对称加密**：加密和解密用**同一把钥匙**（像一把锁一把钥匙）。快，但前提是双方先共享同一把钥匙。
//!   本模块用的 ChaCha20-Poly1305 就是一种对称加密（而且自带完整性校验，见下）。
//! - **非对称加密（公钥/私钥）**：每个人有一对钥匙——公钥可以随便发给别人，私钥自己藏好。
//!   公钥能加密，私钥能解密。X25519 是其中一种具体算法。
//! - **哈希（摘要）**：把任意长度的数据算成一串固定长度的指纹（SHA-256）。数据哪怕改一位，指纹就全变。
//!   用来做文件完整性校验（见 file_transfer.rs 的 SHA-256）。
//!
//! # 双层加密设计（为什么有两层？）
//! 1. **第一层：libp2p Noise 握手加密（传输层）**
//!    所有 libp2p 流量在网络上传输时都由 Noise 协议加密，并基于节点身份做了双向认证。
//!    这保证了网络层不可窃听、不可篡改、身份可信。
//! 2. **第二层：本模块的应用层加密（协议负载层）**
//!    在 request-response 的请求/响应当中，真正的业务负载（聊天文本、文件分片）还会被
//!    ChaCha20-Poly1305 再次加密。这样即使第一层被绕过（比如未来某个传输插件不开加密），
//!    或者有人在协议层截获了"明文"格式的消息，也依然无法读取真正的数据内容。
//!
//! # 应用层密钥协商（ECDH + HKDF）——怎么"不用传钥匙"就共享一把钥匙？
//! 对称加密要求双方有同一把钥匙，但网络上传钥匙会被偷听，怎么办？用 ECDH 的数学魔法：
//! 1. 每个节点启动时，独立生成一对 X25519 椭圆曲线密钥（应用层密钥，与 libp2p 身份无关）。
//! 2. 两个节点建立连接后，通过 request-response 交换各自的**应用层公钥**。
//!    （这个交换通道本身已经处于 Noise 第一层加密之下，因此公钥不可能被中间人篡改。）
//! 3. 双方各自计算：`共享秘密 = X25519(自己的私钥, 对方的公钥)`。
//!    由于 X25519 的数学性质，双方算出来的共享秘密**完全相同**，且外人无法从公钥反推出它。
//! 4. 用 HKDF-SHA256 把共享秘密"正规地"派生为 32 字节会话密钥。
//!    （直接拿原始共享秘密当密钥是不好的习惯，HKDF 会做信息去相关，得到更安全的密钥。）
//!
//! # 完整性校验（包完整校验机制）
//! ChaCha20-Poly1305 是 **AEAD**（Authenticated Encryption with Associated Data，认证加密）。
//! 加密后的密文会附带一个认证标签：接收方解密时，任何一位数据被篡改、丢失、损坏，
//! 解密都会失败并返回错误。因此"加密 + 完整性 + 真实性"一次全部搞定。
//! （针对文件传输，模块 file_transfer.rs 还会额外做整文件 SHA-256 校验，双保险。）

use crate::protocol::Envelope;
use base64::Engine;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// 应用层加密器：持有本节点的 X25519 密钥对。
pub struct AppCrypto {
    /// 本节点的应用层私钥（X25519）。**绝对不要发给别人！**
    secret: StaticSecret,
    /// 本节点的应用层公钥，可以公开，会通过密钥协商发给对方。
    pub pubkey: [u8; 32],
}

impl AppCrypto {
    /// 生成一对全新的应用层密钥。
    pub fn new() -> Self {
        // 使用系统安全随机数生成私钥。
        // x25519 私钥本质上就是 32 个随机字节。
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let pubkey = PublicKey::from(&secret);
        Self {
            secret,
            pubkey: *pubkey.as_bytes(),
        }
    }

    /// 用已有的 32 字节私钥还原应用层密钥（持久化后重启时用）。
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let pubkey = PublicKey::from(&secret);
        Self {
            secret,
            pubkey: *pubkey.as_bytes(),
        }
    }

    /// 取出私钥的原始 32 字节（用于持久化到 config.json）。
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.secret.as_bytes()
    }

    /// 与某个对端节点协商出**双方一致**的 32 字节会话密钥。
    ///
    /// `remote_pubkey` 是对端应用层公钥（通过密钥协商消息拿到）。
    /// 本函数计算 `X25519(本节点私钥, 对端公钥)`，再经 HKDF 派生。
    /// 对端调用同样的函数（只是本节点/对端身份互换），得到完全相同的结果。
    pub fn derive_session_key(&self, remote_pubkey: &[u8; 32]) -> [u8; 32] {
        // 1. X25519 密钥交换：计算共享秘密
        let remote = PublicKey::from(*remote_pubkey);
        let shared = self.secret.diffie_hellman(&remote);

        // 2. HKDF-SHA256 派生：salt 用固定的域分离串，info 用于说明用途。
        //    Hkdf::new(可选盐, 输入密钥材料)；expand(用途信息, 输出缓冲区)。
        let hk = Hkdf::<Sha256>::new(Some(b"peerchat-app-v1"), shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"session-key", &mut key)
            .expect("32 字节输出一定满足 HKDF 长度要求");
        key
    }
}

impl Default for AppCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// 应用层密钥对 -> base64 字符串（持久化到 config.json）。
pub fn appkey_to_b64(kp: &AppCrypto) -> String {
    base64::engine::general_purpose::STANDARD.encode(kp.secret_bytes())
}

/// base64 字符串 -> 应用层密钥对（重启后还原身份）。
pub fn appkey_from_b64(s: &str) -> Result<AppCrypto, Box<dyn std::error::Error>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
    if bytes.len() != 32 {
        return Err("应用层密钥长度不对（应为 32 字节）".into());
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(AppCrypto::from_secret_bytes(&buf))
}

/// 计算一串字节的 SHA-256 摘要（十六进制字符串），用于文件完整性校验。
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 把一个可序列化的消息对象加密成一个「信封」。
///
/// 步骤：消息 -> JSON 字节 -> ChaCha20-Poly1305 加密（随机 nonce）-> Envelope。
/// 随机 nonce 保证同一条消息即使重复发送，密文也完全不同（重放保护）。
pub fn encrypt_json<T: Serialize>(key: &[u8; 32], msg: &T) -> Result<Envelope, Box<dyn std::error::Error>> {
    let plaintext = serde_json::to_vec(msg)?;
    encrypt(key, &plaintext)
}

/// 与 [`encrypt_json`] 相反：解密并反序列化，同时完成 AEAD 完整性校验。
pub fn decrypt_json<T: DeserializeOwned>(key: &[u8; 32], env: &Envelope) -> Result<T, Box<dyn std::error::Error>> {
    let plaintext = decrypt(key, env)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// 底层加密：用会话密钥加密一段明文，返回带随机 nonce 的 Envelope。
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Envelope, Box<dyn std::error::Error>> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));

    // ChaCha20-Poly1305 的 nonce 是 12 字节；必须每条消息重新随机生成，
    // 否则同一密钥下 nonce 复用会彻底破坏安全性。
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // encrypt 的返回值 = 密文 + 认证标签（AEAD 标签就在密文末尾）。
    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    Ok(Envelope {
        // JSON 里放二进制不太合适，这里用 base64 把字节编码成字符串。
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
}

/// 底层解密：验证 AEAD 标签并解出明文。
/// 任何篡改都会在这里返回 `Err`（这正是"包完整校验机制"的体现）。
pub fn decrypt(key: &[u8; 32], env: &Envelope) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&env.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&env.ciphertext)?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    // decrypt 会先验签再解，失败说明数据被篡改或密钥不对。
    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())?;
    Ok(plaintext)
}
