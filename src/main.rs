//! peerchat —— 一个用于学习的 P2P 聊天 + 文件传输程序。
//!
//! # 一句话理解本程序
//! 想象局域网里有两台电脑，想互相聊天、互传文件，但**没有中心服务器**。
//! 每个程序实例就是一个"节点"（peer / node）。程序启动后自动发现局域网里的
//! 其他节点（用 mDNS），跟它们建立连接，然后就能收发聊天消息和文件了。
//!
//! # 只需要这点网络知识就能看懂
//! - **IP / 端口**：网络地址，例如 `192.168.1.5:8080`。
//! - **TCP 连接**：两台电脑之间一条可靠的、双向的"管道"（字节流）。
//! - **协议**：双方约定好的通信规则。每条协议有一个协议 ID（protocol ID）。
//! - **多路复用**：一条物理连接里同时跑多条"逻辑通道"（libp2p 里叫子流/stream）。
//!
//! # libp2p 的关键概念（对应代码里的结构）
//! 1. **PeerId（节点身份）**：唯一 ID，由节点的密钥对（ed25519）派生而来。
//!    本程序把密钥对持久化到 config.json，因此**重启后 ID 不变**。
//! 2. **Transport（传输层）**：本程序 = TCP + DNS + Noise + Yamux。
//! 3. **Behaviour（行为层）**：ping(心跳)、mdns(发现)、key(密钥协商)、chat(聊天)、file(文件)。
//! 4. **Swarm（蜂群）**：把 Transport 和 Behaviour 拼装起来的"总指挥"。
//! 5. **事件循环**：主循环用 `tokio::select!` 同时等网络事件 / 键盘 / 退出信号。
//!
//! # 双层加密
//! - **第一层**：libp2p 的 Noise 加密（传输层）。
//! - **第二层**：我们自己的应用层加密（crypto.rs）：X25519 公钥交换 -> ECDH ->
//!   HKDF 派生会话密钥 -> ChaCha20-Poly1305 对称加密聊天/文件。
//!
//! # 用法
//! ```text
//! peerchat --nick 小明                 # 用昵称"小明"启动（会被存入 config.json）
//! peerchat --duration 30               # 30 秒后自动退出（自动化测试用）
//! peerchat --no-tui                    # 强制纯文本模式
//! # 外网（跨局域网）支持：
//! peerchat --dht --bootstrap /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...   # 经 DHT 引导站点发现节点
//! peerchat --dial /ip4/9.9.9.9/tcp/5000/p2p/12D3KooW...             # 直接拨号连接已知对端
//! ```
//! 交互终端下自动进入 TUI：
//! - **左侧窗口**：联系人列表（昵称/ID/在线状态/未读条数）。↑↓ 选择、回车进入对话
//!   （或鼠标点击）。
//! - **聊天页**：当前选中的联系人对话。打字回车发送；滚轮/↑↓ 滚动历史；
//!   点击邀请行左半=接受、右半=拒绝文件。
//! - **纯文本模式**：直接输入文字 = 群发；`send <路径>` = 发送文件。
//!
//! # 外网（跨局域网）是怎么通的？
//! - **本地**：mDNS 自动发现同网段节点（第一层，零配置）。
//! - **DHT（--dht + --bootstrap）**：节点加入 Kademlia 分布式哈希表（自定义协议
//!   `/peerchat/kad/1.0.0`，不接入 IPFS 公共 DHT）。每个节点在 DHT 上"宣告自己在线"，
//!   并通过周期性 `get_providers` 发现其他节点，发现后自动拨号直连。
//! - **直连（--dial）**：若已知对端完整 multiaddr（含 `/p2p/<id>`），可直接拨号，
//!   适合没有公共引导站点时的点对点外网连接。

mod chat;
mod config;
mod crypto;
mod file_transfer;
mod protocol;
mod tui;

use crate::chat::{ChatAck, ChatMsg, ChatRecord};
use crate::crypto::{decrypt_json, encrypt_json, AppCrypto};
use crate::file_transfer::{FileResp, OutboundReq};
use crate::protocol::{CHAT_PROTOCOL, Envelope, FILE_PROTOCOL, KEY_PROTOCOL, KeyHello};
use futures::prelude::*; // 提供 Stream 扩展方法（swarm.select_next_some() 需要它）
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::kad::{self, store::MemoryStore, Behaviour as Kademlia, Config as KadConfig, QueryResult, RecordKey};
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, StreamProtocol, Swarm, SwarmEvent};
use libp2p::{mdns, ping, PeerId, Transport};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::io::IsTerminal;
use std::time::Duration;

// ===== 混合行为（NetworkBehaviour） =====
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "MyBehaviourEvent")]
struct MyBehaviour {
    ping: ping::Behaviour,
    mdns: mdns::tokio::Behaviour,
    key: request_response::json::Behaviour<KeyHello, KeyHello>,
    chat: request_response::json::Behaviour<Envelope, ChatAck>,
    file: request_response::json::Behaviour<Envelope, FileResp>,
    /// Kademlia DHT：用于跨局域网（外网）发现对等节点。
    /// 自定义协议名，避免接入到 IPFS 的公共 DHT。
    kad: Kademlia<MemoryStore>,
}

/// 各行为的对外事件汇总。
#[derive(Debug)]
enum MyBehaviourEvent {
    Ping(ping::Event),
    Mdns(mdns::Event),
    Key(request_response::Event<KeyHello, KeyHello>),
    Chat(request_response::Event<Envelope, ChatAck>),
    File(request_response::Event<Envelope, FileResp>),
    Kad(kad::Event),
}

impl From<ping::Event> for MyBehaviourEvent {
    fn from(e: ping::Event) -> Self {
        MyBehaviourEvent::Ping(e)
    }
}
impl From<mdns::Event> for MyBehaviourEvent {
    fn from(e: mdns::Event) -> Self {
        MyBehaviourEvent::Mdns(e)
    }
}
impl From<request_response::Event<KeyHello, KeyHello>> for MyBehaviourEvent {
    fn from(e: request_response::Event<KeyHello, KeyHello>) -> Self {
        MyBehaviourEvent::Key(e)
    }
}
impl From<request_response::Event<Envelope, ChatAck>> for MyBehaviourEvent {
    fn from(e: request_response::Event<Envelope, ChatAck>) -> Self {
        MyBehaviourEvent::Chat(e)
    }
}
impl From<request_response::Event<Envelope, FileResp>> for MyBehaviourEvent {
    fn from(e: request_response::Event<Envelope, FileResp>) -> Self {
        MyBehaviourEvent::File(e)
    }
}
impl From<kad::Event> for MyBehaviourEvent {
    fn from(e: kad::Event) -> Self {
        MyBehaviourEvent::Kad(e)
    }
}

// ===== 一位联系人的信息（左侧窗口显示 + 聊天记录） =====
#[derive(Debug, Clone)]
struct PeerInfo {
    /// 对方昵称（密钥协商或收到的消息里得知）。
    nickname: String,
    /// 是否在线（有活跃连接）。
    online: bool,
    /// 未读消息条数（左侧红色显示）。
    unread: u32,
    /// 与这位联系人的聊天记录（会持久化到 conversations/<id>.json）。
    records: Vec<ChatRecord>,
    /// 最近知道的地址（用于展示 IP）。
    last_addr: Option<String>,
}

// ===== 应用状态 =====
struct AppState {
    /// 应用层加密器（第二层加密用）。
    crypto: AppCrypto,
    /// 本节点昵称。
    nickname: String,
    /// 是否启用 TUI。
    tui_enabled: bool,
    /// 是否启用 DHT（外网发现）。可由 --dht/--bootstrap 启动，也可在 TUI「+加好友」时开启。
    dht_enabled: bool,
    /// 本节点自己的 PeerId（用于展示与分享）。
    local_peer_id: PeerId,
    /// 本节点的监听地址（已拼上 /p2p/<id>），可直接发给好友做「直连」。
    listen_addrs: Vec<String>,
    /// DHT 路由表中的节点数（仅作展示；预留字段，当前未在 UI 显示）。
    #[allow(dead_code)]
    dht_routing_peers: usize,
    /// 已建立连接的节点集合（用于在线判定与文件广播目标）。
    connected: HashSet<PeerId>,
    /// 已与对端协商好的应用层会话密钥。
    sessions: HashMap<PeerId, [u8; 32]>,
    /// 联系人表：PeerId -> 信息（含每条聊天记录，持久化）。
    peers: HashMap<PeerId, PeerInfo>,
    /// 当前正在对话（选中的）联系人；None = 还没选。
    selected_peer: Option<PeerId>,
    /// 系统日志（TUI 日志页；headless 模式打印到 stdout）。
    logs: VecDeque<String>,
    /// 聊天消息 ID 自增器。
    next_msg_id: u64,
    /// 文件传输 ID 自增器。
    next_file_id: u64,
    /// 时间戳自增器（只用于记录排序）。
    next_ts: u64,
    /// 发送端进行中的文件传输。
    outgoing_files: HashMap<u64, file_transfer::OutgoingTransfer>,
    /// 接收端正在接收的文件。
    incoming_files: HashMap<u64, file_transfer::IncomingTransfer>,
    /// 待决定的文件接收邀请（对方发来的，等我点[接受]）。
    pending_offers: HashMap<PeerId, Vec<file_transfer::PendingOffer>>,
    /// 已发出的文件协议请求 -> (文件ID, 请求类型)。
    file_outstanding: HashMap<OutboundRequestId, (u64, OutboundReq)>,
    /// 待确认的聊天消息：request_id -> (目标节点, 消息内容, 已重试次数)。
    /// 收到 ACK 则移除；超时/失败则自动重传，最多 3 次。
    pending_chat_msgs: HashMap<OutboundRequestId, (PeerId, ChatMsg, u32)>,
    /// 标记哪些对话有未持久化的改动（延迟批量写入用，避免每条消息全量写盘）。
    dirty_conversations: HashSet<PeerId>,
}

impl AppState {
    fn new(
        crypto: AppCrypto,
        nickname: String,
        tui_enabled: bool,
        local_peer_id: PeerId,
        known_peers: Vec<PeerId>,
    ) -> Self {
        // 启动时从 conversations/ 目录恢复已知联系人（当前都算离线）
        let mut peers = HashMap::new();
        for pid in known_peers {
            let cf = config::load_conversation(&pid);
            peers.insert(
                pid,
                PeerInfo {
                    nickname: cf.nickname,
                    online: false,
                    unread: 0,
                    records: cf.records,
                    last_addr: cf.last_addr,
                },
            );
        }
        Self {
            crypto,
            nickname,
            tui_enabled,
            dht_enabled: false,
            local_peer_id,
            listen_addrs: Vec::new(),
            dht_routing_peers: 0,
            connected: HashSet::new(),
            sessions: HashMap::new(),
            peers,
            selected_peer: None,
            logs: VecDeque::with_capacity(2000),
            next_msg_id: 1,
            next_file_id: 1,
            next_ts: 1,
            outgoing_files: HashMap::new(),
            incoming_files: HashMap::new(),
            pending_offers: HashMap::new(),
            file_outstanding: HashMap::new(),
            pending_chat_msgs: HashMap::new(),
            dirty_conversations: HashSet::new(),
        }
    }

    /// 产生一个新的、递增的时间戳（用于聊天记录排序）。
    fn tick_ts(&mut self) -> u64 {
        let t = self.next_ts;
        self.next_ts += 1;
        t
    }

    /// 记录一条系统日志（headless 打印，TUI 进日志页）。
    fn log(&mut self, line: String) {
        if self.tui_enabled {
            self.logs.push_back(line);
            self.logs.truncate(2000);
        } else {
            println!("{line}");
        }
    }

    /// 拿到某联系人的可变引用（没有就建一个新的）。
    fn peer_or_insert(&mut self, peer: PeerId) -> &mut PeerInfo {
        self.peers.entry(peer).or_insert(PeerInfo {
            nickname: String::new(),
            online: false,
            unread: 0,
            records: Vec::new(),
            last_addr: None,
        })
    }

    /// 把一条记录写进与某联系人的聊天历史，并标记为待持久化（延迟批量写入）。
    /// - inbound 且不是当前对话窗口 => 未读数 +1；
    /// - 始终把未读清零交给"选中该联系人"时处理。
    fn record_to_peer(&mut self, peer: PeerId, record: ChatRecord) {
        let is_msg = record.kind == "text";
        let inbound = !record.outbound;
        let bump_unread = is_msg && inbound && self.selected_peer != Some(peer);
        let info = self.peer_or_insert(peer);
        info.records.push(record.clone());
        info.records.truncate(2000);
        if bump_unread {
            info.unread = info.unread.saturating_add(1);
        }
        // 标记为脏，由定时 flush_conversations 批量写盘（避免每条消息全量写 JSON）
        self.dirty_conversations.insert(peer);
    }

    /// 把所有标记为脏的对话持久化到磁盘（批量写入，提升性能）。
    fn flush_conversations(&mut self) {
        let dirty: Vec<PeerId> = self.dirty_conversations.drain().collect();
        for peer in dirty {
            if let Some(info) = self.peers.get(&peer) {
                let conv = config::ConversationFile {
                    peer_id: peer.to_string(),
                    nickname: info.nickname.clone(),
                    last_addr: info.last_addr.clone(),
                    records: info.records.clone(),
                };
                config::save_conversation(&conv);
            }
        }
    }

    /// 设置昵称（写入 config.json，并在日志/相应记录里反映）。
    fn set_nickname(&mut self, new: String) {
        self.nickname = new.clone();
        config::save_nickname(&new);
        self.log(format!("[系统] 昵称已改为：{new}"));
    }

    /// 选中一个联系人开始对话：切换窗口并清零其未读。
    fn select_peer(&mut self, peer: PeerId) {
        self.selected_peer = Some(peer);
        if let Some(info) = self.peers.get_mut(&peer) {
            info.unread = 0;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ===== 1. 解析命令行参数 =====
    let cli = parse_args();
    let nickname_arg = cli.nickname.clone();
    let duration = cli.duration;
    let no_tui = cli.no_tui;

    // DHT（外网发现）在显式 --dht 或提供了 --bootstrap 时启用
    let mut dht_enabled = cli.dht || !cli.bootstrap.is_empty();

    // 判断是否启用 TUI
    let tui_enabled = !no_tui && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

    // ===== 2. 加载/生成持久化配置（昵称 + 持久密钥对 + 应用层密钥）=====
    // 有密钥对 => PeerId 稳定；重启后还是同一个人。
    // 应用层密钥也持久化 => 重启后第二层加密身份不变。
    let (cfg, id_keys, app_crypto) = config::load_or_create_config(nickname_arg);
    let nickname = cfg.nickname;
    let peer_id = PeerId::from(id_keys.public());

    // 启动时恢复已知联系人
    let known_peers = config::list_known_peers();
    let mut state = AppState::new(app_crypto, nickname.clone(), tui_enabled, peer_id, known_peers);
    state.log(format!("[启动] 昵称: {nickname}, PeerID: {peer_id}"));
    state.log(format!("[启动] 配置已保存到 config.json；聊天记录保存到 conversations/"));
    state.log(format!("[启动] 应用层 X25519 公钥: {}", hex::encode(state.crypto.pubkey)));

    // ===== 3. 构建传输层 =====
    let transport = libp2p::dns::tokio::Transport::system(
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true)),
    )?
    .upgrade(libp2p::core::upgrade::Version::V1)
    .authenticate(libp2p::noise::Config::new(&id_keys).unwrap())
    .multiplex(libp2p::yamux::Config::default())
    .boxed();

    // ===== 4. 组装行为层 =====
    // Kademlia DHT（应用层发现用，自定义协议避免接入 IPFS 公共 DHT）
    let kad_store = MemoryStore::new(peer_id);
    let mut kad_config = KadConfig::default();
    kad_config.set_protocol_names(vec![StreamProtocol::new("/peerchat/kad/1.0.0")]);
    let kad = Kademlia::with_config(peer_id, kad_store, kad_config);
    let behaviour = MyBehaviour {
        ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(5))),
        mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?,
        key: request_response::json::Behaviour::new(
            [(StreamProtocol::new(KEY_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        chat: request_response::json::Behaviour::new(
            [(StreamProtocol::new(CHAT_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        file: request_response::json::Behaviour::new(
            [(StreamProtocol::new(FILE_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        kad,
    };

    // ===== 5. 创建 Swarm =====
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(15 * 60)),
    );
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    state.log("[等待] 正在扫描局域网内的其他 P2P 节点…".to_string());

    // ===== 6. 外网部分：DHT 引导 + 直连拨号 =====
    // 合并命令行参数与已持久化（TUI「+加好友」添加）的好友/引导站点
    let bootstrap_list: Vec<String> = cli
        .bootstrap
        .iter()
        .cloned()
        .chain(cfg.bootstrap_nodes.iter().cloned())
        .collect();
    let dial_list: Vec<String> = cli
        .dial
        .iter()
        .cloned()
        .chain(cfg.friends.iter().cloned())
        .collect();
    if !bootstrap_list.is_empty() {
        dht_enabled = true;
    }
    state.dht_enabled = dht_enabled;

    if dht_enabled {
        let mut bootstrapped = false;
        for b in &bootstrap_list {
            match b.parse::<Multiaddr>() {
                Ok(ma) => match split_p2p(ma) {
                    Some((pid, addr)) => {
                        swarm.behaviour_mut().kad.add_address(&pid, addr);
                        bootstrapped = true;
                    }
                    None => state.log(format!("[DHT] 引导地址缺少 /p2p/<id>，已跳过：{b}")),
                },
                Err(e) => state.log(format!("[DHT] 引导地址解析失败 {b}：{e}")),
            }
        }
        if bootstrapped {
            match swarm.behaviour_mut().kad.bootstrap() {
                Ok(_) => state.log("[DHT] 已向引导站点发起 bootstrap，正在加入分布式哈希表…".to_string()),
                Err(e) => state.log(format!("[DHT] bootstrap 失败：{e}")),
            }
        } else {
            state.log("[DHT] 未提供可用的引导站点，DHT 仅作为被动节点（可由他人发现）".to_string());
        }
        // 在 DHT 上宣告自己在线，使他人可用同一 key 发现本节点
        if let Err(e) = swarm.behaviour_mut().kad.start_providing(dht_record_key()) {
            state.log(format!("[DHT] 宣告在线失败：{e}"));
        } else {
            state.log("[DHT] 已在 DHT 上宣告自己在线（供他人发现）".to_string());
        }
        // 立刻查一次在线节点
        let _ = swarm.behaviour_mut().kad.get_providers(dht_record_key());
    }
    // 直连：直接拨号到指定 multiaddr（适合已知对端地址的外网连接）
    for d in &dial_list {
        match d.parse::<Multiaddr>() {
            Ok(ma) => match swarm.dial(ma) {
                Ok(_) => state.log(format!("[直连] 正在连接：{d}")),
                Err(e) => state.log(format!("[直连] 拨号失败 {d}：{e}")),
            },
            Err(e) => state.log(format!("[直连] 地址解析失败 {d}：{e}")),
        }
    }

    // ===== 7. TUI 初始化 =====
    let mut ui = tui::UiState::default();
    let mut terminal: Option<ratatui::DefaultTerminal> = None;
    if state.tui_enabled {
        terminal = Some(ratatui::init());
        ratatui::crossterm::execute!(
            std::io::stdout(),
            ratatui::crossterm::event::EnableMouseCapture
        )?;
        tui::refresh_file_list(&mut ui);
    }

    // ===== 8. 后台读取 stdin（仅 headless 模式）=====
    let mut stdin_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>> = None;
    if !state.tui_enabled {
        let (stdin_tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            use std::io::BufRead;
            loop {
                for line in std::io::stdin().lock().lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    if stdin_tx.send(line).is_err() {
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        stdin_rx = Some(rx);
    }

    // ===== 9. 优雅退出机制 =====
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
    let default_duration = Duration::from_secs(365 * 24 * 3600);
    let mut exit_timer = Box::pin(tokio::time::sleep(
        duration.map(Duration::from_secs).unwrap_or(default_duration),
    ));
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    // 聊天记录延迟批量写入：每 3 秒把有改动的对话批量写盘，避免每条消息全量写 JSON
    let mut save_timer = tokio::time::interval(Duration::from_secs(3));
    // DHT 定时刷新：周期性地向 DHT 查询在线节点，维持路由表与发现能力
    let mut dht_timer = tokio::time::interval(Duration::from_secs(20));

    // ===== 10. 主事件循环 =====
    let mut quit = false;
    loop {
        if let Some(term) = terminal.as_mut() {
            // 1) 处理这一时刻攒下的所有按键/鼠标事件
            let cmds = tui::poll_keys(&mut ui, &mut state);
            for cmd in cmds {
                match cmd {
                    tui::UiCmd::SendChat(text) => {
                        send_chat(&mut swarm, &mut state, &text);
                        file_transfer::drive_outgoing(&mut swarm, &mut state);
                    }
                    tui::UiCmd::SendFile(path) => {
                        file_transfer::start_file_send(&mut swarm, &mut state, &path);
                    }
                    tui::UiCmd::SelectPeer(peer) => {
                        state.select_peer(peer);
                    }
                    tui::UiCmd::AcceptFile(peer, file_id) => {
                        file_transfer::accept_file(&mut swarm, &mut state, peer, file_id);
                    }
                    tui::UiCmd::RejectFile(peer, file_id) => {
                        file_transfer::reject_file(&mut swarm, &mut state, peer, file_id);
                    }
                    tui::UiCmd::SetNickname(n) => state.set_nickname(n),
                    tui::UiCmd::ShowMyAddr => {
                        state.log(format!("[我的信息] PeerId: {}", state.local_peer_id));
                        if state.listen_addrs.is_empty() {
                            state.log("[我的信息] 尚未获取到监听地址（可能还在初始化）".to_string());
                            tui::set_toast(&format!("ID: {}", &state.local_peer_id.to_string()[..8]));
                        } else {
                            let addrs: Vec<String> = state.listen_addrs.clone();
                            for addr in &addrs {
                                state.log(format!("[我的信息] 监听地址: {addr}"));
                            }
                            let first = &addrs[0];
                            tui::set_toast(&format!("地址已显示在日志页: {}", &first[..first.len().min(40)]));
                        }
                    }
                    tui::UiCmd::AddFriend { addr, bootstrap } => {
                        add_friend(&mut swarm, &mut state, &addr, bootstrap);
                    }
                    tui::UiCmd::PickFile => {
                        // 弹出系统文件选择对话框（跨平台原生）；直接调用即可，
                        // 它是独立的 OS 窗口，不影响终端 raw 模式。
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            let p = path.to_string_lossy().to_string();
                            file_transfer::start_file_send(&mut swarm, &mut state, &p);
                            tui::set_toast(&format!("已选择文件：{p}"));
                        }
                    }
                    tui::UiCmd::Quit => {
                        state.log("[退出] 收到退出指令，正在优雅退出…".to_string());
                        quit = true;
                    }
                }
            }
            if quit {
                break;
            }
            // 2) 重绘
            let _ = term.draw(|f| tui::draw(f, &state, &mut ui));
        }

        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, &mut state, event);
                file_transfer::drive_outgoing(&mut swarm, &mut state);
            }
            cmd = async {
                match stdin_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => match cmd {
                Some(line) => {
                    handle_cmd(&mut swarm, &mut state, &line);
                    file_transfer::drive_outgoing(&mut swarm, &mut state);
                }
                None => break,
            },
            _ = &mut ctrl_c => {
                state.log("\n[退出] 收到 Ctrl+C，正在优雅退出…".to_string());
                break;
            }
            _ = &mut exit_timer => {
                state.log("\n[退出] 运行时长已到，自动退出（--duration 主要用于测试）".to_string());
                break;
            }
            _ = ticker.tick() => {}
            _ = save_timer.tick() => {
                state.flush_conversations();
            }
            _ = dht_timer.tick() => {
                if state.dht_enabled {
                    // 周期性查询 DHT 上的在线节点，并刷新路由表
                    let _ = swarm.behaviour_mut().kad.get_providers(dht_record_key());
                }
            }
        }
    }

    // 退出前强制把所有未持久化的聊天记录写盘
    state.flush_conversations();

    // 退出 TUI：恢复终端原状
    if let Some(term) = terminal.as_mut() {
        let _ = ratatui::crossterm::execute!(
            std::io::stdout(),
            ratatui::crossterm::event::DisableMouseCapture
        );
        let _ = term.clear();
        ratatui::restore();
    }

    println!("[退出] 再见！{nickname}");
    Ok(())
}

/// 命令行参数。
struct CliArgs {
    /// `--nick <昵称>`
    nickname: Option<String>,
    /// `--duration <秒>`：到时自动退出（测试用）。
    duration: Option<u64>,
    /// `--no-tui`：强制纯文本模式。
    no_tui: bool,
    /// `--dht`：启用 Kademlia DHT（外网发现）。
    dht: bool,
    /// `--bootstrap <multiaddr>`（可重复）：DHT 引导站点，须带 `/p2p/<id>`。
    bootstrap: Vec<String>,
    /// `--dial <multiaddr>`（可重复）：直接拨号连接指定节点（外网直连）。
    dial: Vec<String>,
}

/// 解析命令行参数。
fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut cli = CliArgs {
        nickname: None,
        duration: None,
        no_tui: false,
        dht: false,
        bootstrap: Vec::new(),
        dial: Vec::new(),
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--nick" => {
                if i + 1 < args.len() {
                    cli.nickname = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--duration" => {
                if i + 1 < args.len() {
                    cli.duration = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--no-tui" => {
                cli.no_tui = true;
                i += 1;
            }
            "--dht" => {
                cli.dht = true;
                i += 1;
            }
            "--bootstrap" => {
                if i + 1 < args.len() {
                    cli.bootstrap.push(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--dial" => {
                if i + 1 < args.len() {
                    cli.dial.push(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    cli
}

/// 发送一条聊天消息。TUI 模式下发给当前选中的联系人；headless 模式群发给所有已协商节点。
fn send_chat(swarm: &mut Swarm<MyBehaviour>, state: &mut AppState, text: &str) {
    let msg_id = state.next_msg_id;
    state.next_msg_id += 1;
    let msg = ChatMsg {
        msg_id,
        nickname: state.nickname.clone(),
        text: text.to_string(),
    };

    // 决定发给谁
    let targets: Vec<PeerId> = if state.tui_enabled {
        match state.selected_peer {
            Some(p) => vec![p],
            None => {
                state.log("[聊天] 请先在左侧选择一个联系人".to_string());
                return;
            }
        }
    } else {
        state.sessions.keys().copied().collect()
    };

    let ts = state.tick_ts();
    if targets.is_empty() {
        state.log("[聊天] 还没有任何可发送的对象（尚未发现/协商完成）".to_string());
        return;
    }
    for peer in targets {
        let Some(key) = state.sessions.get(&peer).copied() else {
            continue;
        };
        match encrypt_json(&key, &msg) {
            Ok(env) => {
                let req_id = swarm.behaviour_mut().chat.send_request(&peer, env);
                // 记录待确认消息，用于超时/失败后自动重传
                state.pending_chat_msgs.insert(req_id, (peer, msg.clone(), 0));
                // 自己的消息也存进本地聊天记录（绿色显示）
                state.record_to_peer(
                    peer,
                    ChatRecord::text(true, &state.nickname, text, ts),
                );
            }
            Err(e) => state.log(format!("[聊天] 加密失败: {e}")),
        }
    }
}

/// headless 命令分发。
fn handle_cmd(swarm: &mut Swarm<MyBehaviour>, state: &mut AppState, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    if let Some(path) = line.strip_prefix("send ") {
        file_transfer::start_file_send(swarm, state, path.trim());
    } else if line == "help" {
        state.log("直接输入=群发聊天；`send <路径>`=发文件；`nick <名称>`=改名；Ctrl+C=退出".to_string());
    } else if let Some(n) = line.strip_prefix("nick ") {
        state.set_nickname(n.trim().to_string());
    } else if line.starts_with('/') {
        state.log("[提示] 未知命令，输入 help 查看帮助".to_string());
    } else {
        send_chat(swarm, state, line);
    }
}

/// 显示对端的名字（优先昵称，否则 PeerID 简写）。
fn display_name(state: &AppState, peer: &PeerId) -> String {
    state
        .peers
        .get(peer)
        .and_then(|p| if p.nickname.is_empty() { None } else { Some(p.nickname.clone()) })
        .unwrap_or_else(|| peer.to_string())
}

/// 处理一条 Swarm 网络事件。
fn handle_swarm_event(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    event: SwarmEvent<MyBehaviourEvent>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            // 记录带 /p2p/<id> 的完整地址，可直接发给好友做直连
            let addr_with_id = format!("{}/p2p/{}", address, state.local_peer_id);
            state.listen_addrs.push(addr_with_id.clone());
            state.log(format!("[监听] 正在地址: {addr_with_id} 等待连接"));
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } => {
            if state.connected.insert(peer_id) {
                // 记录地址供左侧展示（endpoint 是 ConnectedPoint）
                let info = state.peer_or_insert(peer_id);
                info.online = true;
                let sent_addr = match &endpoint {
                    libp2p::core::ConnectedPoint::Dialer { address, .. } => Some(format!("{address}")),
                    libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                        Some(format!("{send_back_addr}"))
                    }
                };
                if let Some(a) = sent_addr {
                    info.last_addr = Some(a);
                }
                let addr_str = info.last_addr.clone().unwrap_or_else(|| "未知IP".into());
                state.log(format!("[成功] 已与节点 {peer_id} 建立连接（{addr_str}）"));
                let hello = KeyHello {
                    nickname: state.nickname.clone(),
                    pubkey: state.crypto.pubkey,
                };
                swarm.behaviour_mut().key.send_request(&peer_id, hello);
            }
            let _ = num_established;
        }
        SwarmEvent::ConnectionClosed { peer_id, num_established, cause, .. } => {
            state.connected.remove(&peer_id);
            state.sessions.remove(&peer_id);
            if num_established == 0 {
                if let Some(info) = state.peers.get_mut(&peer_id) {
                    info.online = false;
                }
                state.log(format!("[断开] 节点 {} 已断开（原因: {:?}）", display_name(state, &peer_id), cause));
                let ts = state.tick_ts();
                state.record_to_peer(
                    peer_id,
                    ChatRecord::system("[离线] 对方已下线", ts),
                );
                // 把它相关的传输全部标为失败
                file_transfer::on_peer_disconnect(state, peer_id);
            }
        }
        SwarmEvent::Behaviour(ev) => match ev {
            MyBehaviourEvent::Ping(ping::Event { peer, result, .. }) => {
                match result {
                    Ok(rtt) => state.log(format!(
                        "[心跳] 节点 {} 在线（RTT = {:?}）",
                        display_name(state, &peer),
                        rtt
                    )),
                    Err(e) => state.log(format!("[心跳] 节点 {} 心跳失败: {e}", display_name(state, &peer))),
                }
            }
            MyBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer, addr) in list {
                    if !state.connected.contains(&peer) {
                        state.log(format!("[发现] mDNS 发现节点: {} @ {addr}", display_name(state, &peer)));
                        // 记录地址
                        let info = state.peer_or_insert(peer);
                        info.last_addr = Some(format!("{addr}"));
                        if let Err(e) = swarm.dial(addr.clone()) {
                            state.log(format!("[发现] 拨号 {addr} 失败: {e}"));
                        }
                    }
                }
            }
            MyBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer, _addr) in list {
                    state.log(format!("[发现] 节点 {} 的 mDNS 记录已过期", display_name(state, &peer)));
                }
            }
            MyBehaviourEvent::Key(ev) => handle_key_event(swarm, state, ev),
            MyBehaviourEvent::Chat(ev) => handle_chat_event(swarm, state, ev),
            MyBehaviourEvent::File(ev) => handle_file_event(swarm, state, ev),
            MyBehaviourEvent::Kad(ev) => handle_kad_event(swarm, state, ev),
        },
        _ => {}
    }
}

/// 处理密钥协商事件。
fn handle_key_event(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    ev: request_response::Event<KeyHello, KeyHello>,
) {
    match ev {
        request_response::Event::Message {
            peer,
            message: request_response::Message::Request { request, channel, .. },
        } => {
            let key = state.crypto.derive_session_key(&request.pubkey);
            let nickname = request.nickname.clone();
            let is_new = state.sessions.insert(peer, key).is_none();
            let info = state.peer_or_insert(peer);
            info.nickname = nickname.clone();
            if is_new {
                let ts = state.tick_ts();
                let sys_text = format!("[在线] {nickname} 上线");
                state.record_to_peer(peer, ChatRecord::system(&sys_text, ts));
            }
            let hello = KeyHello {
                nickname: state.nickname.clone(),
                pubkey: state.crypto.pubkey,
            };
            let _ = swarm.behaviour_mut().key.send_response(channel, hello);
        }
        request_response::Event::Message {
            peer,
            message: request_response::Message::Response { response, .. },
        } => {
            let key = state.crypto.derive_session_key(&response.pubkey);
            let nickname = response.nickname.clone();
            let is_new = state.sessions.insert(peer, key).is_none();
            let info = state.peer_or_insert(peer);
            info.nickname = nickname.clone();
            if is_new {
                let ts = state.tick_ts();
                let sys_text = format!("[在线] {nickname} 上线");
                state.record_to_peer(peer, ChatRecord::system(&sys_text, ts));
            }
        }
        request_response::Event::OutboundFailure { peer, request_id, error } => {
            state.log(format!("[密钥] 与 {peer} 的协商请求失败: {error:?} (id={request_id:?})"));
        }
        _ => {}
    }
}

/// 处理聊天事件：收到消息（回 ACK）与收到 ACK。
fn handle_chat_event(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    ev: request_response::Event<Envelope, ChatAck>,
) {
    match ev {
        request_response::Event::Message {
            peer,
            message: request_response::Message::Request { request, channel, .. },
        } => {
            let ack = match state.sessions.get(&peer).copied() {
                Some(key) => match decrypt_json::<ChatMsg>(&key, &request) {
                    Ok(msg) => {
                        let ts = state.tick_ts();
                        state.record_to_peer(
                            peer,
                            ChatRecord::text(false, &msg.nickname, &msg.text, ts),
                        );
                        ChatAck { msg_id: msg.msg_id, ok: true }
                    }
                    Err(e) => {
                        state.log(format!("[聊天] 来自 {peer} 的消息解密/校验失败: {e}"));
                        ChatAck { msg_id: 0, ok: false }
                    }
                },
                None => {
                    state.log(format!("[聊天] 收到 {peer} 的消息，但尚未完成密钥协商，无法解密"));
                    ChatAck { msg_id: 0, ok: false }
                }
            };
            let _ = swarm.behaviour_mut().chat.send_response(channel, ack);
        }
        request_response::Event::Message {
            peer,
            message: request_response::Message::Response { request_id, response },
        } => {
            // 收到 ACK -> 从待确认表移除
            state.pending_chat_msgs.remove(&request_id);
            if response.ok {
                state.log(format!("[聊天] 消息 #{} 已送达确认(ACK)", response.msg_id));
                tui::set_toast("✓ 消息已送达");
            } else {
                state.log(format!("[聊天] 消息 #{} 对方未能正确收到", response.msg_id));
                tui::set_toast("✗ 消息发送失败（对方未能收到）");
            }
            let _ = peer;
        }
        request_response::Event::OutboundFailure { peer, request_id, error } => {
            // 发送失败/超时 -> 自动重传，最多 3 次
            if let Some((_, msg, retries)) = state.pending_chat_msgs.remove(&request_id) {
                if retries < 3 {
                    state.log(format!(
                        "[聊天] 消息 #{} 发送失败({:?})，第{}次重传…",
                        msg.msg_id, error, retries + 1
                    ));
                    tui::set_toast(&format!("↻ 消息重传中({}/3)", retries + 1));
                    if let Some(key) = state.sessions.get(&peer).copied() {
                        if let Ok(env) = encrypt_json(&key, &msg) {
                            let new_id = swarm.behaviour_mut().chat.send_request(&peer, env);
                            state.pending_chat_msgs.insert(new_id, (peer, msg, retries + 1));
                        }
                    }
                } else {
                    state.log(format!("[聊天] 消息 #{} 重试3次仍失败，放弃", msg.msg_id));
                    tui::set_toast("✗ 消息发送失败（已重试3次）");
                    let ts = state.tick_ts();
                    state.record_to_peer(
                        peer,
                        ChatRecord::system(&format!("[系统] 消息「{}」发送失败", msg.text), ts),
                    );
                }
            } else {
                state.log(format!("[聊天] 发送给 {peer} 失败: {error:?} (id={request_id:?})"));
            }
        }
        _ => {}
    }
}

/// 处理文件事件：分发到文件模块。
fn handle_file_event(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    ev: request_response::Event<Envelope, FileResp>,
) {
    match ev {
        request_response::Event::Message {
            peer,
            message: request_response::Message::Request { request, channel, .. },
        } => file_transfer::on_file_request(swarm, state, peer, request, channel),
        request_response::Event::Message {
            peer: _,
            message: request_response::Message::Response { request_id, response },
        } => file_transfer::on_file_response(swarm, state, request_id, response),
        request_response::Event::OutboundFailure { request_id, .. } => {
            file_transfer::on_file_outbound_failure(state, request_id);
        }
        _ => {}
    }
}

/// DHT 上用于"宣告/发现在线节点"的共享记录键。所有 peerchat 节点用同一个键，
/// 互相把对方登记为 provider，从而可通过 `get_providers` 找到彼此。
fn dht_record_key() -> RecordKey {
    RecordKey::new(b"peerchat-discovery-v1")
}

/// 从一个 multiaddr 里拆出末尾的 `/p2p/<id>`，返回 (PeerId, 去掉 p2p 部分的地址)。
/// 引导/直连地址通常形如 `/ip4/x/tcp/y/p2p/<id>`，DHT 需要单独的 PeerId 与地址。
fn split_p2p(ma: Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut ma = ma;
    if let Some(Protocol::P2p(pid)) = ma.pop() {
        return Some((pid, ma));
    }
    None
}

/// 通过 TUI「+加好友」添加好友：直连拨号或加入 DHT 引导站点，并持久化保存。
/// - `bootstrap = false`：当作直连地址，立即拨号，并把对端登记为（离线）联系人。
/// - `bootstrap = true`：当作 DHT 引导站点，运行时加入 DHT（首次会开启 DHT）。
fn add_friend(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    addr: &str,
    bootstrap: bool,
) {
    match addr.parse::<Multiaddr>() {
        Ok(ma) => {
            if bootstrap {
                state.dht_enabled = true;
                match split_p2p(ma) {
                    Some((pid, a)) => {
                        swarm.behaviour_mut().kad.add_address(&pid, a);
                        match swarm.behaviour_mut().kad.bootstrap() {
                            Ok(_) => state.log("[DHT] 已添加引导站点并向 DHT 发起 bootstrap".to_string()),
                            Err(e) => state.log(format!("[DHT] bootstrap 失败：{e}")),
                        }
                        let _ = swarm.behaviour_mut().kad.start_providing(dht_record_key());
                        let _ = swarm.behaviour_mut().kad.get_providers(dht_record_key());
                        config::add_bootstrap_node(addr);
                        state.log("[DHT] 引导站点已保存，重启后自动加入".to_string());
                    }
                    None => state.log("[DHT] 引导地址须带 /p2p/<id>，已跳过".to_string()),
                }
            } else {
                // 直连：若地址带 /p2p/<id>，先把对方登记为联系人（离线，待连接）
                if let Some((pid, _)) = split_p2p(ma.clone()) {
                    let info = state.peer_or_insert(pid);
                    info.last_addr = Some(addr.to_string());
                    config::add_friend(addr);
                    state.log("[好友] 已保存，重启后自动直连".to_string());
                }
                match swarm.dial(ma) {
                    Ok(_) => state.log(format!("[直连] 正在连接：{addr}")),
                    Err(e) => state.log(format!("[直连] 拨号失败 {addr}：{e}")),
                }
            }
        }
        Err(e) => state.log(format!("[加好友] 地址解析失败 {addr}：{e}")),
    }
}

/// 处理 Kademlia DHT 事件：把发现的节点尝试直连，从而打通外网（跨局域网）通信。
fn handle_kad_event(
    swarm: &mut Swarm<MyBehaviour>,
    state: &mut AppState,
    ev: kad::Event,
) {
    match ev {
        // 路由表里新增（或更新）了一个节点：拿到它的已知地址，直接拨号尝试连接
        kad::Event::RoutingUpdated {
            peer,
            is_new_peer,
            addresses,
            ..
        } => {
            if is_new_peer && !state.connected.contains(&peer) {
                state.log(format!("[DHT] 路由表新增节点 {peer}，尝试直连"));
                for addr in addresses.into_vec() {
                    if let Err(e) =
                        swarm.dial(DialOpts::peer_id(peer).addresses(vec![addr]).build())
                    {
                        state.log(format!("[DHT] 拨号 {peer} 失败: {e}"));
                    }
                }
            }
        }
        // 一次 DHT 查询有进展：把发现的 provider / 最近节点也尝试直连
        kad::Event::OutboundQueryProgressed { result, .. } => match result {
            QueryResult::GetProviders(Ok(ok)) => match ok {
                kad::GetProvidersOk::FoundProviders { providers, .. } => {
                    if !providers.is_empty() {
                        state.log(format!("[DHT] 发现 {} 个在线节点（provider）", providers.len()));
                    }
                    for p in providers {
                        if !state.connected.contains(&p) {
                            let _ = swarm.dial(DialOpts::peer_id(p).build());
                        }
                    }
                }
                kad::GetProvidersOk::FinishedWithNoAdditionalRecord { closest_peers } => {
                    for p in closest_peers {
                        if !state.connected.contains(&p) {
                            let _ = swarm.dial(DialOpts::peer_id(p).build());
                        }
                    }
                }
            },
            QueryResult::GetClosestPeers(Ok(ok)) => {
                for p in ok.peers {
                    if !state.connected.contains(&p) {
                        let _ = swarm.dial(DialOpts::peer_id(p).build());
                    }
                }
            }
            _ => {}
        },
        _ => {}
    }
}
