//! TUI 界面模块：左侧联系人 + 右侧内容（聊天 / 文件 / 进度 / 日志 / 已收）。
//!
//! 设计目标：简洁、克制、蓝色调、留白充足，不像传统 IRC 那样密密麻麻。
//! - 顶部：程序名 + 自己的昵称；右上角一个 [ 设置 ] 按钮（点一下就能改昵称）。
//! - 左侧：联系人列表（在线点、昵称、未读徽标、短 ID、IP），选中行蓝底高亮。
//! - 右侧：按标签页展示当前内容。
//! - 底部：平时留白，改名或提示时才有内容。

use crate::AppState;
use crate::chat::ChatRecord;
use crate::file_transfer;
use libp2p::PeerId;
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::sync::OnceLock;
use std::time::Duration;

/// 全局 toast（一次性小提示），用静态锁实现，方便 main 里设置、draw 里取出。
fn toast_cell() -> &'static std::sync::Mutex<Option<String>> {
    static CELL: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();
    CELL.get_or_init(|| std::sync::Mutex::new(None))
}

/// 设置一条 toast 小提示（例如 ACK 送达）。
pub fn set_toast(msg: &str) {
    if let Ok(mut t) = toast_cell().lock() {
        *t = Some(msg.to_string());
    }
}

/// 取出并消费当前 toast（draw 时调用）。
fn take_toast() -> Option<String> {
    toast_cell().lock().ok().and_then(|mut t| t.take())
}

/// 顶部标签页。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Chat,
    Files,
    Progress,
    Log,
    Received,
}

impl Tab {
    pub fn title(&self) -> &'static str {
        match self {
            Tab::Chat => "聊天",
            Tab::Files => "文件",
            Tab::Progress => "进度",
            Tab::Log => "日志",
            Tab::Received => "已收文件",
        }
    }
}

/// 从 TUI 发给主循环的命令。
#[derive(Debug)]
pub enum UiCmd {
    SendChat(String),
    SendFile(String),
    /// 弹出系统文件选择对话框，然后发送所选文件。
    PickFile,
    SelectPeer(PeerId),
    AcceptFile(PeerId, u64),
    RejectFile(PeerId, u64),
    SetNickname(String),
    /// 通过「+加好友」添加一个外网对端。`bootstrap=true` 视为 DHT 引导站点。
    AddFriend { addr: String, bootstrap: bool },
    Quit,
}

/// TUI 的全部可变状态（与 AppState 分离，便于在不碰网络状态下渲染/收键）。
pub struct UiState {
    /// 当前标签页。
    pub tab: Tab,
    /// 左侧联系人选中行。
    pub contact_sel: usize,
    /// 聊天记录滚动量（向上滚的偏移）。
    pub chat_scroll: u16,
    /// 聊天输入框内容。
    pub chat_input: String,
    /// 是否正在编辑昵称（通过 [设置] 按钮进入）。
    pub editing_nick: bool,
    /// 昵称编辑临时输入。
    pub nick_input: String,
    /// 是否正在添加好友（通过「+加好友」按钮进入）。
    pub editing_friend: bool,
    /// 添加好友时的地址临时输入。
    pub friend_input: String,
    /// 添加好友时选择的类型：false=直连，true=DHT 引导。
    pub friend_bootstrap: bool,
    /// 左侧是否聚焦（Esc 在空输入时切换）。
    pub left_focused: bool,
    /// 当前目录文件列表（Files 页用）。
    pub file_list: Vec<String>,
    /// 文件列表选中行。
    pub file_sel: usize,
    /// 稳定排序后的联系人 PeerId（每次绘制刷新，供键盘/鼠标命中）。
    pub contact_ids: Vec<PeerId>,
    /// 每行联系人的命中矩形。
    pub contact_rects: Vec<(Rect, PeerId)>,
    /// 聊天页里"接受/拒绝"文件邀请行的命中矩形（含对端+文件ID）。
    pub offer_rects: Vec<(Rect, PeerId, u64)>,
    /// 顶部标签页标题的命中矩形。
    pub tab_rects: Vec<(Rect, Tab)>,
    /// 聊天输入框的命中矩形（鼠标点击聚焦）。
    pub chat_input_rect: Rect,
    /// 右上角 [设置] 按钮的命中矩形。
    pub settings_rect: Rect,
    /// 聊天页 [发文件] 按钮的命中矩形。
    pub sendfile_rect: Rect,
    /// 左侧「+加好友」按钮的命中矩形。
    pub addfriend_rect: Rect,
    /// 最近一次鼠标列/行。
    pub mouse_col: u16,
    pub mouse_row: u16,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            tab: Tab::Chat,
            contact_sel: 0,
            chat_scroll: 0,
            chat_input: String::new(),
            editing_nick: false,
            nick_input: String::new(),
            editing_friend: false,
            friend_input: String::new(),
            friend_bootstrap: false,
            left_focused: true,
            file_list: Vec::new(),
            file_sel: 0,
            contact_ids: Vec::new(),
            contact_rects: Vec::new(),
            offer_rects: Vec::new(),
            tab_rects: Vec::new(),
            chat_input_rect: Rect::default(),
            settings_rect: Rect::default(),
            sendfile_rect: Rect::default(),
            addfriend_rect: Rect::default(),
            mouse_col: 0,
            mouse_row: 0,
        }
    }
}

/// 面板（普通直角边框，Windows 终端兼容，不乱码）。
fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(title.to_string())
}

/// 刷新当前目录文件列表（只保留文件、按名字排序）。
pub fn refresh_file_list(ui: &mut UiState) {
    let mut files: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(".") {
        for e in rd.flatten() {
            if let Ok(meta) = e.metadata() {
                if meta.is_file() {
                    files.push(e.file_name().to_string_lossy().to_string());
                }
            }
        }
    }
    files.sort();
    ui.file_list = files;
}

/// 非阻塞地收集这一刻攒下的所有按键/鼠标事件，转成 UiCmd 列表。
/// 传入 `state` 以便直接读取待决定邀请等信息（避免绕弯缓存）。
pub fn poll_keys(ui: &mut UiState, state: &mut AppState) -> Vec<UiCmd> {
    let mut cmds = Vec::new();
    while event::poll(Duration::ZERO).unwrap_or(false) {
        match event::read() {
            Ok(Event::Key(key)) => {
                if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                    handle_key(ui, key.code, key.modifiers, &mut cmds, state);
                }
            }
            Ok(Event::Mouse(me)) => handle_mouse(ui, me, &mut cmds),
            _ => {}
        }
    }
    cmds
}

/// 键盘绑定（聊天输入完全自由，不占用任何字母键）。
/// - 接受/拒绝文件：鼠标点击聊天页里的邀请行（左半=接受，右半=拒绝）。
/// - 文件列表在"文件"页自动刷新（不绑定任何字母键，避免影响聊天输入）。
/// - 退出：Ctrl+C。
///
/// 左侧联系人选择（↑↓/j/k）会**实时**切换当前对话：高亮行即正在对话的联系人。
fn handle_key(
    ui: &mut UiState,
    code: KeyCode,
    mods: KeyModifiers,
    cmds: &mut Vec<UiCmd>,
    state: &mut AppState,
) {
    // 正在编辑昵称或添加好友：这段时间内只接收编辑相关按键
    if ui.editing_nick || ui.editing_friend {
        match code {
            KeyCode::Enter => {
                if ui.editing_nick {
                    if !ui.nick_input.is_empty() {
                        cmds.push(UiCmd::SetNickname(ui.nick_input.clone()));
                    }
                    ui.editing_nick = false;
                    ui.nick_input.clear();
                } else {
                    if !ui.friend_input.is_empty() {
                        cmds.push(UiCmd::AddFriend {
                            addr: ui.friend_input.clone(),
                            bootstrap: ui.friend_bootstrap,
                        });
                    }
                    ui.editing_friend = false;
                    ui.friend_input.clear();
                }
            }
            KeyCode::Tab => {
                // 添加好友时：在「直连 / DHT 引导」之间切换
                if ui.editing_friend {
                    ui.friend_bootstrap = !ui.friend_bootstrap;
                }
            }
            KeyCode::Esc => {
                ui.editing_nick = false;
                ui.editing_friend = false;
                ui.nick_input.clear();
                ui.friend_input.clear();
            }
            KeyCode::Backspace => {
                if ui.editing_nick {
                    ui.nick_input.pop();
                } else {
                    ui.friend_input.pop();
                }
            }
            KeyCode::Char(c) => {
                if ui.editing_nick {
                    ui.nick_input.push(c);
                } else {
                    ui.friend_input.push(c);
                }
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Tab => ui.tab = next_tab(ui.tab),
        KeyCode::Up => {
            move_sel(ui, -1);
            // 聊天页：实时切换当前对话到高亮联系人
            if ui.tab == Tab::Chat {
                if let Some(peer) = ui.contact_ids.get(ui.contact_sel).copied() {
                    cmds.push(UiCmd::SelectPeer(peer));
                }
            }
            let _ = state;
        }
        KeyCode::Down => {
            move_sel(ui, 1);
            if ui.tab == Tab::Chat {
                if let Some(peer) = ui.contact_ids.get(ui.contact_sel).copied() {
                    cmds.push(UiCmd::SelectPeer(peer));
                }
            }
            let _ = state;
        }
        KeyCode::Enter => {
            if ui.tab == Tab::Chat {
                if !ui.chat_input.is_empty() {
                    cmds.push(UiCmd::SendChat(ui.chat_input.clone()));
                    ui.chat_input.clear();
                } else if let Some(peer) = ui.contact_ids.get(ui.contact_sel).copied() {
                    cmds.push(UiCmd::SelectPeer(peer));
                }
            } else if ui.tab == Tab::Files {
                if let Some(p) = ui.file_list.get(ui.file_sel).cloned() {
                    cmds.push(UiCmd::SendFile(p));
                }
            }
        }
        KeyCode::Backspace => {
            // 聊天输入框里可以删除字符（否则只能加不能删，等于"打不了字"）
            if ui.tab == Tab::Chat && !ui.editing_nick {
                ui.chat_input.pop();
            }
        }
        KeyCode::Esc => {
            if !ui.chat_input.is_empty() {
                ui.chat_input.clear();
            } else {
                ui.left_focused = !ui.left_focused;
            }
        }
        KeyCode::Char(c) if !mods.contains(KeyModifiers::CONTROL) => {
            // 普通可打印字符：聊天输入框接收（a/d/h/r 等都能正常输入）
            if ui.tab == Tab::Chat {
                ui.chat_input.push(c);
            }
        }
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => cmds.push(UiCmd::Quit),
        _ => {}
    }
}

/// 鼠标事件：记录位置，处理滚轮与左键命中。
fn handle_mouse(ui: &mut UiState, me: MouseEvent, cmds: &mut Vec<UiCmd>) {
    ui.mouse_col = me.column;
    ui.mouse_row = me.row;
    match me.kind {
        MouseEventKind::ScrollUp => {
            if ui.tab == Tab::Chat && ui.chat_scroll > 0 {
                ui.chat_scroll -= 1;
            }
        }
        MouseEventKind::ScrollDown => {
            if ui.tab == Tab::Chat {
                ui.chat_scroll += 1;
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            let p = (me.column, me.row);
            // 右上角 [设置] 按钮
            if in_rect(p, ui.settings_rect) {
                ui.editing_nick = true;
                ui.nick_input.clear();
                return;
            }
            // 左侧「+加好友」按钮
            if in_rect(p, ui.addfriend_rect) {
                ui.editing_friend = true;
                ui.friend_input.clear();
                ui.friend_bootstrap = false;
                return;
            }
            // 聊天页 [发文件] 按钮
            if ui.tab == Tab::Chat && in_rect(p, ui.sendfile_rect) {
                cmds.push(UiCmd::PickFile);
                return;
            }
            // 顶部标签页切换
            for (r, t) in &ui.tab_rects {
                if in_rect(p, *r) {
                    ui.tab = *t;
                    return;
                }
            }
            // 联系人行点击
            for (r, pid) in &ui.contact_rects {
                if in_rect(p, *r) {
                    cmds.push(UiCmd::SelectPeer(*pid));
                    // 让高亮跟随点击行
                    if let Some(i) = ui.contact_ids.iter().position(|p| p == pid) {
                        ui.contact_sel = i;
                    }
                    return;
                }
            }
            // 聊天页文件邀请行：左半=接受，右半=拒绝
            for (r, pid, fid) in &ui.offer_rects {
                if in_rect(p, *r) {
                    if me.column < r.x + r.width / 2 {
                        cmds.push(UiCmd::AcceptFile(*pid, *fid));
                    } else {
                        cmds.push(UiCmd::RejectFile(*pid, *fid));
                    }
                    return;
                }
            }
            // 聊天输入框点击聚焦
            if in_rect(p, ui.chat_input_rect) {
                ui.left_focused = false;
                return;
            }
        }
        _ => {}
    }
}

fn in_rect(p: (u16, u16), r: Rect) -> bool {
    let (c, row) = p;
    c >= r.x && c < r.x + r.width && row >= r.y && row < r.y + r.height
}

fn next_tab(t: Tab) -> Tab {
    match t {
        Tab::Chat => Tab::Files,
        Tab::Files => Tab::Progress,
        Tab::Progress => Tab::Log,
        Tab::Log => Tab::Received,
        Tab::Received => Tab::Chat,
    }
}

fn move_sel(ui: &mut UiState, delta: i32) {
    if ui.tab == Tab::Files {
        let n = ui.file_list.len() as i32;
        if n == 0 {
            return;
        }
        ui.file_sel = (ui.file_sel as i32 + delta).clamp(0, n - 1) as usize;
    } else {
        let n = ui.contact_ids.len() as i32;
        if n == 0 {
            return;
        }
        ui.contact_sel = (ui.contact_sel as i32 + delta).clamp(0, n - 1) as usize;
    }
}

/// 聊天页里的一个条目：普通记录或文件邀请。
enum ChatEntry {
    Record(Line<'static>),
    Offer(PeerId, u64, String),
}

/// 主绘制入口。
pub fn draw(f: &mut Frame, state: &AppState, ui: &mut UiState) {
    ui.contact_rects.clear();
    ui.offer_rects.clear();
    ui.tab_rects.clear();

    let size = f.area();
    let outer = Layout::vertical([Constraint::Length(2), Constraint::Min(3), Constraint::Length(1)])
        .split(size);

    // 顶部：标题行 + 标签页行
    let top = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(outer[0]);
    let title_row =
        Layout::horizontal([Constraint::Length(16), Constraint::Min(0), Constraint::Length(12)])
            .split(top[0]);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " peerchat",
            Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
        ))),
        title_row[0],
    );
    f.render_widget(
        Paragraph::new(format!("我: {}", state.nickname))
            .alignment(Alignment::Right)
            .style(Style::default().fg(Color::DarkGray)),
        title_row[1],
    );
    // 设置按钮
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " [ 设置 ] ",
            Style::default().fg(Color::Blue),
        )))
        .alignment(Alignment::Center),
        title_row[2],
    );
    ui.settings_rect = title_row[2];

    // 标签页
    let tabs = [Tab::Chat, Tab::Files, Tab::Progress, Tab::Log, Tab::Received];
    let tab_c: Vec<Constraint> = tabs.iter().map(|_| Constraint::Length(10)).collect();
    let tab_areas = Layout::horizontal(tab_c).split(top[1]);
    for (i, t) in tabs.iter().enumerate() {
        let active = *t == ui.tab;
        let label = format!(" {}{} ", if active { "▸" } else { " " }, t.title());
        let style = if active {
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        f.render_widget(Paragraph::new(Line::from(Span::styled(label, style))), tab_areas[i]);
        ui.tab_rects.push((tab_areas[i], *t));
    }

    // 主区：左联系人 / 右内容
    let main = Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(outer[1]);
    draw_contacts(f, main[0], state, ui);
    match ui.tab {
        Tab::Chat => draw_chat(f, main[1], state, ui),
        Tab::Files => draw_files(f, main[1], state, ui),
        Tab::Progress => draw_progress(f, main[1], state, ui),
        Tab::Log => draw_log(f, main[1], state, ui),
        Tab::Received => draw_received(f, main[1], ui),
    }

    // 底部：改名/加好友输入优先，否则 toast，否则留白（不再常驻操作提示）
    if ui.editing_nick {
        let s = format!("修改昵称：{}_   （回车确认 · Esc 取消）", ui.nick_input);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(s, Style::default().fg(Color::Blue)))),
            outer[2],
        );
    } else if ui.editing_friend {
        let kind = if ui.friend_bootstrap { "DHT引导" } else { "直连" };
        let s = format!(
            "加好友（{}）：{}_   （回车确认 · Tab切换类型 · Esc取消）",
            kind, ui.friend_input
        );
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(s, Style::default().fg(Color::Blue)))),
            outer[2],
        );
    } else if let Some(t) = take_toast() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" ☞ {t}"),
                Style::default().fg(Color::Blue),
            ))),
            outer[2],
        );
    } else {
        f.render_widget(Paragraph::new(""), outer[2]);
    }
}

fn draw_contacts(f: &mut Frame, area: Rect, state: &AppState, ui: &mut UiState) {
    let inner = panel("联系人").inner(area);
    f.render_widget(panel("联系人"), area);

    // 顶部一行：「+加好友」按钮（点一下输入地址，可直连或加 DHT 引导站点）
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " [+加好友] ",
            Style::default().fg(Color::Blue),
        )))
        .alignment(Alignment::Left),
        chunks[0],
    );
    ui.addfriend_rect = chunks[0];
    let list_area = chunks[1];

    let mut ids: Vec<PeerId> = state.peers.keys().copied().collect();
    ids.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    ui.contact_ids = ids.clone();
    if ids.is_empty() {
        f.render_widget(
            Paragraph::new("等待局域网发现其他节点…（外网见「+加好友」）")
                .style(Style::default().fg(Color::DarkGray)),
            list_area,
        );
        return;
    }
    // 高亮行始终与"当前对话联系人"对齐，让用户一眼看清在跟谁聊。
    if let Some(sp) = state.selected_peer {
        if let Some(i) = ids.iter().position(|p| *p == sp) {
            ui.contact_sel = i;
        }
    }
    if ui.contact_sel >= ids.len() {
        ui.contact_sel = ids.len() - 1;
    }

    // 每行一个条目；选中项由 List 的高亮样式整行铺蓝底（而非只覆盖文字）
    let items: Vec<ListItem> = ids
        .iter()
        .map(|pid| {
            let info = &state.peers[pid];
            let dot = if info.online { "●" } else { "○" };
            let dot_color = if info.online { Color::Green } else { Color::Red };
            let nick = if info.nickname.is_empty() {
                "(未知)".to_string()
            } else {
                info.nickname.clone()
            };
            let s = pid.to_string();
            let short = s[..s.len().min(8)].to_string();
            let ip = info.last_addr.clone().unwrap_or_else(|| "—".to_string());
            let mut spans = vec![
                Span::styled(dot, Style::default().fg(dot_color)),
                Span::styled(format!(" {}", nick), Style::default().fg(Color::White)),
            ];
            // 未读徽标紧跟昵称（靠前，避免窄栏被截断）
            if info.unread > 0 {
                spans.push(Span::styled(
                    format!(" {} ", info.unread),
                    Style::default().bg(Color::Red).fg(Color::White),
                ));
            }
            spans.push(Span::styled(format!("  {}", short), Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(format!("  {}", ip), Style::default().fg(Color::DarkGray)));
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(ui.contact_sel));
    let list = List::new(items)
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("");
    f.render_stateful_widget(list, list_area, &mut list_state);

    // 记录命中矩形（与 List 行布局一致，每项 1 高）
    let c: Vec<Constraint> = ids.iter().map(|_| Constraint::Length(1)).collect();
    let rows = Layout::vertical(c).split(list_area);
    for (i, pid) in ids.iter().enumerate() {
        ui.contact_rects.push((rows[i], *pid));
    }
}

fn draw_chat(f: &mut Frame, area: Rect, state: &AppState, ui: &mut UiState) {
    let inner = panel("聊天").inner(area);
    f.render_widget(panel("聊天"), area);

    let header_h: u16 = 1;
    let input_h: u16 = 2;
    let avail = inner.height.saturating_sub(header_h + input_h);
    let layout = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Length(avail),
        Constraint::Length(input_h),
    ])
    .split(inner);

    let peer = state.selected_peer;
    let header = match peer {
        Some(p) => match state.peers.get(&p) {
            Some(i) => {
                let on = if i.online { "在线" } else { "离线" };
                let nick = if i.nickname.is_empty() {
                    "(未知)".to_string()
                } else {
                    i.nickname.clone()
                };
                format!("与 {} 聊天   [{}]", nick, on)
            }
            None => format!("与 {p} 聊天"),
        },
        None => "在左侧选择一个联系人，回车开始对话".to_string(),
    };
    // 标题 + 右侧 [发文件] 按钮
    let header_split =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(12)]).split(layout[0]);
    f.render_widget(
        Paragraph::new(header).style(Style::default().fg(Color::Blue)),
        header_split[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " [发文件] ",
            Style::default().fg(Color::Blue),
        )))
        .alignment(Alignment::Center),
        header_split[1],
    );
    ui.sendfile_rect = header_split[1];

    let mut entries: Vec<ChatEntry> = Vec::new();
    if let Some(p) = peer {
        if let Some(info) = state.peers.get(&p) {
            for rec in &info.records {
                entries.push(ChatEntry::Record(render_record(rec)));
            }
        }
        if let Some(offers) = state.pending_offers.get(&p) {
            for o in offers {
                entries.push(ChatEntry::Offer(
                    p,
                    o.file_id,
                    format!(
                        "对方想发来文件：{}（{} 字节）  点左=接受 点右=拒绝",
                        o.filename, o.size
                    ),
                ));
            }
        }
    }

    let total = entries.len() as u16;
    let max_start = if total > avail { total - avail } else { 0 };
    let mut start = max_start.saturating_sub(ui.chat_scroll);
    if start > max_start {
        start = max_start;
    }
    let (x, y0, w) = (layout[1].x, layout[1].y, layout[1].width);
    let mut lines: Vec<Line> = Vec::new();
    for (idx, e) in entries.iter().enumerate() {
        if idx < start as usize || idx >= (start + avail) as usize {
            continue;
        }
        let row = (idx - start as usize) as u16;
        let rect = Rect {
            x,
            y: y0 + row,
            width: w,
            height: 1,
        };
        match e {
            ChatEntry::Record(l) => lines.push(l.clone()),
            ChatEntry::Offer(pp, fid, t) => {
                lines.push(Line::from(Span::styled(
                    t.clone(),
                    Style::default().fg(Color::Blue),
                )));
                ui.offer_rects.push((rect, *pp, *fid));
            }
        }
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), layout[1]);

    let input_line = if ui.editing_nick {
        "（正在修改昵称…）".to_string()
    } else {
        format!("{} › {}_", state.nickname, ui.chat_input)
    };
    f.render_widget(
        Paragraph::new(input_line).style(Style::default().fg(Color::Blue)),
        layout[2],
    );
    ui.chat_input_rect = layout[2];
}

fn draw_files(f: &mut Frame, area: Rect, _state: &AppState, ui: &mut UiState) {
    // 进入文件页即自动刷新（不再绑定字母键做快捷键）
    refresh_file_list(ui);
    let inner = panel("文件（当前目录）").inner(area);
    f.render_widget(panel("文件（当前目录）"), area);
    if ui.file_list.is_empty() {
        f.render_widget(
            Paragraph::new("当前目录没有文件").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    if ui.file_sel >= ui.file_list.len() {
        ui.file_sel = ui.file_list.len() - 1;
    }
    let c: Vec<Constraint> = ui.file_list.iter().map(|_| Constraint::Length(1)).collect();
    let rows = Layout::vertical(c).split(inner);
    for (i, name) in ui.file_list.iter().enumerate() {
        let selected = i == ui.file_sel;
        let style = if selected {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else {
            Style::default()
        };
        f.render_widget(Paragraph::new(format!(" {name}")).style(style), rows[i]);
    }
}

fn draw_progress(f: &mut Frame, area: Rect, state: &AppState, _ui: &mut UiState) {
    let inner = panel("进度").inner(area);
    f.render_widget(panel("进度"), area);

    let mut items: Vec<(String, f64)> = Vec::new();
    for t in state.outgoing_files.values() {
        let total = t.chunks.len() as f64;
        let sent = if total > 0.0 {
            (total - t.pending.len() as f64) / total
        } else {
            0.0
        };
        let label = format!(
            "↑ {} {} [{}]",
            peer_short(state, &t.peer),
            t.filename,
            phase_name(t.phase)
        );
        items.push((label, sent.clamp(0.0, 1.0)));
    }
    for inc in state.incoming_files.values() {
        let total = inc.total as f64;
        let got = if total > 0.0 {
            inc.chunks.len() as f64 / total
        } else {
            0.0
        };
        items.push((format!("↓ {} [接收中]", inc.filename), got.clamp(0.0, 1.0)));
    }
    if items.is_empty() {
        f.render_widget(
            Paragraph::new("当前没有进行中的文件传输").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    let c: Vec<Constraint> = items.iter().map(|_| Constraint::Length(2)).collect();
    let rows = Layout::vertical(c).split(inner);
    for (i, (label, ratio)) in items.iter().enumerate() {
        f.render_widget(Paragraph::new(label.clone()), rows[i]);
        let g = Rect {
            x: rows[i].x,
            y: rows[i].y + 1,
            width: rows[i].width,
            height: 1,
        };
        f.render_widget(
            Gauge::default()
                .ratio(*ratio)
                .label(format!("{:.0}%", ratio * 100.0))
                .style(Style::default().fg(Color::Blue)),
            g,
        );
    }
}

fn draw_log(f: &mut Frame, area: Rect, state: &AppState, _ui: &mut UiState) {
    let inner = panel("日志").inner(area);
    f.render_widget(panel("日志"), area);
    let logs: Vec<Line> = state.logs.iter().map(|l| Line::from(l.clone())).collect();
    f.render_widget(Paragraph::new(logs).wrap(Wrap { trim: true }), inner);
}

fn draw_received(f: &mut Frame, area: Rect, _ui: &mut UiState) {
    let inner = panel("已收文件").inner(area);
    f.render_widget(panel("已收文件"), area);
    let mut files: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("downloads") {
        for e in rd.flatten() {
            if let Ok(meta) = e.metadata() {
                if meta.is_file() {
                    files.push(e.file_name().to_string_lossy().to_string());
                }
            }
        }
    }
    files.sort();
    if files.is_empty() {
        f.render_widget(
            Paragraph::new("downloads/ 目录还没有文件").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    let c: Vec<Constraint> = files.iter().map(|_| Constraint::Length(1)).collect();
    let rows = Layout::vertical(c).split(inner);
    for (i, name) in files.iter().enumerate() {
        f.render_widget(
            Paragraph::new(format!(" {name}")).style(Style::default().fg(Color::White)),
            rows[i],
        );
    }
}

/// 判断一条文本是否为"消极/失败"类提示（用于红底醒目显示）。
fn is_negative(s: &str) -> bool {
    ["失败", "拒绝", "中断", "无法", "错误", "无应答", "未送达", "不能", "超时", "未收到"]
        .iter()
        .any(|k| s.contains(k))
}

/// 把一条记录渲染成带对齐方式的行：自己发的靠右（蓝），对方靠左（白），系统/时间居中（灰）。
/// 每条都带发送时刻（暗灰）；消极/失败类提示用红底白字醒目显示。
fn render_record(rec: &ChatRecord) -> Line<'static> {
    let t = &rec.time;
    let neg = is_negative(&rec.text);
    let base = if neg {
        Style::default().bg(Color::Red).fg(Color::White)
    } else {
        Style::default()
    };
    match rec.kind.as_str() {
        "text" => {
            if rec.outbound {
                let mut l = Line::from(vec![
                    Span::styled(format!("我：{}", rec.text), base.fg(Color::Blue)),
                    Span::styled(format!("  {}", t), Style::default().fg(Color::DarkGray)),
                ]);
                l.alignment = Some(Alignment::Right);
                l
            } else {
                let mut l = Line::from(vec![
                    Span::styled(format!("{} ", t), Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}：{}", rec.name, rec.text),
                        if neg {
                            base
                        } else {
                            Style::default().fg(Color::White)
                        },
                    ),
                ]);
                l.alignment = Some(Alignment::Left);
                l
            }
        }
        "system" => {
            let mut l = Line::from(vec![
                Span::styled(format!("{} ", t), Style::default().fg(Color::DarkGray)),
                Span::styled(rec.text.clone(), base),
            ]);
            l.alignment = Some(Alignment::Center);
            l
        }
        "file" => {
            let mut l = Line::from(vec![
                Span::styled(format!("{} ", t), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("〔文件〕{}", rec.text),
                    if neg {
                        base
                    } else {
                        Style::default().fg(Color::Blue)
                    },
                ),
            ]);
            l.alignment = Some(Alignment::Left);
            l
        }
        _ => {
            let mut l = Line::from(vec![
                Span::styled(format!("{} ", t), Style::default().fg(Color::DarkGray)),
                Span::styled(rec.text.clone(), base.fg(Color::White)),
            ]);
            l.alignment = Some(Alignment::Left);
            l
        }
    }
}

fn phase_name(p: file_transfer::Phase) -> &'static str {
    match p {
        file_transfer::Phase::Offering => "等待接受",
        file_transfer::Phase::Sending => "发送中",
        file_transfer::Phase::Checking => "查漏",
        file_transfer::Phase::Done => "完成",
    }
}

fn peer_short(state: &AppState, peer: &PeerId) -> String {
    state
        .peers
        .get(peer)
        .map(|i| {
            if i.nickname.is_empty() {
                let s = peer.to_string();
                s[..s.len().min(8)].to_string()
            } else {
                i.nickname.clone()
            }
        })
        .unwrap_or_else(|| peer.to_string())
}
