use anyhow::{Context, Result};
use blake3::Hasher;
use parking_lot::RwLock;
use rusqlite::{params, Connection as SqliteConnection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::Event;
use x11rb::{connect, COPY_DEPTH_FROM_PARENT};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt;
use x11rb::protocol::xproto::ConnectionExt as XprotoConnectionExt;
use zeroize::Zeroize;

const MAX_INLINE_SIZE: usize = 512;
const POLL_INTERVAL_MS: u64 = 100;
const X11_TIMEOUT_MS: u64 = 250;
const HASH_PREFIX_LEN: usize = 8;
const MAX_CLIPBOARD_SIZE: usize = 100 * 1024 * 1024; // 100MB
const MAX_IPC_MESSAGE_SIZE: usize = 4096;
const IPC_MAGIC: &[u8] = b"NOCB\x00\x01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub cache_dir: PathBuf,
    pub max_entries: usize,
    pub max_display_length: usize,
    pub max_print_entries: usize,
    pub use_primary: bool,
    pub blacklist: Vec<String>,
    pub trim_whitespace: bool,
    pub static_entries: Vec<String>,
    pub compress_threshold: usize,
}

impl Default for Config {
    fn default() -> Self {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("nocb");

        Self {
            cache_dir,
            max_entries: 10000,
            max_display_length: 200,
            max_print_entries: 1000,
            use_primary: false,
            blacklist: Vec::new(),
            trim_whitespace: true,
            static_entries: Vec::new(),
            compress_threshold: 4096,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = dirs::config_dir()
            .unwrap_or_default()
            .join("nocb")
            .join("config.toml");

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            Ok(toml::from_str(&content)?)
        } else {
            let config = Self::default();
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&config_path, toml::to_string_pretty(&config)?)?;
            Ok(config)
        }
    }
}

#[derive(Debug, Clone)]
pub enum ContentType {
    Text(String),
    TextFile { hash: String, compressed: bool },
    Image { mime: String, hash: String },
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: Option<i64>,
    pub hash: String,
    pub timestamp: u64,
    pub app_name: String,
    pub content: ContentType,
    pub size_bytes: usize,
}

impl Entry {
    fn new(content: ContentType, app_name: String, hash: String, size: usize) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: None,
            hash,
            timestamp,
            app_name,
            content,
            size_bytes: size,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClipboardTask {
    ServeText(Vec<u8>),
    ServeImage { mime: String, data: Vec<u8> },
}

#[derive(Debug)]
pub enum Command {
    Copy(String),
    Exit,
}

pub struct ClipboardManager {
    config: Config,
    db: SqliteConnection,
    conn: Arc<RustConnection>,
    window: Window,
    atoms: Atoms,
    last_clipboard_hash: Option<String>,
    last_primary_hash: Option<String>,
    seq_counter: AtomicU64,
    serving_selection: Arc<RwLock<Option<ClipboardTask>>>,
    command_rx: Option<mpsc::Receiver<Command>>,
}

#[derive(Clone)]
struct Atoms {
    clipboard: Atom,
    primary: Atom,
    targets: Atom,
    utf8_string: Atom,
    string: Atom,
    text: Atom,
    wm_name: Atom,
}

impl Atoms {
    fn new(conn: &RustConnection) -> Result<Self> {
        Ok(Self {
            clipboard: conn.intern_atom(false, b"CLIPBOARD")?.reply()?.atom,
            primary: AtomEnum::PRIMARY.into(),
            targets: conn.intern_atom(false, b"TARGETS")?.reply()?.atom,
            utf8_string: conn.intern_atom(false, b"UTF8_STRING")?.reply()?.atom,
            string: AtomEnum::STRING.into(),
            text: conn.intern_atom(false, b"TEXT")?.reply()?.atom,
            wm_name: AtomEnum::WM_NAME.into(),
        })
    }
}

impl ClipboardManager {
    pub async fn new(config: Config) -> Result<Self> {
        fs::create_dir_all(&config.cache_dir)?;
        fs::create_dir_all(config.cache_dir.join("blobs"))?;

        let db_path = config.cache_dir.join("index.db");
        let db = SqliteConnection::open(&db_path)?;
        Self::init_db(&db)?;

        let (conn, screen_num) = connect(None).context("Failed to connect to X11")?;
        let conn = Arc::new(conn);
        let atoms = Atoms::new(&conn)?;
        
        let screen = &conn.setup().roots[screen_num];
        let window = conn.generate_id()?;

        conn.create_window(
            COPY_DEPTH_FROM_PARENT,
            window,
            screen.root,
            0, 0, 1, 1, 0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new(),
        )?;

        let mask = EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY;
        conn.change_window_attributes(window, &ChangeWindowAttributesAux::new().event_mask(mask))?;
        conn.flush()?;

        Ok(Self {
            config,
            db,
            conn,
            window,
            atoms,
            last_clipboard_hash: None,
            last_primary_hash: None,
            seq_counter: AtomicU64::new(0),
            serving_selection: Arc::new(RwLock::new(None)),
            command_rx: None,
        })
    }

    fn init_db(db: &SqliteConnection) -> Result<()> {
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000;
             PRAGMA mmap_size = 268435456;
             PRAGMA temp_store = MEMORY;
             
             CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                hash TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                app_name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                file_path TEXT,
                inline_text TEXT,
                mime_type TEXT,
                size_bytes INTEGER NOT NULL,
                compressed INTEGER DEFAULT 0
            );
            
            CREATE INDEX IF NOT EXISTS idx_timestamp ON entries(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_hash ON entries(hash);"
        )?;
        Ok(())
    }

    pub async fn run_daemon(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel(10);
        self.command_rx = Some(rx);
        
        // Spawn IPC server
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::ipc_server(tx_clone).await {
                eprintln!("IPC server error: {}", e);
            }
        });

        // Spawn selection server
        let conn_clone = self.conn.clone();
        let window = self.window;
        let serving_clone = self.serving_selection.clone();
        let atoms_clone = self.atoms.clone();

        tokio::spawn(async move {
            Self::selection_server(conn_clone, window, serving_clone, atoms_clone).await;
        });

        let mut interval = tokio::time::interval(Duration::from_millis(POLL_INTERVAL_MS));
        let mut cleanup_counter = 0u64;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_clipboard().await {
                        eprintln!("Poll error: {}", e);
                    }
                    
                    cleanup_counter += 1;
                    if cleanup_counter % 1000 == 0 {
                        let _ = self.cleanup_old_entries();
                    }
                }
                
                cmd = async { self.command_rx.as_mut()?.recv().await } => {
                    if let Some(cmd) = cmd {
                        match cmd {
                            Command::Copy(selection) => {
                                if let Err(e) = self.copy_selection(&selection).await {
                                    eprintln!("Copy error: {}", e);
                                }
                            }
                            Command::Exit => break,
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn ipc_server(tx: mpsc::Sender<Command>) -> Result<()> {
        use tokio::net::UnixListener;
        
        let sock_path = std::env::temp_dir().join("nocb.sock");
        let _ = fs::remove_file(&sock_path);
        
        let listener = UnixListener::bind(&sock_path)?;
        
        loop {
            let (mut stream, _addr) = listener.accept().await?;
            
            // Verify same UID
            let cred = stream.peer_cred()?;
            if cred.uid() != unsafe { libc::getuid() } {
                eprintln!("IPC rejected: different UID");
                continue;
            }
            
            let tx = tx.clone();
            
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; MAX_IPC_MESSAGE_SIZE];
                
                match stream.read(&mut buf).await {
                    Ok(n) if n > IPC_MAGIC.len() => {
                        if &buf[..IPC_MAGIC.len()] != IPC_MAGIC {
                            return;
                        }
                        
                        if let Ok(cmd) = String::from_utf8(buf[IPC_MAGIC.len()..n].to_vec()) {
                            let cmd = cmd.trim();
                            if cmd.starts_with("COPY:") {
                                let selection = cmd[5..].to_string();
                                let _ = tx.send(Command::Copy(selection)).await;
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
    }

    pub async fn send_copy_command(selection: &str) -> Result<()> {
        use tokio::net::UnixStream;
        use tokio::io::AsyncWriteExt;
        
        let sock_path = std::env::temp_dir().join("nocb.sock");
        let mut stream = UnixStream::connect(&sock_path).await?;
        
        let mut msg = Vec::with_capacity(IPC_MAGIC.len() + 5 + selection.len());
        msg.extend_from_slice(IPC_MAGIC);
        msg.extend_from_slice(format!("COPY:{}", selection).as_bytes());
        
        stream.write_all(&msg).await?;
        Ok(())
    }

    async fn poll_clipboard(&mut self) -> Result<()> {
        if let Some(entry) = self.get_clipboard_content(self.atoms.clipboard).await? {
            if self.last_clipboard_hash.as_ref() != Some(&entry.hash) {
                self.add_entry(entry.clone()).await?;
                self.last_clipboard_hash = Some(entry.hash);
            }
        }

        if self.config.use_primary {
            if let Some(entry) = self.get_clipboard_content(self.atoms.primary).await? {
                if self.last_primary_hash.as_ref() != Some(&entry.hash) {
                    self.add_entry(entry.clone()).await?;
                    self.last_primary_hash = Some(entry.hash);
                }
            }
        }

        Ok(())
    }

    async fn get_clipboard_content(&self, selection: Atom) -> Result<Option<Entry>> {
        let app_name = self.get_selection_owner_name(selection).await
            .unwrap_or_else(|| "unknown".to_string());

        // Get available targets first
        if let Ok(targets_data) = self.convert_selection(selection, "TARGETS").await {
            let targets = self.parse_targets(&targets_data);
            
            // Only try images if image targets are actually advertised
            let has_image_target = targets.iter().any(|t| 
                t.contains("image/") || t.contains("IMAGE")
            );
            
            if has_image_target {
                for mime in &["image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp"] {
                    if let Ok(data) = self.convert_selection(selection, mime).await {
                        if !data.is_empty() && data.len() <= MAX_CLIPBOARD_SIZE {
                            let hash = self.hash_data(&data);
                            let stored_hash = self.store_blob(&hash, &data)?;
                            let content = ContentType::Image {
                                mime: mime.to_string(),
                                hash: stored_hash.clone(),
                            };
                            return Ok(Some(Entry::new(content, app_name, stored_hash, data.len())));
                        }
                    }
                }
            }
        }

        // Try text
        for target in &["UTF8_STRING", "STRING", "TEXT"] {
            if let Ok(mut data) = self.convert_selection(selection, target).await {
                if data.len() > MAX_CLIPBOARD_SIZE {
                    continue;
                }
                
                if let Ok(text) = String::from_utf8(data.clone()) {
                    let text = if self.config.trim_whitespace {
                        let trimmed = text.trim();
                        if trimmed.is_empty() { continue; }
                        trimmed.to_string()
                    } else {
                        if text.trim().is_empty() { continue; }
                        text
                    };

                    let hash = self.hash_data(text.as_bytes());
                    let size = text.len();

                    let content = if size <= MAX_INLINE_SIZE {
                        ContentType::Text(text)
                    } else {
                        let compressed = size > self.config.compress_threshold;
                        let stored_hash = self.store_text_blob(&hash, &text, compressed)?;
                        ContentType::TextFile { hash: stored_hash, compressed }
                    };

                    data.zeroize();
                    return Ok(Some(Entry::new(content, app_name, hash, size)));
                }
            }
        }

        Ok(None)
    }

    fn hash_data(&self, data: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data);
        format!("{}", hasher.finalize().to_hex())
    }

    fn parse_targets(&self, data: &[u8]) -> Vec<String> {
        let mut targets = Vec::new();
        
        // TARGETS returns array of atoms (u32 values)
        for chunk in data.chunks_exact(4) {
            if let Ok(bytes) = <[u8; 4]>::try_from(chunk) {
                let atom = u32::from_ne_bytes(bytes);
                
                // Try to get atom name
                if let Ok(reply) = self.conn.get_atom_name(atom) {
                    if let Ok(reply) = reply.reply() {
                        if let Ok(name) = String::from_utf8(reply.name) {
                            targets.push(name);
                        }
                    }
                }
            }
        }
        
        targets
    }

    fn store_blob(&self, hash: &str, data: &[u8]) -> Result<String> {
        let path = self.config.cache_dir.join("blobs").join(hash);
        if !path.exists() {
            fs::write(&path, data)?;
        }
        Ok(hash.to_string())
    }

    fn store_text_blob(&self, hash: &str, text: &str, compress: bool) -> Result<String> {
        let filename = if compress {
            format!("{}.txt.zst", hash)
        } else {
            format!("{}.txt", hash)
        };
        
        let path = self.config.cache_dir.join("blobs").join(&filename);
        if !path.exists() {
            if compress {
                use zstd::stream::write::Encoder;
                let file = fs::File::create(&path)?;
                let mut encoder = Encoder::new(file, 3)?;
                encoder.write_all(text.as_bytes())?;
                encoder.finish()?;
            } else {
                fs::write(&path, text)?;
            }
        }
        Ok(hash.to_string())
    }

    async fn get_selection_owner_name(&self, selection: Atom) -> Option<String> {
        let owner = self.conn.get_selection_owner(selection).ok()?.reply().ok()?.owner;
        if owner == x11rb::NONE {
            return None;
        }

        let reply = self.conn.get_property(
            false, owner, self.atoms.wm_name, AtomEnum::STRING, 0, 1024
        ).ok()?.reply().ok()?;

        String::from_utf8(reply.value).ok()
    }

    async fn convert_selection(&self, selection: Atom, target: &str) -> Result<Vec<u8>> {
        let target_atom = if target == "UTF8_STRING" {
            self.atoms.utf8_string
        } else if target == "STRING" {
            self.atoms.string
        } else if target == "TEXT" {
            self.atoms.text
        } else {
            self.conn.intern_atom(false, target.as_bytes())?.reply()?.atom
        };

        let property = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        let property_atom = self.conn.intern_atom(false, format!("NOCB_{}", property).as_bytes())?.reply()?.atom;

        self.conn.convert_selection(
            self.window,
            selection,
            target_atom,
            property_atom,
            x11rb::CURRENT_TIME,
        )?;
        self.conn.flush()?;

        let deadline = tokio::time::Instant::now() + Duration::from_millis(X11_TIMEOUT_MS);

        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(event)) = self.conn.poll_for_event() {
                if let Event::SelectionNotify(notify) = event {
                    if notify.requestor == self.window && notify.property == property_atom {
                        if notify.property == AtomEnum::NONE.into() {
                            return Err(anyhow::anyhow!("Selection conversion failed"));
                        }

                        let reply = self.conn.get_property(
                            true,
                            self.window,
                            property_atom,
                            AtomEnum::ANY,
                            0,
                            u32::MAX,
                        )?.reply()?;

                        return Ok(reply.value);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        Err(anyhow::anyhow!("Selection timeout"))
    }

    async fn add_entry(&mut self, entry: Entry) -> Result<()> {
        if self.config.blacklist.iter().any(|app| entry.app_name.contains(app)) {
            return Ok(());
        }

        let tx = self.db.transaction()?;
        
        let exists: bool = tx.query_row(
            "SELECT 1 FROM entries WHERE hash = ?1",
            params![entry.hash],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);

        if exists {
            tx.execute(
                "UPDATE entries SET timestamp = ?1 WHERE hash = ?2",
                params![entry.timestamp as i64, entry.hash],
            )?;
        } else {
            match &entry.content {
                ContentType::Text(text) => {
                    tx.execute(
                        "INSERT INTO entries (hash, timestamp, app_name, content_type, inline_text, size_bytes)
                         VALUES (?1, ?2, ?3, 'text', ?4, ?5)",
                        params![entry.hash, entry.timestamp as i64, entry.app_name, text, entry.size_bytes as i64],
                    )?;
                }
                ContentType::TextFile { hash, compressed } => {
                    let file_path = if *compressed {
                        format!("{}.txt.zst", hash)
                    } else {
                        format!("{}.txt", hash)
                    };
                    tx.execute(
                        "INSERT INTO entries (hash, timestamp, app_name, content_type, file_path, size_bytes, compressed)
                         VALUES (?1, ?2, ?3, 'text_file', ?4, ?5, ?6)",
                        params![entry.hash, entry.timestamp as i64, entry.app_name, file_path, entry.size_bytes as i64, *compressed as i64],
                    )?;
                }
                ContentType::Image { mime, hash } => {
                    tx.execute(
                        "INSERT INTO entries (hash, timestamp, app_name, content_type, file_path, mime_type, size_bytes)
                         VALUES (?1, ?2, ?3, 'image', ?4, ?5, ?6)",
                        params![entry.hash, entry.timestamp as i64, entry.app_name, hash, mime, entry.size_bytes as i64],
                    )?;
                }
            }
        }
        
        tx.commit()?;
        Ok(())
    }

    fn cleanup_old_entries(&mut self) -> Result<()> {
        let tx = self.db.transaction()?;
        
        let mut stmt = tx.prepare(
            "SELECT hash, file_path FROM entries
             WHERE id NOT IN (
                 SELECT id FROM entries ORDER BY timestamp DESC LIMIT ?1
             )"
        )?;

        let to_delete: Vec<(String, Option<String>)> = stmt.query_map(
            params![self.config.max_entries as i64],
            |row| Ok((row.get(0)?, row.get(1)?))
        )?.collect::<Result<Vec<_>, _>>()?;

        drop(stmt);

        for (hash, file_path) in &to_delete {
            if let Some(file_path) = file_path {
                let path = self.config.cache_dir.join("blobs").join(file_path);
                let _ = fs::remove_file(path);
            } else {
                let path = self.config.cache_dir.join("blobs").join(hash);
                let _ = fs::remove_file(path);
            }
        }

        tx.execute(
            "DELETE FROM entries WHERE id NOT IN (
                SELECT id FROM entries ORDER BY timestamp DESC LIMIT ?1
            )",
            params![self.config.max_entries as i64],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn print_history(&self) -> Result<()> {
        for entry in &self.config.static_entries {
            println!("{}", entry.replace('\n', " "));
        }

        let mut stmt = self.db.prepare(
            "SELECT hash, app_name, content_type, inline_text, file_path, mime_type, size_bytes
             FROM entries ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let rows = stmt.query_map([self.config.max_print_entries as i64], |row| {
            let hash: String = row.get(0)?;
            let app_name: String = row.get(1)?;
            let content_type: String = row.get(2)?;
            let inline_text: Option<String> = row.get(3)?;
            let file_path: Option<String> = row.get(4)?;
            let mime_type: Option<String> = row.get(5)?;
            let size_bytes: i64 = row.get(6)?;

            Ok((hash, app_name, content_type, inline_text, file_path, mime_type, size_bytes))
        })?;

        for row in rows {
            let (hash, _app_name, content_type, inline_text, file_path, mime_type, size_bytes) = row?;

            match content_type.as_str() {
                "text" => {
                    if let Some(text) = inline_text {
                        let display = if text.len() > self.config.max_display_length {
                            let mut end = self.config.max_display_length;
                            while !text.is_char_boundary(end) && end > 0 {
                                end -= 1;
                            }
                            format!("{}…", &text[..end])
                        } else {
                            text
                        };
                        println!("{}", display.replace('\n', " "));
                    }
                }
                "text_file" => {
                    // Try to read first part of the file for preview
                    if let Some(fp) = file_path {
                        let path = self.config.cache_dir.join("blobs").join(&fp);
                        let preview = if fp.ends_with(".zst") {
                            // Compressed file
                            use zstd::stream::read::Decoder;
                            if let Ok(file) = fs::File::open(&path) {
                                if let Ok(mut decoder) = Decoder::new(file) {
                                    let mut buffer = vec![0u8; 512];
                                    if let Ok(n) = std::io::Read::read(&mut decoder, &mut buffer) {
                                        String::from_utf8_lossy(&buffer[..n]).into_owned()
                                    } else {
                                        String::new()
                                    }
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            }
                        } else {
                            // Regular file - read first 512 bytes
                            fs::read(&path)
                                .ok()
                                .and_then(|data| {
                                    let len = data.len().min(512);
                                    String::from_utf8(data[..len].to_vec()).ok()
                                })
                                .unwrap_or_default()
                        };
                        
                        if !preview.is_empty() {
                            let display = if preview.len() > self.config.max_display_length {
                                let mut end = self.config.max_display_length;
                                while !preview.is_char_boundary(end) && end > 0 {
                                    end -= 1;
                                }
                                format!("{}…", &preview[..end])
                            } else {
                                preview
                            };
                            
                            let size_str = if size_bytes < 1024 {
                                format!("{}B", size_bytes)
                            } else {
                                format!("{}KB", size_bytes / 1024)
                            };
                            
                            println!("{} [{}]", display.replace('\n', " "), size_str);
                        } else {
                            // Fallback to hash display
                            if size_bytes < 1024 {
                                println!("[Text: {} bytes] {}", size_bytes, &hash[..HASH_PREFIX_LEN.min(hash.len())]);
                            } else {
                                println!("[Text: {} KB] {}", size_bytes / 1024, &hash[..HASH_PREFIX_LEN.min(hash.len())]);
                            }
                        }
                    }
                }
                "image" => {
                    println!("{} {} {}",
                        mime_type.unwrap_or_else(|| "image/unknown".to_string()),
                        _app_name,
                        hash
                    );
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn copy_selection(&mut self, selection: &str) -> Result<()> {
        if selection.starts_with("image/") {
            self.copy_image_selection(selection).await
        } else if selection.ends_with(']') && (selection.contains(" [") || selection.contains("B]") || selection.contains("KB]")) {
            // Handle new format: "preview text... [3KB]"
            if let Some(bracket_pos) = selection.rfind(" [") {
                let text_part = &selection[..bracket_pos];
                self.copy_text_selection(text_part).await
            } else {
                self.copy_text_selection(selection).await
            }
        } else if selection.starts_with("[Text:") {
            // Handle old format for backwards compatibility
            self.copy_large_text_selection(selection).await
        } else {
            self.copy_text_selection(selection).await
        }
    }

    async fn copy_text_selection(&self, text: &str) -> Result<()> {
        let text = text.replace(" ", "\n");
        let data = text.into_bytes();

        {
            let mut serving = self.serving_selection.write();
            *serving = Some(ClipboardTask::ServeText(data));
        }

        self.conn.set_selection_owner(self.window, self.atoms.clipboard, x11rb::CURRENT_TIME)?;
        self.conn.flush()?;

        Ok(())
    }

    async fn copy_large_text_selection(&self, selection: &str) -> Result<()> {
        // Extract hash from the selection format "[Text: X KB] hash_prefix"
        let hash_start = selection.rfind(' ').ok_or_else(|| anyhow::anyhow!("Invalid format"))?;
        let hash_prefix = &selection[hash_start + 1..];
        
        let row: (String, Option<bool>) = self.db.query_row(
            "SELECT file_path, compressed FROM entries WHERE hash LIKE ?1 || '%' ORDER BY timestamp DESC LIMIT 1",
            params![hash_prefix],
            |row| Ok((row.get(0)?, row.get::<_, Option<i64>>(1)?.map(|v| v != 0))),
        )?;

        let (file_path, compressed) = row;
        let path = self.config.cache_dir.join("blobs").join(&file_path);

        let mut text = if compressed.unwrap_or(false) {
            use zstd::stream::read::Decoder;
            let file = fs::File::open(path)?;
            let mut decoder = Decoder::new(file)?;
            let mut text = String::new();
            decoder.read_to_string(&mut text)?;
            text
        } else {
            fs::read_to_string(path)?
        };

        let data = text.as_bytes().to_vec();
        text.zeroize();

        {
            let mut serving = self.serving_selection.write();
            *serving = Some(ClipboardTask::ServeText(data));
        }

        self.conn.set_selection_owner(self.window, self.atoms.clipboard, x11rb::CURRENT_TIME)?;
        self.conn.flush()?;
        
        Ok(())
    }

    async fn copy_image_selection(&self, selection: &str) -> Result<()> {
        let parts: Vec<&str> = selection.split_whitespace().collect();
        if parts.len() < 3 {
            anyhow::bail!("Invalid image selection format");
        }

        let mime = parts[0].to_string();
        let hash = parts[2];

        let path = self.config.cache_dir.join("blobs").join(hash);
        let data = fs::read(&path).context("Failed to read image file")?;

        {
            let mut serving = self.serving_selection.write();
            *serving = Some(ClipboardTask::ServeImage { mime, data });
        }

        self.conn.set_selection_owner(self.window, self.atoms.clipboard, x11rb::CURRENT_TIME)?;
        self.conn.flush()?;

        Ok(())
    }

    async fn selection_server(
        conn: Arc<RustConnection>,
        window: Window,
        serving: Arc<RwLock<Option<ClipboardTask>>>,
        atoms: Atoms,
    ) {
        loop {
            if let Ok(Some(event)) = conn.poll_for_event() {
                match event {
                    Event::SelectionRequest(req) if req.owner == window => {
                        let task = {
                            let serving_guard = serving.read();
                            serving_guard.clone()
                        };
                        
                        if let Some(task) = task {
                            let _ = Self::handle_selection_request(&conn, &req, &task, &atoms).await;
                        }
                    }
                    Event::SelectionClear(clear) if clear.owner == window => {
                        // Don't clear the data, just note we lost ownership
                    }
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn handle_selection_request(
        conn: &Arc<RustConnection>,
        req: &SelectionRequestEvent,
        task: &ClipboardTask,
        atoms: &Atoms,
    ) -> Result<()> {
        let mut property = req.property;

        match task {
            ClipboardTask::ServeText(data) => {
                if req.target == atoms.targets {
                    let targets = [atoms.utf8_string, atoms.string, atoms.targets];
                    conn.change_property32(
                        PropMode::REPLACE,
                        req.requestor,
                        req.property,
                        AtomEnum::ATOM,
                        &targets,
                    )?;
                } else if req.target == atoms.utf8_string || req.target == atoms.string {
                    conn.change_property8(
                        PropMode::REPLACE,
                        req.requestor,
                        req.property,
                        req.target,
                        data,
                    )?;
                } else {
                    property = AtomEnum::NONE.into();
                }
            }
            ClipboardTask::ServeImage { mime, data } => {
                let mime_atom = conn.intern_atom(false, mime.as_bytes())?.reply()?.atom;

                if req.target == atoms.targets {
                    let targets = [mime_atom, atoms.targets];
                    conn.change_property32(
                        PropMode::REPLACE,
                        req.requestor,
                        req.property,
                        AtomEnum::ATOM,
                        &targets,
                    )?;
                } else if req.target == mime_atom {
                    conn.change_property8(
                        PropMode::REPLACE,
                        req.requestor,
                        req.property,
                        mime_atom,
                        data,
                    )?;
                } else {
                    property = AtomEnum::NONE.into();
                }
            }
        }

        let notify = SelectionNotifyEvent {
            response_type: x11rb::protocol::xproto::SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: req.time,
            requestor: req.requestor,
            selection: req.selection,
            target: req.target,
            property,
        };

        conn.send_event(false, req.requestor, EventMask::NO_EVENT, notify)?;
        conn.flush()?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        self.db.execute("DELETE FROM entries", [])?;

        let blobs_dir = self.config.cache_dir.join("blobs");
        if blobs_dir.exists() {
            for entry in fs::read_dir(&blobs_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    fs::remove_file(entry.path())?;
                }
            }
        }

        Ok(())
    }

    pub fn prune(&mut self, hashes: &[String]) -> Result<()> {
        for hash in hashes {
            let file_path: Option<String> = self.db.query_row(
                "SELECT file_path FROM entries WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            ).optional()?;

            self.db.execute("DELETE FROM entries WHERE hash = ?1", params![hash])?;

            if let Some(file_path) = file_path {
                let path = self.config.cache_dir.join("blobs").join(file_path);
                let _ = fs::remove_file(path);
            } else {
                let path = self.config.cache_dir.join("blobs").join(hash);
                let _ = fs::remove_file(path);
            }
        }

        Ok(())
    }
}
