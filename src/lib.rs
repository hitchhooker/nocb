use anyhow::{Context, Result};
use rusqlite::{params, Connection as SqliteConnection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::Event;
use x11rb::{connect, COPY_DEPTH_FROM_PARENT};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt;
use x11rb::protocol::xproto::ConnectionExt as XprotoConnectionExt;

const MAX_INLINE_SIZE: usize = 1024; // Store small content inline, large as files
const POLL_INTERVAL_MS: u64 = 50;
const X11_TIMEOUT_MS: u64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub cache_dir: PathBuf,
    pub max_entries: usize,
    pub use_primary: bool,
    pub blacklist: Vec<String>,
    pub trim_whitespace: bool,
    pub static_entries: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("nocb");
        
        Self {
            cache_dir,
            max_entries: 10000,
            use_primary: false,
            blacklist: Vec::new(),
            trim_whitespace: true,
            static_entries: Vec::new(),
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
            let content = toml::to_string_pretty(&config)?;
            fs::write(&config_path, content)?;
            Ok(config)
        }
    }
}

#[derive(Debug, Clone)]
pub enum ContentType {
    Text(String),        // Small text stored inline
    TextFile(String),    // Large text stored in file (hash as filename)
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
    fn new(content: ContentType, app_name: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (hash, size_bytes) = match &content {
            ContentType::Text(text) => {
                let mut hasher = DefaultHasher::new();
                text.hash(&mut hasher);
                (format!("{:016x}", hasher.finish()), text.len())
            }
            ContentType::TextFile(hash) | ContentType::Image { hash, .. } => {
                (hash.clone(), 0) // Size will be set separately
            }
        };

        Self {
            id: None,
            hash,
            timestamp,
            app_name,
            content,
            size_bytes,
        }
    }
}

#[derive(Debug, Clone)]
enum ClipboardTask {
    ServeText(Vec<u8>),
    ServeImage { mime: String, data: Vec<u8> },
}

pub struct ClipboardManager {
    config: Config,
    db: SqliteConnection,
    conn: Arc<RustConnection>,
    window: Window,
    last_clipboard_hash: Option<String>,
    last_primary_hash: Option<String>,
    seq_counter: AtomicU64,
    serving_selection: Arc<std::sync::Mutex<Option<ClipboardTask>>>,
}

impl ClipboardManager {
    pub async fn new(config: Config) -> Result<Self> {
        // Create directories
        fs::create_dir_all(&config.cache_dir)?;
        fs::create_dir_all(config.cache_dir.join("blobs"))?;
        
        // Open database
        let db_path = config.cache_dir.join("index.db");
        let db = SqliteConnection::open(&db_path)?;
        Self::init_db(&db)?;
        
        // Setup X11
        let (conn, screen_num) = connect(None).context("Failed to connect to X11")?;
        let conn = Arc::new(conn);
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

        let change_mask = EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY;
        conn.change_window_attributes(window, &ChangeWindowAttributesAux::new().event_mask(change_mask))?;
        conn.flush()?;

        Ok(Self {
            config,
            db,
            conn,
            window,
            last_clipboard_hash: None,
            last_primary_hash: None,
            seq_counter: AtomicU64::new(0),
            serving_selection: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    fn init_db(db: &SqliteConnection) -> Result<()> {
        db.execute(
            "CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                app_name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                file_path TEXT,
                inline_text TEXT,
                mime_type TEXT,
                size_bytes INTEGER NOT NULL,
                UNIQUE(hash)
            )",
            [],
        )?;

        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON entries(timestamp DESC)",
            [],
        )?;

        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_hash ON entries(hash)",
            [],
        )?;

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(POLL_INTERVAL_MS));
        
        // Spawn selection server task
        let conn_clone = self.conn.clone();
        let window = self.window;
        let serving_clone = self.serving_selection.clone();
        
        tokio::spawn(async move {
            Self::selection_server_loop(conn_clone, window, serving_clone).await;
        });
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.poll_clipboard().await {
                eprintln!("Poll error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Cleanup old entries periodically
            if self.seq_counter.load(Ordering::Relaxed) % 1000 == 0 {
                let _ = self.cleanup_old_entries();
            }
        }
    }

    async fn poll_clipboard(&mut self) -> Result<()> {
        // Check clipboard
        if let Some(entry) = self.get_clipboard_content("CLIPBOARD").await.unwrap_or(None) {
            if self.last_clipboard_hash.as_ref() != Some(&entry.hash) {
                self.add_entry(entry.clone()).await?;
                self.last_clipboard_hash = Some(entry.hash);
            }
        }

        // Check primary if enabled
        if self.config.use_primary {
            if let Some(entry) = self.get_clipboard_content("PRIMARY").await.unwrap_or(None) {
                if self.last_primary_hash.as_ref() != Some(&entry.hash) {
                    self.add_entry(entry.clone()).await?;
                    self.last_primary_hash = Some(entry.hash);
                }
            }
        }

        Ok(())
    }

    async fn get_clipboard_content(&self, selection: &str) -> Result<Option<Entry>> {
        let selection_atom = if selection == "PRIMARY" {
            AtomEnum::PRIMARY.into()
        } else {
            self.conn.intern_atom(false, selection.as_bytes())?.reply()?.atom
        };

        // Get app name
        let app_name = self.get_selection_owner_name(selection_atom).await
            .unwrap_or_else(|| "unknown".to_string());

        // Try images first
        for mime in &["image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp"] {
            if let Ok(data) = self.convert_selection_with_timeout(selection_atom, mime).await {
                if !data.is_empty() {
                    let hash = self.store_blob(&data)?;
                    let content = ContentType::Image {
                        mime: mime.to_string(),
                        hash: hash.clone(),
                    };
                    let mut entry = Entry::new(content, app_name);
                    entry.size_bytes = data.len();
                    return Ok(Some(entry));
                }
            }
        }

        // Try text
        for target in &["UTF8_STRING", "text/plain;charset=utf-8", "STRING", "TEXT"] {
            if let Ok(data) = self.convert_selection_with_timeout(selection_atom, target).await {
                if let Ok(text) = String::from_utf8(data) {
                    if !text.trim().is_empty() {
                        let text = if self.config.trim_whitespace {
                            text.trim().to_string()
                        } else {
                            text
                        };

                        let content = if text.len() <= MAX_INLINE_SIZE {
                            ContentType::Text(text.clone())
                        } else {
                            let hash = self.store_text_blob(&text)?;
                            ContentType::TextFile(hash)
                        };

                        let mut entry = Entry::new(content, app_name);
                        entry.size_bytes = text.len();
                        return Ok(Some(entry));
                    }
                }
            }
        }

        Ok(None)
    }

    fn store_blob(&self, data: &[u8]) -> Result<String> {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = format!("{:016x}", hasher.finish());
        
        let path = self.config.cache_dir.join("blobs").join(&hash);
        if !path.exists() {
            fs::write(&path, data)?;
        }
        
        Ok(hash)
    }

    fn store_text_blob(&self, text: &str) -> Result<String> {
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        let hash = format!("{:016x}", hasher.finish());
        
        let path = self.config.cache_dir.join("blobs").join(format!("{}.txt", hash));
        if !path.exists() {
            fs::write(&path, text)?;
        }
        
        Ok(hash)
    }

    async fn get_selection_owner_name(&self, selection: Atom) -> Option<String> {
        let owner = self.conn.get_selection_owner(selection).ok()?.reply().ok()?.owner;
        if owner == x11rb::NONE {
            return None;
        }

        let reply = self.conn.get_property(
            false, owner, AtomEnum::WM_NAME, AtomEnum::STRING, 0, 1024
        ).ok()?.reply().ok()?;

        String::from_utf8(reply.value).ok()
    }

    async fn convert_selection_with_timeout(&self, selection: Atom, target: &str) -> Result<Vec<u8>> {
        let timeout = tokio::time::timeout(
            Duration::from_millis(X11_TIMEOUT_MS),
            self.convert_selection(selection, target)
        );

        timeout.await.unwrap_or_else(|_| Err(anyhow::anyhow!("Selection timeout")))
    }

    async fn convert_selection(&self, selection: Atom, target: &str) -> Result<Vec<u8>> {
        let target_atom = self.conn.intern_atom(false, target.as_bytes())?.reply()?.atom;
        let property = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        let property_atom = self.conn.intern_atom(false, &format!("NOCB_{}", property).as_bytes())?.reply()?.atom;

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
                            false,
                            self.window,
                            property_atom,
                            AtomEnum::ANY,
                            0,
                            u32::MAX,
                        )?.reply()?;

                        self.conn.delete_property(self.window, property_atom)?;
                        return Ok(reply.value);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        Err(anyhow::anyhow!("Selection timeout"))
    }

    async fn add_entry(&mut self, entry: Entry) -> Result<()> {
        // Check blacklist
        if self.config.blacklist.iter().any(|app| entry.app_name.contains(app)) {
            return Ok(());
        }

        // Check if already exists
        let exists: bool = self.db.query_row(
            "SELECT 1 FROM entries WHERE hash = ?1",
            params![entry.hash],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);

        if exists {
            return Ok(());
        }

        // Insert into database
        match &entry.content {
            ContentType::Text(text) => {
                self.db.execute(
                    "INSERT INTO entries (hash, timestamp, app_name, content_type, inline_text, size_bytes)
                     VALUES (?1, ?2, ?3, 'text', ?4, ?5)",
                    params![entry.hash, entry.timestamp as i64, entry.app_name, text, entry.size_bytes as i64],
                )?;
            }
            ContentType::TextFile(hash) => {
                let file_path = format!("{}.txt", hash);
                self.db.execute(
                    "INSERT INTO entries (hash, timestamp, app_name, content_type, file_path, size_bytes)
                     VALUES (?1, ?2, ?3, 'text_file', ?4, ?5)",
                    params![entry.hash, entry.timestamp as i64, entry.app_name, file_path, entry.size_bytes as i64],
                )?;
            }
            ContentType::Image { mime, hash } => {
                self.db.execute(
                    "INSERT INTO entries (hash, timestamp, app_name, content_type, file_path, mime_type, size_bytes)
                     VALUES (?1, ?2, ?3, 'image', ?4, ?5, ?6)",
                    params![entry.hash, entry.timestamp as i64, entry.app_name, hash, mime, entry.size_bytes as i64],
                )?;
            }
        }

        Ok(())
    }

    fn cleanup_old_entries(&mut self) -> Result<()> {
        // Get hashes of entries to delete
        let mut stmt = self.db.prepare(
            "SELECT hash, file_path FROM entries 
             WHERE id NOT IN (
                 SELECT id FROM entries ORDER BY timestamp DESC LIMIT ?1
             )"
        )?;

        let to_delete: Vec<(String, Option<String>)> = stmt.query_map(
            params![self.config.max_entries as i64],
            |row| Ok((row.get(0)?, row.get(1)?))
        )?.collect::<Result<Vec<_>, _>>()?;

        // Delete files
        for (hash, file_path) in &to_delete {
            if let Some(file_path) = file_path {
                let path = self.config.cache_dir.join("blobs").join(file_path);
                let _ = fs::remove_file(path);
            } else {
                let path = self.config.cache_dir.join("blobs").join(hash);
                let _ = fs::remove_file(path);
            }
        }

        // Delete from database
        self.db.execute(
            "DELETE FROM entries WHERE id NOT IN (
                SELECT id FROM entries ORDER BY timestamp DESC LIMIT ?1
            )",
            params![self.config.max_entries as i64],
        )?;

        Ok(())
    }

    pub fn print_history(&self) -> Result<()> {
        // Print static entries first
        for entry in &self.config.static_entries {
            println!("{}", entry.replace('\n', "\u{00A0}"));
        }

        // Print database entries
        let mut stmt = self.db.prepare(
            "SELECT hash, app_name, content_type, inline_text, file_path, mime_type
             FROM entries ORDER BY timestamp DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            let hash: String = row.get(0)?;
            let app_name: String = row.get(1)?;
            let content_type: String = row.get(2)?;
            let inline_text: Option<String> = row.get(3)?;
            let file_path: Option<String> = row.get(4)?;
            let mime_type: Option<String> = row.get(5)?;
            
            Ok((hash, app_name, content_type, inline_text, file_path, mime_type))
        })?;

        for row in rows {
            let (hash, app_name, content_type, inline_text, file_path, mime_type) = row?;
            
            match content_type.as_str() {
                "text" => {
                    if let Some(text) = inline_text {
                        println!("{}", text.replace('\n', "\u{00A0}"));
                    }
                }
                "text_file" => {
                    if let Some(file_path) = file_path {
                        let path = self.config.cache_dir.join("blobs").join(file_path);
                        if let Ok(text) = fs::read_to_string(path) {
                            println!("{}", text.replace('\n', "\u{00A0}"));
                        }
                    }
                }
                "image" => {
                    println!("{} {} {}", 
                        mime_type.unwrap_or("image/unknown".to_string()), 
                        app_name, 
                        hash
                    );
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub async fn copy_selection(&mut self, selection: &str) -> Result<()> {
        if selection.starts_with("image/") {
            self.copy_image_selection(selection).await
        } else {
            self.copy_text_selection(selection).await
        }
    }

    async fn copy_text_selection(&self, text: &str) -> Result<()> {
        let text = text.replace('\u{00A0}', "\n");
        let data = text.into_bytes();
        
        // Set the task for the selection server
        {
            let mut serving = self.serving_selection.lock().unwrap();
            *serving = Some(ClipboardTask::ServeText(data));
        }
        
        // Take ownership of clipboard
        let clipboard_atom = self.conn.intern_atom(false, b"CLIPBOARD")?.reply()?.atom;
        self.conn.set_selection_owner(self.window, clipboard_atom, x11rb::CURRENT_TIME)?;
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
        
        // Set the task for the selection server
        {
            let mut serving = self.serving_selection.lock().unwrap();
            *serving = Some(ClipboardTask::ServeImage { mime, data });
        }
        
        // Take ownership of clipboard
        let clipboard_atom = self.conn.intern_atom(false, b"CLIPBOARD")?.reply()?.atom;
        self.conn.set_selection_owner(self.window, clipboard_atom, x11rb::CURRENT_TIME)?;
        self.conn.flush()?;

        Ok(())
    }

    async fn selection_server_loop(
        conn: Arc<RustConnection>,
        window: Window,
        serving: Arc<std::sync::Mutex<Option<ClipboardTask>>>,
    ) {
        loop {
            if let Ok(Some(event)) = conn.poll_for_event() {
                match event {
                    Event::SelectionRequest(req) if req.owner == window => {
                        // Clone the task to avoid holding the mutex across await
                        let task = {
                            let serving_guard = serving.lock().unwrap();
                            serving_guard.clone()
                        };
                        
                        if let Some(task) = task {
                            let _ = Self::handle_selection_request(&conn, &req, &task).await;
                        }
                    }
                    Event::SelectionClear(clear) if clear.owner == window => {
                        // Clear serving task when we lose ownership
                        if let Ok(mut serving_guard) = serving.lock() {
                            *serving_guard = None;
                        }
                    }
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn handle_selection_request(
        conn: &Arc<RustConnection>,
        req: &SelectionRequestEvent,
        task: &ClipboardTask,
    ) -> Result<()> {
        let targets_atom = conn.intern_atom(false, b"TARGETS")?.reply()?.atom;
        let mut property = req.property;

        match task {
            ClipboardTask::ServeText(data) => {
                let utf8_atom = conn.intern_atom(false, b"UTF8_STRING")?.reply()?.atom;
                let string_atom = conn.intern_atom(false, b"STRING")?.reply()?.atom;

                if req.target == targets_atom {
                    let targets = [utf8_atom, string_atom, targets_atom];
                    conn.change_property32(
                        PropMode::REPLACE,
                        req.requestor,
                        req.property,
                        AtomEnum::ATOM,
                        &targets,
                    )?;
                } else if req.target == utf8_atom || req.target == string_atom {
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

                if req.target == targets_atom {
                    let targets = [mime_atom, targets_atom];
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

        // Send selection notify
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
        // Clear database
        self.db.execute("DELETE FROM entries", [])?;
        
        // Clear blob directory
        let blobs_dir = self.config.cache_dir.join("blobs");
        if blobs_dir.exists() {
            for entry in fs::read_dir(&blobs_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    fs::remove_file(entry.path()).ok();
                }
            }
        }

        Ok(())
    }

    pub fn prune(&mut self, hashes: &[String]) -> Result<()> {
        for hash in hashes {
            // Get file path before deletion
            let file_path: Option<String> = self.db.query_row(
                "SELECT file_path FROM entries WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            ).optional()?;

            // Delete from database
            self.db.execute("DELETE FROM entries WHERE hash = ?1", params![hash])?;

            // Delete file
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
