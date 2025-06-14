use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use blake3::Hasher;
use lru::LruCache;
use parking_lot::RwLock;
use rusqlite::{params, Connection as SqliteConnection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use zeroize::Zeroize;

const MAX_INLINE_SIZE: usize = 512;
const POLL_INTERVAL_MS: u64 = 100;
const HASH_PREFIX_LEN: usize = 8;
const MAX_CLIPBOARD_SIZE: usize = 100 * 1024 * 1024; // 100MB
const MAX_IPC_MESSAGE_SIZE: usize = 4096;
const IPC_MAGIC: &[u8] = b"NOCB\x00\x01";
const LRU_CACHE_SIZE: usize = 16; // Only cache recent entries

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub cache_dir: PathBuf,
    pub max_entries: usize,
    pub max_display_length: usize,
    pub max_print_entries: usize,
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

#[derive(Debug)]
pub enum Command {
    Copy(String),
    Exit,
}

// Internal enum for clipboard content
enum ClipboardContent<'a> {
    Text(String),
    Image(ImageData<'a>),
}

// Cached entry data
#[derive(Clone)]
struct CachedEntry {
    exists_in_db: bool,
}

pub struct ClipboardManager {
    config: Config,
    db: SqliteConnection,
    clipboard: Arc<RwLock<Clipboard>>,
    last_clipboard_hash: Option<String>,
    command_rx: Option<mpsc::Receiver<Command>>,
    // LRU cache for recent entries
    lru_cache: Arc<RwLock<LruCache<String, CachedEntry>>>,
}

impl ClipboardManager {
    pub async fn new(config: Config) -> Result<Self> {
        fs::create_dir_all(&config.cache_dir)?;
        fs::create_dir_all(config.cache_dir.join("blobs"))?;

        let db_path = config.cache_dir.join("index.db");
        let db = SqliteConnection::open(&db_path)?;
        Self::init_db(&db)?;

        let clipboard = Clipboard::new()
            .context("Failed to initialize clipboard")?;

        // Create LRU cache
        let lru_cache = LruCache::new(NonZeroUsize::new(LRU_CACHE_SIZE).unwrap());

        Ok(Self {
            config,
            db,
            clipboard: Arc::new(RwLock::new(clipboard)),
            last_clipboard_hash: None,
            command_rx: None,
            lru_cache: Arc::new(RwLock::new(lru_cache)),
        })
    }

    fn init_db(db: &SqliteConnection) -> Result<()> {
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000;
             PRAGMA mmap_size = 268435456;
             PRAGMA temp_store = MEMORY;"
        )?;
        
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
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
        
        let has_compressed: bool = db.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='compressed'",
            [],
            |row| row.get::<_, i64>(0).map(|count| count > 0)
        )?;
        
        if !has_compressed {
            db.execute("ALTER TABLE entries ADD COLUMN compressed INTEGER DEFAULT 0", [])?;
        }
        
        Ok(())
    }

    pub async fn run_daemon(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel(10);
        self.command_rx = Some(rx);

        let sock_path = std::env::temp_dir().join("nocb.sock");

        let tx_clone = tx.clone();
        let sock_path_clone = sock_path.clone();

        let ipc_handle = tokio::spawn(async move {
            let result = Self::ipc_server(tx_clone, sock_path_clone.clone()).await;
            let _ = std::fs::remove_file(&sock_path_clone);
            result
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

        let _ = std::fs::remove_file(&sock_path);
        ipc_handle.abort();

        Ok(())
    }

    async fn ipc_server(tx: mpsc::Sender<Command>, sock_path: PathBuf) -> Result<()> {
        use tokio::net::UnixListener;

        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path)?;
        
        // Set socket permissions to user-only (0700)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&sock_path, perms)?;
        }

        loop {
            let (mut stream, _addr) = listener.accept().await?;

            #[cfg(target_os = "linux")]
            {
                match stream.peer_cred() {
                    Ok(cred) => {
                        let current_uid = unsafe { libc::getuid() };
                        if cred.uid() != current_uid {
                            eprintln!("IPC rejected: different UID ({} != {})", cred.uid(), current_uid);
                            continue;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to get peer credentials: {}", e);
                        continue;
                    }
                }
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
        use tokio::time::timeout;
        
        let sock_path = std::env::temp_dir().join("nocb.sock");
        
        let mut stream = timeout(
            Duration::from_secs(2),
            UnixStream::connect(&sock_path)
        ).await
        .context("Connection timeout")?
        .context("Failed to connect to daemon")?;
        
        let mut msg = Vec::with_capacity(IPC_MAGIC.len() + 5 + selection.len());
        msg.extend_from_slice(IPC_MAGIC);
        msg.extend_from_slice(format!("COPY:{}", selection).as_bytes());
        
        stream.write_all(&msg).await?;
        stream.shutdown().await?;
        Ok(())
    }

    async fn poll_clipboard(&mut self) -> Result<()> {
        // Try to get clipboard content without blocking
        let content = {
            match self.clipboard.try_write() {
                Some(mut clipboard) => {
                    // Try to get text first
                    if let Ok(text) = clipboard.get_text() {
                        Some(ClipboardContent::Text(text))
                    } else if let Ok(img) = clipboard.get_image() {
                        Some(ClipboardContent::Image(img))
                    } else {
                        None
                    }
                },
                None => return Ok(()), // Skip this poll if clipboard is busy
            }
        };

        if let Some(content) = content {
            let entry = match content {
                ClipboardContent::Text(text) => {
                    if text.trim().is_empty() && self.config.trim_whitespace {
                        return Ok(());
                    }

                    let text = if self.config.trim_whitespace {
                        text.trim().to_string()
                    } else {
                        text
                    };

                    let hash = self.hash_data(text.as_bytes());
                    
                    // Quick check against last hash
                    if self.last_clipboard_hash.as_ref() == Some(&hash) {
                        return Ok(());
                    }
                    
                    // Check if already exists (LRU cache, then DB)
                    if self.entry_exists(&hash)? {
                        self.last_clipboard_hash = Some(hash);
                        return Ok(());
                    }

                    let size = text.len();
                    if size > MAX_CLIPBOARD_SIZE {
                        return Ok(());
                    }

                    let content = if size <= MAX_INLINE_SIZE {
                        ContentType::Text(text)
                    } else {
                        let compressed = size > self.config.compress_threshold;
                        let stored_hash = self.store_text_blob(&hash, &text, compressed)?;
                        ContentType::TextFile { hash: stored_hash, compressed }
                    };

                    Some(Entry::new(content, "unknown".to_string(), hash, size))
                }
                ClipboardContent::Image(img) => {
                    let data = self.image_to_png(&img)?;
                    let hash = self.hash_data(&data);
                    
                    if self.last_clipboard_hash.as_ref() == Some(&hash) {
                        return Ok(());
                    }
                    
                    // Check if already exists
                    if self.entry_exists(&hash)? {
                        self.last_clipboard_hash = Some(hash);
                        return Ok(());
                    }

                    if data.len() > MAX_CLIPBOARD_SIZE {
                        return Ok(());
                    }

                    let stored_hash = self.store_blob(&hash, &data)?;
                    let content = ContentType::Image {
                        mime: "image/png".to_string(),
                        hash: stored_hash.clone(),
                    };

                    Some(Entry::new(content, "unknown".to_string(), stored_hash, data.len()))
                }
            };

            if let Some(entry) = entry {
                self.last_clipboard_hash = Some(entry.hash.clone());
                self.add_entry(entry).await?;
            }
        } else {
            self.last_clipboard_hash = None;
        }

        Ok(())
    }

    // Optimized entry existence check with LRU cache
    fn entry_exists(&self, hash: &str) -> Result<bool> {
        // First check LRU cache
        {
            let mut cache = self.lru_cache.write();
            if let Some(cached) = cache.get(hash) {
                if cached.exists_in_db {
                    // Update timestamp in DB since it's being accessed again
                    let _ = self.db.execute(
                        "UPDATE entries SET timestamp = ?1 WHERE hash = ?2",
                        params![SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64, hash],
                    );
                }
                return Ok(cached.exists_in_db);
            }
        }
        
        // Not in cache, check DB
        let exists: bool = self.db.query_row(
            "SELECT 1 FROM entries WHERE hash = ?1",
            params![hash],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        // Add to cache
        {
            let mut cache = self.lru_cache.write();
            cache.put(hash.to_string(), CachedEntry {
                exists_in_db: exists,
            });
        }
        
        Ok(exists)
    }

    fn image_to_png(&self, img: &ImageData) -> Result<Vec<u8>> {
        use image::{ImageBuffer, Rgba};
        
        let width = img.width as u32;
        let height = img.height as u32;
        
        let img_buffer = ImageBuffer::<Rgba<u8>, Vec<u8>>::from_raw(
            width,
            height,
            img.bytes.to_vec()
        ).context("Failed to create image buffer")?;
        
        let mut png_data = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut png_data);
        image::ImageEncoder::write_image(
            encoder,
            &img_buffer,
            width,
            height,
            image::ColorType::Rgba8
        )?;
        
        Ok(png_data)
    }

    fn hash_data(&self, data: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().to_hex().to_string()
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

    async fn add_entry(&mut self, entry: Entry) -> Result<()> {
        if self.config.blacklist.iter().any(|app| entry.app_name.contains(app)) {
            return Ok(());
        }

        // Add to LRU cache immediately
        {
            let mut cache = self.lru_cache.write();
            cache.put(entry.hash.clone(), CachedEntry {
                exists_in_db: true,
            });
        }

        // Add to DB
        match &entry.content {
            ContentType::Text(text) => {
                self.db.execute(
                    "INSERT OR REPLACE INTO entries (hash, timestamp, app_name, content_type, inline_text, size_bytes)
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
                self.db.execute(
                    "INSERT OR REPLACE INTO entries (hash, timestamp, app_name, content_type, file_path, size_bytes, compressed)
                     VALUES (?1, ?2, ?3, 'text_file', ?4, ?5, ?6)",
                    params![entry.hash, entry.timestamp as i64, entry.app_name, file_path, entry.size_bytes as i64, *compressed as i64],
                )?;
            }
            ContentType::Image { mime, hash } => {
                self.db.execute(
                    "INSERT OR REPLACE INTO entries (hash, timestamp, app_name, content_type, file_path, mime_type, size_bytes)
                     VALUES (?1, ?2, ?3, 'image', ?4, ?5, ?6)",
                    params![entry.hash, entry.timestamp as i64, entry.app_name, hash, mime, entry.size_bytes as i64],
                )?;
            }
        }
        
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

    // Helper methods for cleaner code
    fn read_text_preview(&self, file_path: &str, max_len: usize) -> Option<String> {
        let path = self.config.cache_dir.join("blobs").join(file_path);
        
        if file_path.ends_with(".zst") {
            self.read_compressed_preview(&path, max_len)
        } else {
            self.read_plain_preview(&path, max_len)
        }
    }

    fn read_compressed_preview(&self, path: &Path, max_len: usize) -> Option<String> {
        use zstd::stream::read::Decoder;
        
        let file = fs::File::open(path).ok()?;
        let mut decoder = Decoder::new(file).ok()?;
        let mut buffer = vec![0u8; max_len * 4]; // UTF-8 can be up to 4 bytes per char
        let n = std::io::Read::read(&mut decoder, &mut buffer).ok()?;
        
        String::from_utf8(buffer[..n].to_vec()).ok()
    }

    fn read_plain_preview(&self, path: &Path, max_len: usize) -> Option<String> {
        let data = fs::read(path).ok()?;
        let len = data.len().min(max_len * 4);
        String::from_utf8(data[..len].to_vec()).ok()
    }

    fn format_time_ago(&self, timestamp: i64) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ago_secs = now.saturating_sub(timestamp as u64);
        
        if ago_secs < 60 {
            format!("-{}s", ago_secs)
        } else if ago_secs < 3600 {
            format!("-{}m", ago_secs / 60)
        } else if ago_secs < 86400 {
            format!("-{}h", ago_secs / 3600)
        } else {
            format!("-{}d", ago_secs / 86400)
        }
    }

    fn format_size(&self, bytes: i64) -> String {
        if bytes < 1024 {
            format!("{}B", bytes)
        } else {
            format!("{}KB", bytes / 1024)
        }
    }

    fn truncate_display(&self, text: &str) -> String {
        if text.len() > self.config.max_display_length {
            let mut end = self.config.max_display_length;
            while !text.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}…", &text[..end])
        } else {
            text.to_string()
        }
    }

    pub fn print_history(&self) -> Result<()> {
        // Print static entries
        for entry in &self.config.static_entries {
            println!("{}", entry.replace('\n', " "));
        }

        let mut stmt = self.db.prepare(
            "SELECT hash, app_name, content_type, inline_text, file_path, mime_type, size_bytes, timestamp
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
            let timestamp: i64 = row.get(7)?;

            Ok((hash, app_name, content_type, inline_text, file_path, mime_type, size_bytes, timestamp))
        })?;

        for row in rows {
            let (hash, app_name, content_type, inline_text, file_path, mime_type, size_bytes, timestamp) = row?;
            let time_str = self.format_time_ago(timestamp);

            match content_type.as_str() {
                "text" => {
                    if let Some(text) = inline_text {
                        let display = self.truncate_display(&text);
                        println!("{} {}", time_str, display.replace('\n', " "));
                    }
                }
                "text_file" => {
                    if let Some(fp) = file_path {
                        let preview = self.read_text_preview(&fp, self.config.max_display_length)
                            .map(|p| self.truncate_display(&p))
                            .filter(|p| !p.is_empty());

                        if let Some(display) = preview {
                            let size_str = self.format_size(size_bytes);
                            println!("{} {} [{}]", time_str, display.replace('\n', " "), size_str);
                        } else {
                            // Fallback: show hash if can't read file
                            println!("{} [Text: {}] {}", 
                                time_str, 
                                self.format_size(size_bytes),
                                &hash[..HASH_PREFIX_LEN.min(hash.len())]
                            );
                        }
                    }
                }
                "image" => {
                    let mime = mime_type.unwrap_or_else(|| "image/unknown".to_string());
                    println!("{} {} {} {}", time_str, mime, app_name, hash);
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn copy_selection(&mut self, selection: &str) -> Result<()> {
        // Strip timestamp prefix (-5m, -2h, -3d, -10s) at the beginning
        let selection = if selection.starts_with("-") {
            if let Some(space_pos) = selection.find(' ') {
                let timestamp_part = &selection[1..space_pos];
                // Check if it's a valid timestamp format
                let is_timestamp = timestamp_part.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .count() > 0
                    && timestamp_part.chars()
                        .skip_while(|c| c.is_ascii_digit())
                        .all(|c| matches!(c, 's' | 'm' | 'h' | 'd'));
                
                if is_timestamp {
                    selection[space_pos + 1..].trim()
                } else {
                    selection
                }
            } else {
                selection
            }
        } else {
            selection
        };
        
        if selection.starts_with("image/") {
            self.copy_image_selection(selection).await
        } else if selection.starts_with("[Text:") && selection.contains(']') {
            // Large text file format: [Text: SIZE] HASH
            self.copy_large_text_selection(selection).await
        } else if selection.ends_with(']') && selection.contains(" [") {
            // Text with size indicator: TEXT [SIZE]
            if let Some(bracket_pos) = selection.rfind(" [") {
                let text_part = &selection[..bracket_pos];
                self.copy_text_selection(text_part).await
            } else {
                self.copy_text_selection(selection).await
            }
        } else {
            // Regular text
            self.copy_text_selection(selection).await
        }
    }

    async fn copy_text_selection(&self, text: &str) -> Result<()> {
        // Copy text as-is, no modifications
        let mut clipboard = self.clipboard.write();
        clipboard.set_text(text.to_string())?;
        Ok(())
    }

    async fn copy_large_text_selection(&self, selection: &str) -> Result<()> {
        // Format: [Text: SIZE] HASH
        // Find the closing bracket and extract hash after it
        if let Some(bracket_pos) = selection.find(']') {
            let hash_part = selection[bracket_pos + 1..].trim();
            if !hash_part.is_empty() {
                let row: (String, Option<bool>) = self.db.query_row(
                    "SELECT file_path, compressed FROM entries WHERE hash LIKE ?1 || '%' ORDER BY timestamp DESC LIMIT 1",
                    params![hash_part],
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

                let mut clipboard = self.clipboard.write();
                clipboard.set_text(text.clone())?;
                
                text.zeroize();
            }
        }
        
        Ok(())
    }

    async fn copy_image_selection(&self, selection: &str) -> Result<()> {
        // Format: image/TYPE APP_NAME HASH
        let parts: Vec<&str> = selection.split_whitespace().collect();
        if parts.len() < 3 {
            anyhow::bail!("Invalid image selection format");
        }

        let hash = parts[2];

        let path = self.config.cache_dir.join("blobs").join(hash);
        let data = fs::read(&path).context("Failed to read image file")?;

        // Decode PNG to raw RGBA
        let img = image::load_from_memory(&data)?;
        let rgba = img.to_rgba8();
        let (width, height) = (rgba.width() as usize, rgba.height() as usize);
        
        let img_data = ImageData {
            width,
            height,
            bytes: rgba.into_raw().into(),
        };

        let mut clipboard = self.clipboard.write();
        clipboard.set_image(img_data)?;

        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        self.db.execute("DELETE FROM entries", [])?;

        // Clear the LRU cache
        {
            let mut cache = self.lru_cache.write();
            cache.clear();
        }

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
