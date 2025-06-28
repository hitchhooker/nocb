use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use blake3::Hasher;
use lru::LruCache;
use parking_lot::RwLock;
use rusqlite::{Connection as SqliteConnection, OptionalExtension, params};
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
const LRU_CACHE_SIZE: usize = 64;

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
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
}

fn default_max_age_days() -> u32 {
    30
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
            max_age_days: 30,
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
    TextFile {
        hash: String,
        compressed: bool,
    },
    Image {
        mime: String,
        hash: String,
        width: u32,
        height: u32,
    },
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
    Clear,
    Prune(Vec<String>),
}

// Internal enum for clipboard content
enum ClipboardContent<'a> {
    Text(String),
    Image(ImageData<'a>),
}

// Complete cached entry with all display data
#[derive(Clone)]
struct CachedEntry {
    content_type: String,
    inline_text: Option<String>,
    file_path: Option<String>,
    compressed: bool,
    size_bytes: usize,
    timestamp: i64,
    mime_type: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
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

        let clipboard = Clipboard::new().context("Failed to initialize clipboard")?;

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
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;",
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
                compressed INTEGER DEFAULT 0,
                width INTEGER,
                height INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_timestamp ON entries(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_hash ON entries(hash);",
        )?;

        // schema migration for existing databases
        let has_compressed: bool = db.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='compressed'",
            [],
            |row| row.get::<_, i64>(0).map(|count| count > 0),
        )?;

        if !has_compressed {
            db.execute(
                "ALTER TABLE entries ADD COLUMN compressed INTEGER DEFAULT 0",
                [],
            )?;
        }

        let has_width: bool = db.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='width'",
            [],
            |row| row.get::<_, i64>(0).map(|count| count > 0),
        )?;

        if !has_width {
            db.execute("ALTER TABLE entries ADD COLUMN width INTEGER", [])?;
            db.execute("ALTER TABLE entries ADD COLUMN height INTEGER", [])?;
        }

        Ok(())
    }

    pub async fn run_daemon(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel(10);
        self.command_rx = Some(rx);

        #[cfg(unix)]
        let sock_path = std::env::temp_dir().join("nocb.sock");

        #[cfg(windows)]
        let sock_path = PathBuf::from(r"\\.\pipe\nocb");

        let tx_clone = tx.clone();
        let sock_path_clone = sock_path.clone();

        let ipc_handle = tokio::spawn(async move {
            let result = Self::ipc_server(tx_clone, sock_path_clone.clone()).await;
            #[cfg(unix)]
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
                    // Run cleanup every ~100 seconds
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
                            Command::Clear => {
                                if let Err(e) = self.clear() {
                                    eprintln!("Clear error: {}", e);
                                }
                            }
                            Command::Prune(hashes) => {
                                if let Err(e) = self.prune(&hashes) {
                                    eprintln!("Prune error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        let _ = std::fs::remove_file(&sock_path);

        ipc_handle.abort();

        Ok(())
    }

    async fn ipc_server(tx: mpsc::Sender<Command>, sock_path: PathBuf) -> Result<()> {
        let _ = std::fs::remove_file(&sock_path);

        #[cfg(unix)]
        {
            use tokio::net::UnixListener;

            let listener = UnixListener::bind(&sock_path)?;

            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&sock_path, perms)?;

            loop {
                let (mut stream, _addr) = listener.accept().await?;

                // Simple UID check on Linux
                #[cfg(target_os = "linux")]
                {
                    match stream.peer_cred() {
                        Ok(cred) => {
                            let current_uid = unsafe { libc::getuid() };
                            if cred.uid() != current_uid {
                                continue;
                            }
                        }
                        Err(_) => continue,
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
                                } else if cmd == "CLEAR" {
                                    let _ = tx.send(Command::Clear).await;
                                } else if cmd.starts_with("PRUNE:") {
                                    let hashes_str = cmd[6..].to_string();
                                    let hashes: Vec<String> = hashes_str
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                    let _ = tx.send(Command::Prune(hashes)).await;
                                } else if cmd == "CLEAR" {
                                    let _ = tx.send(Command::Clear).await;
                                } else if cmd.starts_with("PRUNE:") {
                                    let hashes_str = cmd[6..].to_string();
                                    let hashes: Vec<String> = hashes_str
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                    let _ = tx.send(Command::Prune(hashes)).await;
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

        #[cfg(windows)]
        {
            use tokio::io::AsyncReadExt;
            use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

            let pipe_name = r"\\.\pipe\nocb";

            loop {
                let mut server = ServerOptions::new()
                    .first_pipe_instance(true)
                    .pipe_mode(PipeMode::Message)
                    .create(pipe_name)?;

                server.connect().await?;
                let tx = tx.clone();

                tokio::spawn(async move {
                    let mut buf = vec![0u8; MAX_IPC_MESSAGE_SIZE];

                    match server.read(&mut buf).await {
                        Ok(n) if n > IPC_MAGIC.len() => {
                            if &buf[..IPC_MAGIC.len()] != IPC_MAGIC {
                                return;
                            }

                            if let Ok(cmd) = String::from_utf8(buf[IPC_MAGIC.len()..n].to_vec()) {
                                let cmd = cmd.trim();
                                if cmd.starts_with("COPY:") {
                                } else if cmd == "CLEAR" {
                                    let _ = tx.send(Command::Clear).await;
                                } else if cmd.starts_with("PRUNE:") {
                                    let hashes_str = cmd[6..].to_string();
                                    let hashes: Vec<String> = hashes_str
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                    let _ = tx.send(Command::Prune(hashes)).await;
                                } else if cmd == "CLEAR" {
                                    let _ = tx.send(Command::Clear).await;
                                } else if cmd.starts_with("PRUNE:") {
                                    let hashes_str = cmd[6..].to_string();
                                    let hashes: Vec<String> = hashes_str
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                    let _ = tx.send(Command::Prune(hashes)).await;
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
    }

    pub async fn send_copy_command(selection: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::time::timeout;

        #[cfg(unix)]
        {
            use tokio::net::UnixStream;

            let sock_path = std::env::temp_dir().join("nocb.sock");

            let mut stream = timeout(Duration::from_secs(2), UnixStream::connect(&sock_path))
                .await
                .context("Connection timeout")?
                .context("Failed to connect to daemon")?;

            let mut msg = Vec::with_capacity(IPC_MAGIC.len() + 5 + selection.len());
            msg.extend_from_slice(IPC_MAGIC);
            msg.extend_from_slice(format!("COPY:{}", selection).as_bytes());

            stream.write_all(&msg).await?;
            stream.shutdown().await?;
        }

        #[cfg(windows)]
        {
            use tokio::io::AsyncWriteExt;
            use tokio::net::windows::named_pipe::ClientOptions;

            let pipe_name = r"\\.\pipe\nocb";

            let mut client = ClientOptions::new().open(pipe_name)?;

            let mut msg = Vec::with_capacity(IPC_MAGIC.len() + 5 + selection.len());
            msg.extend_from_slice(IPC_MAGIC);
            msg.extend_from_slice(format!("COPY:{}", selection).as_bytes());

            timeout(Duration::from_secs(2), client.write_all(&msg))
                .await
                .context("Write timeout")?
                .context("Failed to write to pipe")?;
        }

        Ok(())
    }
    pub async fn send_command(cmd: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::time::timeout;

        #[cfg(unix)]
        {
            use tokio::net::UnixStream;
            let sock_path = std::env::temp_dir().join("nocb.sock");
            let mut stream = timeout(Duration::from_secs(2), UnixStream::connect(&sock_path))
                .await
                .context("Connection timeout")?
                .context("Failed to connect to daemon")?;

            let mut msg = Vec::with_capacity(IPC_MAGIC.len() + cmd.len());
            msg.extend_from_slice(IPC_MAGIC);
            msg.extend_from_slice(cmd.as_bytes());
            stream.write_all(&msg).await?;
            stream.shutdown().await?;
        }
        #[cfg(windows)]
        {
            unimplemented!("Windows support pending");
        }

        Ok(())
    }

    async fn poll_clipboard(&mut self) -> Result<()> {
        // non-blocking clipboard check
        let content = {
            match self.clipboard.try_write() {
                Some(mut clipboard) => {
                    if let Ok(text) = clipboard.get_text() {
                        Some(ClipboardContent::Text(text))
                    } else if let Ok(img) = clipboard.get_image() {
                        Some(ClipboardContent::Image(img))
                    } else {
                        None
                    }
                }
                None => return Ok(()),
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

                    if self.last_clipboard_hash.as_ref() == Some(&hash) {
                        return Ok(());
                    }

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
                        ContentType::TextFile {
                            hash: stored_hash,
                            compressed,
                        }
                    };

                    Some(Entry::new(content, "unknown".to_string(), hash, size))
                }
                ClipboardContent::Image(img) => {
                    let (width, height) = (img.width as u32, img.height as u32);
                    let data = self.image_to_png(&img)?;
                    let hash = self.hash_data(&data);

                    if self.last_clipboard_hash.as_ref() == Some(&hash) {
                        return Ok(());
                    }

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
                        width,
                        height,
                    };

                    Some(Entry::new(
                        content,
                        "unknown".to_string(),
                        stored_hash,
                        data.len(),
                    ))
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

    // check cache first, then database
    fn entry_exists(&self, hash: &str) -> Result<bool> {
        {
            let cache = self.lru_cache.read();
            if cache.contains(hash) {
                // update access time
                let _ = self.db.execute(
                    "UPDATE entries SET timestamp = ?1 WHERE hash = ?2",
                    params![
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                        hash
                    ],
                );
                return Ok(true);
            }
        }

        let exists: bool = self
            .db
            .query_row(
                "SELECT 1 FROM entries WHERE hash = ?1",
                params![hash],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        Ok(exists)
    }

    fn image_to_png(&self, img: &ImageData) -> Result<Vec<u8>> {
        use image::{ImageBuffer, Rgba};

        let width = img.width as u32;
        let height = img.height as u32;

        let img_buffer =
            ImageBuffer::<Rgba<u8>, Vec<u8>>::from_raw(width, height, img.bytes.to_vec())
                .context("Failed to create image buffer")?;

        let mut png_data = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut png_data);
        image::ImageEncoder::write_image(
            encoder,
            &img_buffer,
            width,
            height,
            image::ExtendedColorType::Rgba8,
        )?;

        Ok(png_data)
    }

    fn hash_data(&self, data: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().to_hex().to_string()
    }

    fn store_blob(&self, hash: &str, data: &[u8]) -> Result<String> {
        if hash.contains('/') || hash.contains('\\') || hash.contains("..") {
            anyhow::bail!("Invalid hash");
        }
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
        if self
            .config
            .blacklist
            .iter()
            .any(|app| entry.app_name.contains(app))
        {
            return Ok(());
        }

        let timestamp = entry.timestamp as i64;
        let cached_entry = match &entry.content {
            ContentType::Text(text) => {
                self.db.execute(
                    "INSERT OR REPLACE INTO entries (hash, timestamp, app_name, content_type, inline_text, size_bytes)
                     VALUES (?1, ?2, ?3, 'text', ?4, ?5)",
                    params![entry.hash, timestamp, entry.app_name, text, entry.size_bytes as i64],
                )?;

                CachedEntry {
                    content_type: "text".to_string(),
                    inline_text: Some(text.clone()),
                    file_path: None,
                    compressed: false,
                    size_bytes: entry.size_bytes,
                    timestamp,
                    mime_type: None,
                    width: None,
                    height: None,
                }
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
                    params![entry.hash, timestamp, entry.app_name, file_path, entry.size_bytes as i64, *compressed as i64],
                )?;

                CachedEntry {
                    content_type: "text_file".to_string(),
                    inline_text: None,
                    file_path: Some(file_path),
                    compressed: *compressed,
                    size_bytes: entry.size_bytes,
                    timestamp,
                    mime_type: None,
                    width: None,
                    height: None,
                }
            }
            ContentType::Image {
                mime,
                hash,
                width,
                height,
            } => {
                self.db.execute(
                    "INSERT OR REPLACE INTO entries (hash, timestamp, app_name, content_type, file_path, mime_type, size_bytes, width, height)
                     VALUES (?1, ?2, ?3, 'image', ?4, ?5, ?6, ?7, ?8)",
                    params![entry.hash, timestamp, entry.app_name, hash, mime, entry.size_bytes as i64, *width as i64, *height as i64],
                )?;

                CachedEntry {
                    content_type: "image".to_string(),
                    inline_text: None,
                    file_path: Some(hash.clone()),
                    compressed: false,
                    size_bytes: entry.size_bytes,
                    timestamp,
                    mime_type: Some(mime.clone()),
                    width: Some(*width),
                    height: Some(*height),
                }
            }
        };

        // Add to cache
        let mut cache = self.lru_cache.write();
        cache.put(entry.hash.clone(), cached_entry);

        Ok(())
    }

    fn cleanup_old_entries(&mut self) -> Result<()> {
        // Clean by max entries
        let mut stmt = self.db.prepare(
            "SELECT hash FROM entries 
             WHERE id NOT IN (
                 SELECT id FROM entries ORDER BY timestamp DESC LIMIT ?1
             )",
        )?;

        let hashes_to_delete: Vec<String> = stmt
            .query_map(params![self.config.max_entries as i64], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        drop(stmt);

        // Clean by age
        let cutoff = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            - (self.config.max_age_days as u64 * 86400);

        let mut stmt = self
            .db
            .prepare("SELECT hash FROM entries WHERE timestamp < ?1")?;

        let old_hashes: Vec<String> = stmt
            .query_map(params![cutoff as i64], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        drop(stmt);

        // Delete all collected hashes
        for hash in hashes_to_delete.into_iter().chain(old_hashes) {
            self.delete_entry(&hash)?;
        }

        // VACUUM occasionally (every 100 cleanups)
        static VACUUM_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if VACUUM_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 100 == 0 {
            let _ = self.db.execute("VACUUM", []);
        }

        Ok(())
    }

    fn delete_entry(&mut self, hash: &str) -> Result<()> {
        let file_path: Option<String> = self
            .db
            .query_row(
                "SELECT file_path FROM entries WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .optional()?;

        self.db
            .execute("DELETE FROM entries WHERE hash = ?1", params![hash])?;

        {
            let mut cache = self.lru_cache.write();
            cache.pop(hash);
        }

        if let Some(file_path) = file_path {
            let path = self.config.cache_dir.join("blobs").join(file_path);
            let _ = fs::remove_file(path);
        } else {
            // backward compatibility
            let path = self.config.cache_dir.join("blobs").join(hash);
            let _ = fs::remove_file(path);
        }

        Ok(())
    }

    // Helper methods for cleaner code
    pub fn read_text_preview(&self, file_path: &str, max_len: usize) -> Option<String> {
        let path = self.config.cache_dir.join("blobs").join(file_path);

        if file_path.ends_with(".zst") {
            self.read_compressed_preview(&path, max_len)
        } else {
            self.read_plain_preview(&path, max_len)
        }
    }

    pub fn read_compressed_preview(&self, path: &Path, max_len: usize) -> Option<String> {
        use zstd::stream::read::Decoder;

        let file = fs::File::open(path).ok()?;
        let mut decoder = Decoder::new(file).ok()?;
        let mut buffer = vec![0u8; max_len * 4];
        let n = std::io::Read::read(&mut decoder, &mut buffer).ok()?;

        String::from_utf8(buffer[..n].to_vec()).ok()
    }

    pub fn read_plain_preview(&self, path: &Path, max_len: usize) -> Option<String> {
        let data = fs::read(path).ok()?;
        let len = data.len().min(max_len * 4);
        String::from_utf8(data[..len].to_vec()).ok()
    }

    pub fn format_time_ago(&self, timestamp: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ago_secs = now.saturating_sub(timestamp as u64);

        if ago_secs < 60 {
            format!("{}s", ago_secs)
        } else if ago_secs < 3600 {
            format!("{}m", ago_secs / 60)
        } else if ago_secs < 86400 {
            format!("{}h", ago_secs / 3600)
        } else {
            format!("{}d", ago_secs / 86400)
        }
    }

    pub fn format_size(&self, bytes: i64) -> String {
        if bytes < 1024 {
            format!("{}B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{}K", bytes / 1024)
        } else {
            format!("{}M", bytes / (1024 * 1024))
        }
    }

    pub fn print_history(&self) -> Result<()> {
        // Print static entries
        for entry in &self.config.static_entries {
            println!("{}", entry.replace('\n', " "));
        }

        // Optimized: build hash set of cached entries first
        let cached_hashes: Vec<String> = {
            let cache = self.lru_cache.read();
            cache.iter().map(|(hash, _)| hash.clone()).collect()
        };

        // Process cached entries first
        let mut printed_hashes = std::collections::HashSet::new();
        let mut printed_count = 0;

        // Sort cached entries by timestamp
        let mut cached_entries: Vec<(String, CachedEntry)> = {
            let cache = self.lru_cache.read();
            cached_hashes
                .iter()
                .filter_map(|hash| cache.peek(hash).map(|entry| (hash.clone(), entry.clone())))
                .collect()
        };
        cached_entries.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp));

        // Print cached entries
        for (hash, cached) in cached_entries.iter().take(self.config.max_print_entries) {
            if printed_count >= self.config.max_print_entries {
                break;
            }

            self.print_cached_entry(hash, cached)?;
            printed_hashes.insert(hash.clone());
            printed_count += 1;
        }

        // Only query database for remaining entries if needed
        if printed_count < self.config.max_print_entries {
            let mut stmt = self.db.prepare(
                "SELECT hash, app_name, content_type, inline_text, file_path, mime_type, size_bytes, timestamp, width, height
                 FROM entries 
                 WHERE hash NOT IN (SELECT value FROM json_each(?1))
                 ORDER BY timestamp DESC LIMIT ?2"
            )?;

            let excluded_json = serde_json::to_string(&printed_hashes.iter().collect::<Vec<_>>())?;
            let remaining_limit = self.config.max_print_entries - printed_count;

            let rows = stmt.query_map(params![excluded_json, remaining_limit as i64], |row| {
                let hash: String = row.get(0)?;
                let app_name: String = row.get(1)?;
                let content_type: String = row.get(2)?;
                let inline_text: Option<String> = row.get(3)?;
                let file_path: Option<String> = row.get(4)?;
                let mime_type: Option<String> = row.get(5)?;
                let size_bytes: i64 = row.get(6)?;
                let timestamp: i64 = row.get(7)?;
                let width: Option<i64> = row.get(8)?;
                let height: Option<i64> = row.get(9)?;

                Ok((
                    hash,
                    app_name,
                    content_type,
                    inline_text,
                    file_path,
                    mime_type,
                    size_bytes,
                    timestamp,
                    width,
                    height,
                ))
            })?;

            for row in rows {
                let (
                    hash,
                    _app_name,
                    content_type,
                    inline_text,
                    file_path,
                    mime_type,
                    size_bytes,
                    timestamp,
                    width,
                    height,
                ) = row?;
                let time_str = self.format_time_ago(timestamp);
                let hash_prefix = &hash[..HASH_PREFIX_LEN.min(hash.len())];

                let size_str = self.format_size(size_bytes);

                match content_type.as_str() {
                    "text" => {
                        if let Some(text) = inline_text {
                            let available_chars = 80 - time_str.len() - 1 - 9 - 1;
                            let display = self.truncate_to_fit(&text, available_chars);
                            println!("{} {} #{}", time_str, display, hash_prefix);
                        }
                    }
                    "text_file" => {
                        if let Some(fp) = file_path {
                            let available_chars =
                                80 - time_str.len() - 1 - 9 - 1 - size_str.len() - 3;
                            let preview = self
                                .read_text_preview(&fp, available_chars * 4)
                                .map(|p| self.truncate_to_fit(&p, available_chars))
                                .filter(|p| !p.is_empty());

                            if let Some(display) = preview {
                                println!(
                                    "{} {} [{}] #{}",
                                    time_str, display, size_str, hash_prefix
                                );
                            } else {
                                println!("{} [Text: {}] #{}", time_str, size_str, hash_prefix);
                            }
                        }
                    }
                    "image" => {
                        let mime_short = mime_type
                            .as_ref()
                            .map(|m| m.split('/').last().unwrap_or("?"))
                            .unwrap_or("?");

                        if let (Some(w), Some(h)) = (width, height) {
                            let dims_str = format!("{}x{}px", w, h);
                            let available = 80
                                - time_str.len()
                                - 1
                                - 9
                                - 7
                                - mime_short.len()
                                - size_str.len()
                                - 2;
                            if dims_str.len() <= available {
                                println!(
                                    "{} [IMG:{} {} {}] #{}",
                                    time_str, dims_str, mime_short, size_str, hash_prefix
                                );
                            } else {
                                println!(
                                    "{} [IMG:{} {}] #{}",
                                    time_str, mime_short, size_str, hash_prefix
                                );
                            }
                        } else {
                            println!(
                                "{} [IMG:{} {}] #{}",
                                time_str, mime_short, size_str, hash_prefix
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn print_cached_entry(&self, hash: &str, cached: &CachedEntry) -> Result<()> {
        let time_str = self.format_time_ago(cached.timestamp);
        let hash_prefix = &hash[..HASH_PREFIX_LEN.min(hash.len())];
        let size_str = self.format_size(cached.size_bytes as i64);

        match cached.content_type.as_str() {
            "text" => {
                if let Some(text) = &cached.inline_text {
                    let available_chars = 80 - time_str.len() - 1 - 9 - 1;
                    let display = self.truncate_to_fit(text, available_chars);
                    println!("{} {} #{}", time_str, display, hash_prefix);
                }
            }
            "text_file" => {
                if let Some(fp) = &cached.file_path {
                    let available_chars = 80 - time_str.len() - 1 - 9 - 1 - size_str.len() - 3;
                    let preview = self
                        .read_text_preview(fp, available_chars * 4)
                        .map(|p| self.truncate_to_fit(&p, available_chars))
                        .filter(|p| !p.is_empty());

                    if let Some(display) = preview {
                        println!("{} {} [{}] #{}", time_str, display, size_str, hash_prefix);
                    } else {
                        println!("{} [Text: {}] #{}", time_str, size_str, hash_prefix);
                    }
                }
            }
            "image" => {
                let mime_short = cached
                    .mime_type
                    .as_ref()
                    .map(|m| m.split('/').last().unwrap_or("?"))
                    .unwrap_or("?");

                if let (Some(w), Some(h)) = (cached.width, cached.height) {
                    let dims_str = format!("{}x{}px", w, h);
                    let available =
                        80 - time_str.len() - 1 - 9 - 7 - mime_short.len() - size_str.len() - 2;
                    if dims_str.len() <= available {
                        println!(
                            "{} [IMG:{} {} {}] #{}",
                            time_str, dims_str, mime_short, size_str, hash_prefix
                        );
                    } else {
                        println!(
                            "{} [IMG:{} {}] #{}",
                            time_str, mime_short, size_str, hash_prefix
                        );
                    }
                } else {
                    println!(
                        "{} [IMG:{} {}] #{}",
                        time_str, mime_short, size_str, hash_prefix
                    );
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn truncate_to_fit(&self, text: &str, max_chars: usize) -> String {
        let text = text.replace('\n', " ").replace('\t', " ");

        if text.len() <= max_chars {
            text
        } else {
            let mut end = max_chars.saturating_sub(1);
            while !text.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}…", &text[..end])
        }
    }

    async fn copy_selection(&mut self, selection: &str) -> Result<()> {
        // extract hash from #hash format anywhere in string
        if let Some(hash_pos) = selection.rfind('#') {
            let hash_start = hash_pos + 1;
            let hash_end = selection[hash_start..]
                .find(|c: char| c.is_whitespace())
                .map(|i| hash_start + i)
                .unwrap_or(selection.len());

            let hash = &selection[hash_start..hash_end];

            if !hash.is_empty() && hash.len() >= 8 {
                match self.copy_by_hash(hash).await {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        // fallback to literal copy
                    }
                }
            }
        }

        // copy as literal text
        let mut clipboard = self.clipboard.write();
        clipboard.set_text(selection.to_string())?;
        Ok(())
    }

    async fn copy_by_hash(&self, hash_prefix: &str) -> Result<()> {
        // cache lookup first for performance
        {
            let cache = self.lru_cache.read();
            for (full_hash, cached) in cache.iter() {
                if full_hash.starts_with(hash_prefix) {
                    match cached.content_type.as_str() {
                        "text" => {
                            if let Some(text) = &cached.inline_text {
                                let mut clipboard = self.clipboard.write();
                                clipboard.set_text(text.clone())?;
                                return Ok(());
                            }
                        }
                        "text_file" => {
                            if let Some(fp) = &cached.file_path {
                                let path = self.config.cache_dir.join("blobs").join(fp);
                                let mut text = if cached.compressed {
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
                                return Ok(());
                            }
                        }
                        "image" => {
                            if let Some(fp) = &cached.file_path {
                                let path = self.config.cache_dir.join("blobs").join(fp);
                                let data = fs::read(&path)?;

                                let img = image::load_from_memory(&data)?;
                                let rgba = img.to_rgba8();
                                let (width, height) =
                                    (rgba.width() as usize, rgba.height() as usize);

                                let img_data = ImageData {
                                    width,
                                    height,
                                    bytes: rgba.into_raw().into(),
                                };

                                let mut clipboard = self.clipboard.write();
                                clipboard.set_image(img_data)?;
                                return Ok(());
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }

        // cache miss, query database
        let row: Option<(String, Option<String>, Option<String>, Option<bool>)> = self
            .db
            .query_row(
                "SELECT content_type, inline_text, file_path, compressed 
             FROM entries WHERE hash LIKE ?1 || '%' 
             ORDER BY timestamp DESC LIMIT 1",
                params![hash_prefix],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get::<_, Option<i64>>(3)?.map(|v| v != 0),
                    ))
                },
            )
            .optional()?;

        if let Some((content_type, inline_text, file_path, compressed)) = row {
            match content_type.as_str() {
                "text" => {
                    if let Some(text) = inline_text {
                        let mut clipboard = self.clipboard.write();
                        clipboard.set_text(text)?;
                    }
                }
                "text_file" => {
                    if let Some(fp) = file_path {
                        let path = self.config.cache_dir.join("blobs").join(&fp);
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
                "image" => {
                    if let Some(fp) = file_path {
                        let path = self.config.cache_dir.join("blobs").join(&fp);
                        let data = fs::read(&path)?;

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
                    }
                }
                _ => anyhow::bail!("Unknown content type"),
            }
        } else {
            anyhow::bail!("Entry not found for hash: {}", hash_prefix);
        }

        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        let mut stmt = self.db.prepare("SELECT hash FROM entries")?;
        let all_hashes: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        drop(stmt);

        for hash in &all_hashes {
            self.delete_entry(hash)?;
        }

        Ok(())
    }

    pub fn prune(&mut self, hashes: &[String]) -> Result<()> {
        for hash in hashes {
            self.delete_entry(hash)?;
        }
        Ok(())
    }

    pub fn get_history(&self, limit: usize) -> Result<Vec<Entry>> {
        let mut stmt = self.db.prepare(
            "SELECT id, hash, timestamp, app_name, content_type, inline_text, file_path, mime_type, size_bytes, compressed, width, height
             FROM entries ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let entries = stmt
            .query_map([limit as i64], |row| {
                let id: i64 = row.get(0)?;
                let hash: String = row.get(1)?;
                let timestamp: i64 = row.get(2)?;
                let app_name: String = row.get(3)?;
                let content_type: String = row.get(4)?;
                let inline_text: Option<String> = row.get(5)?;
                let _file_path: Option<String> = row.get(6)?;
                let mime_type: Option<String> = row.get(7)?;
                let size_bytes: i64 = row.get(8)?;
                let compressed: Option<bool> = row.get::<_, Option<i64>>(9)?.map(|v| v != 0);
                let width: Option<i64> = row.get(10)?;
                let height: Option<i64> = row.get(11)?;

                let content = match content_type.as_str() {
                    "text" => ContentType::Text(inline_text.unwrap_or_default()),
                    "text_file" => ContentType::TextFile {
                        hash: hash.clone(),
                        compressed: compressed.unwrap_or(false),
                    },
                    "image" => ContentType::Image {
                        mime: mime_type.unwrap_or_else(|| "image/unknown".to_string()),
                        hash: hash.clone(),
                        width: width.unwrap_or(0) as u32,
                        height: height.unwrap_or(0) as u32,
                    },
                    _ => ContentType::Text("Unknown".to_string()),
                };

                Ok(Entry {
                    id: Some(id),
                    hash,
                    timestamp: timestamp as u64,
                    app_name,
                    content,
                    size_bytes: size_bytes as usize,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    pub fn get_entries(&self, limit: usize) -> Result<Vec<(String, String, String, i64, i64)>> {
        let mut stmt = self.db.prepare(
            "SELECT hash, content_type, inline_text, file_path, size_bytes, timestamp
             FROM entries ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt
            .query_map([limit as i64], |row| {
                let hash: String = row.get(0)?;
                let content_type: String = row.get(1)?;
                let inline_text: Option<String> = row.get(2)?;
                let file_path: Option<String> = row.get(3)?;
                let size_bytes: i64 = row.get(4)?;
                let timestamp: i64 = row.get(5)?;

                let content = match content_type.as_str() {
                    "text" => inline_text.unwrap_or_else(|| "[Empty]".to_string()),
                    "text_file" => {
                        if let Some(fp) = file_path {
                            self.read_text_preview(&fp, self.config.max_display_length)
                                .unwrap_or_else(|| {
                                    format!("[Text: {}]", self.format_size(size_bytes))
                                })
                        } else {
                            format!("[Text: {}]", self.format_size(size_bytes))
                        }
                    }
                    "image" => format!("[Image: {}]", self.format_size(size_bytes)),
                    _ => "[Unknown]".to_string(),
                };

                Ok((hash, content, content_type, size_bytes, timestamp))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }
}
