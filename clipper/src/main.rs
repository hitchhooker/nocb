// clipper/src/main.rs
use clipper::{ClipperApp, ClipEntry, Effect, Event, Key, Model};
use crux_core::{Core, Request};
use eframe::egui;
use nocb::{ClipboardManager, Config, ContentType, Entry};
use parking_lot::Mutex;
use std::sync::Arc;

struct ClipperGui {
    core: Core<Effect, ClipperApp>,
    model: Model,
    clipboard_manager: Arc<Mutex<ClipboardManager>>,
}

impl ClipperGui {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Dark theme by default
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        
        // Initialize clipboard manager
        let config = Config::load().expect("Failed to load config");
        let manager = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(ClipboardManager::new(config))
            .expect("Failed to create clipboard manager");
        
        let clipboard_manager = Arc::new(Mutex::new(manager));
        
        // Start monitoring in background
        let manager_clone = clipboard_manager.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut manager = manager_clone.lock();
                manager.run_daemon().await.expect("Daemon failed");
            });
        });
        
        let mut app = Self {
            core: Core::new(),
            model: Model::default(),
            clipboard_manager,
        };
        
        // Initial load
        app.process_event(Event::Init);
        app
    }
    
    fn process_event(&mut self, event: Event) {
        let requests = self.core.process_event(event);
        
        for request in requests {
            match request {
                Request::Effect(effect) => {
                    self.process_effect(effect);
                }
            }
        }
        
        self.model = self.core.view();
    }
    
    fn process_effect(&mut self, effect: Effect) {
        match effect {
            Effect::Render(_) => {
                // egui handles rendering automatically
            }
            Effect::LoadClips => {
                let manager = self.clipboard_manager.lock();
                let entries = manager.get_history(1000).unwrap_or_default();
                
                let clips: Vec<ClipEntry> = entries.into_iter().map(|entry| {
                    let (content, entry_type) = match &entry.content {
                        ContentType::Text(text) => {
                            (text.clone(), "text".to_string())
                        }
                        ContentType::TextFile { hash, .. } => {
                            let preview = manager.get_text_preview(hash, 200)
                                .unwrap_or_else(|| format!("[Text: {}]", manager.format_size(entry.size_bytes as i64)));
                            (preview, "text_file".to_string())
                        }
                        ContentType::Image { mime, .. } => {
                            (format!("{} image", mime), "image".to_string())
                        }
                    };
                    
                    ClipEntry {
                        id: entry.id.unwrap_or(0),
                        hash: entry.hash,
                        content,
                        time_ago: manager.format_time_ago(entry.timestamp as i64),
                        entry_type,
                        size_str: if entry.size_bytes > 1024 {
                            Some(manager.format_size(entry.size_bytes as i64))
                        } else {
                            None
                        },
                    }
                }).collect();
                
                drop(manager);
                self.process_event(Event::ClipsLoaded(clips));
            }
            Effect::CopyToClipboard(content) => {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let mut manager = self.clipboard_manager.lock();
                    manager.copy_selection(&content).await.ok();
                });
                self.process_event(Event::Copied);
            }
        }
    }
    
    fn filtered_clips(&self) -> Vec<ClipEntry> {
        if self.model.search_query.is_empty() {
            self.model.clips.clone()
        } else {
            let query = self.model.search_query.to_lowercase();
            self.model.clips
                .iter()
                .filter(|clip| clip.content.to_lowercase().contains(&query))
                .cloned()
                .collect()
        }
    }
}

impl eframe::App for ClipperGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle keyboard shortcuts
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // Search bar
            ui.horizontal(|ui| {
                ui.label("Search:");
                let response = ui.text_edit_singleline(&mut self.model.search_query);
                if response.changed() {
                    self.process_event(Event::UpdateSearch(self.model.search_query.clone()));
                }
                
                ui.label(format!("{}/{}", self.filtered_clips().len(), self.model.clips.len()));
                
                if ui.button("⟳").clicked() {
                    self.process_event(Event::RefreshClips);
                }
            });
            
            ui.separator();
            
            // Clips list
            let clips = self.filtered_clips();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (index, clip) in clips.iter().enumerate() {
                    let is_selected = index == self.model.selected_index;
                    
                    let response = ui.selectable_label(is_selected, 
                        format!("{} {} {}", 
                            clip.time_ago,
                            clip.content.chars().take(100).collect::<String>(),
                            clip.size_str.as_deref().unwrap_or("")
                        )
                    );
                    
                    if response.clicked() {
                        self.process_event(Event::SelectIndex(index));
                        self.process_event(Event::CopyClip(index));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    
                    if response.hovered() && !is_selected {
                        self.process_event(Event::SelectIndex(index));
                    }
                }
            });
            
            // Handle arrow keys
            if ctx.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                self.process_event(Event::KeyPress(Key::Up));
            }
            if ctx.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                self.process_event(Event::KeyPress(Key::Down));
            }
            if ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.process_event(Event::KeyPress(Key::Enter));
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
        
        // Refresh periodically
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 600.0])
            .with_always_on_top()
            .with_decorations(false),
        ..Default::default()
    };
    
    eframe::run_native(
        "Clipper",
        options,
        Box::new(|cc| Box::new(ClipperGui::new(cc))),
    )
}
