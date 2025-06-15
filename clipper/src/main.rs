// clipper/src/main.rs
use clipper::{ClipperApp, ClipEntry, Event, Key, Model};
use crux_core::Core;
use eframe::egui;
use nocb::{ClipboardManager, Config};
use parking_lot::Mutex;
use std::sync::Arc;

// chaOS color scheme
fn chaos_theme() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();

    // Colors from rofi theme
    let pink = egui::Color32::from_rgb(0xE6, 0x00, 0x7A);
    let _green = egui::Color32::from_rgb(0x56, 0xF3, 0x9A);
    let _cyan = egui::Color32::from_rgb(0x00, 0xFF, 0xE1);
    let bg = egui::Color32::from_rgba_unmultiplied(0, 0, 0, 0xCC);
    let bg_alt = egui::Color32::from_rgb(0x1A, 0x1B, 0x26);

    // Widget visuals
    visuals.widgets.noninteractive.bg_fill = bg_alt;
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(2.0, pink);
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, pink);

    visuals.widgets.inactive.bg_fill = bg_alt;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(2.0, pink);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, pink);

    visuals.widgets.hovered.bg_fill = pink.linear_multiply(0.2);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(2.0, pink);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, pink);

    visuals.widgets.active.bg_fill = pink;
    visuals.widgets.active.bg_stroke = egui::Stroke::new(2.0, pink);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, egui::Color32::BLACK);

    // Selection colors
    visuals.selection.bg_fill = pink;
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::BLACK);

    // Window
    visuals.window_fill = bg;
    visuals.window_stroke = egui::Stroke::new(3.0, pink);
    visuals.window_rounding = egui::Rounding::same(8.0);

    // Misc
    visuals.extreme_bg_color = bg;
    visuals.panel_fill = bg;
    visuals.faint_bg_color = bg_alt;

    visuals
}

struct ClipperGui {
    core: Core<ClipperApp>,
    model: Model,
    clipboard_manager: Arc<Mutex<ClipboardManager>>,
}

impl ClipperGui {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Apply chaOS theme
        cc.egui_ctx.set_visuals(chaos_theme());

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
        // Handle shell operations based on the event
        match &event {
            Event::Init | Event::RefreshClips => {
                self.load_clips();
            }
            Event::CopyClip(index) => {
                // Get the clip content from the current model
                if let Some(clip) = self.model.clips.get(*index) {
                    self.copy_to_clipboard(clip.content.clone());
                }
            }
            _ => {}
        }
        
        // Send to core - this returns Vec<Effect> 
        let _effects = self.core.process_event(event);
        
        // Update the view model
        self.model = self.core.view();
    }

    fn load_clips(&mut self) {
        // ClipboardManager doesn't have a direct method to get history as a Vec<Entry>
        // The print_history method prints to stdout, so we'll need to query the DB directly
        // For now, let's create a method that reads from the database
        
        let manager = self.clipboard_manager.lock();
        
        // We'll need to access the database directly or modify nocb to expose a method
        // For MVP, let's use dummy data and add a TODO
        
        // TODO: Add a method to ClipboardManager to return Vec<Entry> or expose the database
        let clips = vec![
            ClipEntry {
                id: 1,
                hash: "abc123".to_string(),
                content: "Sample clipboard content".to_string(),
                time_ago: manager.format_time_ago(
                    (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() - 300) as i64
                ),
                entry_type: "text".to_string(),
                size_str: Some(manager.format_size(24)),
            },
            ClipEntry {
                id: 2,
                hash: "def456".to_string(),
                content: "Another clipboard entry with more text that might be truncated".to_string(),
                time_ago: manager.format_time_ago(
                    (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() - 600) as i64
                ),
                entry_type: "text".to_string(),
                size_str: Some(manager.format_size(64)),
            },
        ];
        
        drop(manager);
        self.process_event(Event::ClipsLoaded(clips));
    }

    fn copy_to_clipboard(&mut self, content: String) {
        // Use the IPC mechanism to send copy command
        let content_clone = content.clone();
        
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // Use the static send_copy_command method
                ClipboardManager::send_copy_command(&content_clone).await.ok();
            });
        });
        
        self.process_event(Event::Copied);
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

        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgba_unmultiplied(0, 0, 0, 0xCC))
                .inner_margin(egui::Margin::same(24.0))
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 16.0);

                // Search bar with custom styling
                let bg_alt = egui::Color32::from_rgb(0x1A, 0x1B, 0x26);
                let pink = egui::Color32::from_rgb(0xE6, 0x00, 0x7A);
                let cyan = egui::Color32::from_rgb(0x00, 0xFF, 0xE1);

                egui::Frame::none()
                    .fill(bg_alt)
                    .rounding(egui::Rounding::same(5.0))
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Icon and prompt
                            ui.colored_label(pink, " Apps:");

                            // Search input
                            let response = ui.add_sized(
                                [ui.available_width() - 120.0, 20.0],
                                egui::TextEdit::singleline(&mut self.model.search_query)
                                    .font(egui::TextStyle::Monospace)
                                    .hint_text("Type to search...")
                                    .desired_width(f32::INFINITY)
                            );
                            
                            if response.changed() {
                                self.process_event(Event::UpdateSearch(self.model.search_query.clone()));
                            }

                            // Counter
                            ui.colored_label(cyan, format!("{}/{}",
                                self.filtered_clips().len(),
                                self.model.clips.len()
                            ));

                            // Refresh button
                            if ui.button("⟳").clicked() {
                                self.process_event(Event::RefreshClips);
                            }
                        });
                    });

                ui.add_space(8.0);

                // Clips list
                let clips = self.filtered_clips();
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for (index, clip) in clips.iter().enumerate() {
                            let is_selected = index == self.model.selected_index;

                            let mut frame = egui::Frame::none()
                                .inner_margin(egui::Margin::symmetric(16.0, 10.0))
                                .rounding(egui::Rounding::same(5.0));

                            if is_selected {
                                frame = frame.fill(pink);
                            } else if index % 2 == 1 {
                                frame = frame.fill(egui::Color32::from_rgba_unmultiplied(0x1A, 0x1B, 0x26, 0x11));
                            }

                            let response = frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    // Time with proper color
                                    if is_selected {
                                        ui.colored_label(egui::Color32::BLACK, &clip.time_ago);
                                    } else {
                                        ui.colored_label(cyan, &clip.time_ago);
                                    }

                                    ui.separator();

                                    // Content preview - truncate only for display
                                    let preview = if clip.content.len() > 80 {
                                        format!("{}...", clip.content.chars().take(77).collect::<String>())
                                    } else {
                                        clip.content.clone()
                                    };
                                    let label = if is_selected {
                                        ui.colored_label(egui::Color32::BLACK, preview)
                                    } else {
                                        ui.label(preview)
                                    };

                                    // Size if present
                                    if let Some(size) = &clip.size_str {
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if is_selected {
                                                ui.colored_label(egui::Color32::BLACK, size);
                                            } else {
                                                ui.colored_label(cyan, size);
                                            }
                                        });
                                    }

                                    label
                                })
                            }).inner;

                            if response.response.clicked() {
                                self.process_event(Event::SelectIndex(index));
                                self.process_event(Event::CopyClip(index));
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }

                            if response.response.hovered() && !is_selected {
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
    // Set renderer to glow (OpenGL) which works better in constrained environments
    unsafe {
        std::env::set_var("WGPU_BACKEND", "gl");
    }
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 700.0])
            .with_always_on_top()
            .with_decorations(false)
            .with_transparent(true),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "Clipper",
        options,
        Box::new(|cc| Ok(Box::new(ClipperGui::new(cc)))),
    )
}
