// clipper/src/lib.rs
use crux_core::{render::Render, App};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClipEntry {
    pub id: i64,
    pub hash: String,
    pub content: String,
    pub time_ago: String,
    pub entry_type: String,
    pub size_str: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Model {
    pub clips: Vec<ClipEntry>,
    pub search_query: String,
    pub selected_index: usize,
    pub theme: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Event {
    Init,
    RefreshClips,
    ClipsLoaded(Vec<ClipEntry>),
    UpdateSearch(String),
    SelectIndex(usize),
    CopyClip(usize),
    Copied,
    KeyPress(Key),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Key {
    Up,
    Down,
    Enter,
    Escape,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Effect {
    Render(crux_core::render::RenderOperation),
    LoadClips,
    CopyToClipboard(String), // The actual content to copy
}

#[derive(Default)]
pub struct ClipperApp;

impl App for ClipperApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = Model; // For simplicity, using Model as ViewModel
    type Capabilities = Capabilities;

    fn update(&self, event: Self::Event, model: &mut Self::Model, caps: &Self::Capabilities) {
        match event {
            Event::Init | Event::RefreshClips => {
                caps.clipboard.load_clips();
            }
            Event::ClipsLoaded(clips) => {
                model.clips = clips;
                caps.render.render();
            }
            Event::UpdateSearch(query) => {
                model.search_query = query;
                model.selected_index = 0;
                caps.render.render();
            }
            Event::SelectIndex(index) => {
                model.selected_index = index;
                caps.render.render();
            }
            Event::CopyClip(index) => {
                if let Some(clip) = self.filtered_clips(model).get(index) {
                    caps.clipboard.copy_content(clip.content.clone());
                }
            }
            Event::Copied => {
                // Could show a notification or close the window
                caps.render.render();
            }
            Event::KeyPress(key) => {
                match key {
                    Key::Up => {
                        if model.selected_index > 0 {
                            model.selected_index -= 1;
                            caps.render.render();
                        }
                    }
                    Key::Down => {
                        let max = self.filtered_clips(model).len().saturating_sub(1);
                        if model.selected_index < max {
                            model.selected_index += 1;
                            caps.render.render();
                        }
                    }
                    Key::Enter => {
                        self.update(Event::CopyClip(model.selected_index), model, caps);
                    }
                    Key::Escape => {
                        // Handle in shell (close window)
                    }
                }
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        // For now, just return the model
        // In a more complex app, you'd transform it here
        model.clone()
    }
}

impl ClipperApp {
    fn filtered_clips(&self, model: &Model) -> Vec<ClipEntry> {
        if model.search_query.is_empty() {
            model.clips.clone()
        } else {
            let query = model.search_query.to_lowercase();
            model.clips
                .iter()
                .filter(|clip| clip.content.to_lowercase().contains(&query))
                .cloned()
                .collect()
        }
    }
}

#[derive(crux_core::macros::Capabilities)]
#[capabilities(render = "Render", clipboard = "Clipboard")]
pub struct Capabilities {
    render: Render<Effect>,
    clipboard: Clipboard<Event>,
}

// Custom capability for clipboard operations
#[derive(Clone)]
pub struct Clipboard<Ev> {
    context: crux_core::capability::CapabilityContext<Effect, Ev>,
}

impl<Ev> Clipboard<Ev> 
where
    Ev: 'static,
{
    pub fn new(context: crux_core::capability::CapabilityContext<Effect, Ev>) -> Self {
        Self { context }
    }

    pub fn load_clips(&self) {
        self.context.spawn({
            let context = self.context.clone();
            async move {
                context.notify(Effect::LoadClips);
            }
        });
    }

    pub fn copy_content(&self, content: String) {
        self.context.spawn({
            let context = self.context.clone();
            async move {
                context.notify(Effect::CopyToClipboard(content));
            }
        });
    }
}

impl<Ev> crux_core::capability::Capability<Ev> for Clipboard<Ev> {
    type Operation = ();
    type MappedSelf<MappedEv> = Clipboard<MappedEv>;

    fn map_event<F, NewEv>(&self, f: F) -> Self::MappedSelf<NewEv>
    where
        F: Fn(NewEv) -> Ev + Send + Sync + 'static,
        Ev: 'static,
        NewEv: 'static,
    {
        Clipboard::new(self.context.map_event(f))
    }
}
