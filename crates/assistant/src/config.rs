use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use azazel_coe5_protocol::GameSnapshot;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CONFIG_VERSION: u32 = 1;

/// Where the restart draws its settings from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsSource {
    /// Copy the running game's own settings (map/rule arguments from its
    /// command line, participant roster from the live snapshot).
    #[default]
    CopyLastGame,
    /// Use the active profile's configured settings.
    UseProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub version: u32,
    pub coe5_executable: PathBuf,
    pub active_profile: Option<Uuid>,
    pub profile_lock: bool,
    pub restart_hotkey: HotkeyBinding,
    pub restart_double_tap_ms: u64,
    #[serde(default)]
    pub restart_settings_source: SettingsSource,
    #[serde(default)]
    pub launch_via_steam: bool,
    pub profiles: Vec<Profile>,
    pub remaps: Vec<RemapRule>,
    pub update: UpdateConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            coe5_executable: PathBuf::from(
                r"D:\SteamLibrary\steamapps\common\ConquestOfElysium5\CoE5.exe",
            ),
            active_profile: None,
            profile_lock: false,
            restart_hotkey: HotkeyBinding {
                modifiers: vec![Modifier::Control, Modifier::Alt],
                code: "KeyR".into(),
            },
            restart_double_tap_ms: 1200,
            restart_settings_source: SettingsSource::default(),
            launch_via_steam: false,
            profiles: vec![Profile::default()],
            remaps: Vec::new(),
            update: UpdateConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let source = fs::read_to_string(&path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("parse configuration {}", path.display()))?;
        if config.version != CONFIG_VERSION {
            anyhow::bail!(
                "configuration version {} is unsupported; expected {CONFIG_VERSION}",
                config.version
            );
        }
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        let parent = path.parent().context("configuration path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = path.with_extension("toml.tmp");
        fs::write(&temporary, toml::to_string_pretty(self)?)?;
        fs::rename(&temporary, &path)
            .with_context(|| format!("replace configuration {}", path.display()))
    }

    pub fn active_profile(&self) -> Option<&Profile> {
        let id = self.active_profile?;
        self.profiles.iter().find(|profile| profile.id == id)
    }

    pub fn active_profile_mut(&mut self) -> Option<&mut Profile> {
        let id = self.active_profile?;
        self.profiles.iter_mut().find(|profile| profile.id == id)
    }

    pub fn matching_profiles(&self, snapshot: &GameSnapshot) -> Vec<Uuid> {
        self.profiles
            .iter()
            .filter(|profile| profile.matches(snapshot))
            .map(|profile| profile.id)
            .collect()
    }

    pub fn auto_select(&mut self, snapshot: &GameSnapshot) -> Option<Uuid> {
        if self.profile_lock {
            return self.active_profile;
        }
        let matches = self.matching_profiles(snapshot);
        if matches.len() == 1 {
            self.active_profile = Some(matches[0]);
        }
        self.active_profile
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub human_class_id: i16,
    pub participant_count: u8,
    pub ai_difficulty: i16,
    pub map: MapProfile,
    pub rules: RuleProfile,
    pub mods: Vec<String>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "Current game".into(),
            human_class_id: 2,
            participant_count: 4,
            ai_difficulty: 2,
            map: MapProfile::default(),
            rules: RuleProfile::default(),
            mods: Vec::new(),
        }
    }
}

impl Profile {
    pub fn matches(&self, snapshot: &GameSnapshot) -> bool {
        let human_class = snapshot
            .participants
            .iter()
            .find(|participant| participant.controller == 0)
            .map(|participant| participant.class_id);
        let participant_count = configured_participant_count(snapshot);
        let difficulties = snapshot
            .participants
            .iter()
            .take(participant_count as usize)
            .filter(|participant| participant.controller != 0)
            .filter_map(|participant| participant.difficulty)
            .collect::<Vec<_>>();
        human_class == Some(self.human_class_id)
            && participant_count == self.participant_count
            && difficulties
                .iter()
                .all(|difficulty| *difficulty == self.ai_difficulty)
    }

    pub fn differences(&self, snapshot: &GameSnapshot) -> Vec<ProfileDifference> {
        let mut differences = Vec::new();
        let human_class = snapshot
            .participants
            .iter()
            .find(|participant| participant.controller == 0)
            .map(|participant| participant.class_id);
        if human_class != Some(self.human_class_id) {
            differences.push(ProfileDifference {
                field: "human_class_id".into(),
                profile: self.human_class_id.to_string(),
                live: human_class
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".into()),
            });
        }
        let participant_count = configured_participant_count(snapshot);
        if participant_count != self.participant_count {
            differences.push(ProfileDifference {
                field: "participant_count".into(),
                profile: self.participant_count.to_string(),
                live: participant_count.to_string(),
            });
        }
        if snapshot.options.society != self.map.society {
            differences.push(ProfileDifference {
                field: "society".into(),
                profile: self.map.society.to_string(),
                live: snapshot.options.society.to_string(),
            });
        }
        if snapshot.options.independent_strength != self.rules.independent_strength {
            differences.push(ProfileDifference {
                field: "independent_strength".into(),
                profile: self.rules.independent_strength.to_string(),
                live: snapshot.options.independent_strength.to_string(),
            });
        }
        differences
    }
}

pub fn configured_participant_count(snapshot: &GameSnapshot) -> u8 {
    snapshot
        .participants
        .iter()
        .take(24)
        .position(|participant| participant.controller == -1)
        .unwrap_or(24) as u8
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapProfile {
    pub width: u16,
    pub height: u16,
    pub society: i16,
    pub north_percent: i32,
    pub south_percent: i32,
}

impl Default for MapProfile {
    fn default() -> Self {
        Self {
            width: 50,
            height: 36,
            society: 0,
            north_percent: 25,
            south_percent: 35,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProfile {
    pub independent_strength: i32,
    pub common_cause: bool,
    pub score_graphs: bool,
    pub battle_reports: bool,
    pub start_policy: StartPolicy,
    pub unique_random_classes: bool,
    pub city_names: bool,
}

impl Default for RuleProfile {
    fn default() -> Self {
        Self {
            independent_strength: 1,
            common_cause: false,
            score_graphs: false,
            battle_reports: false,
            start_policy: StartPolicy::Random,
            unique_random_classes: false,
            city_names: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartPolicy {
    Random,
    Clustered,
    WestEast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotkeyBinding {
    pub modifiers: Vec<Modifier>,
    pub code: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Modifier {
    Control,
    Alt,
    Shift,
    Super,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemapRule {
    pub enabled: bool,
    pub trigger: InputTrigger,
    pub action: InputAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InputTrigger {
    Keyboard {
        virtual_key: u16,
        control: bool,
        alt: bool,
        shift: bool,
    },
    MouseButton {
        button: MouseButton,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputAction {
    pub virtual_key: u16,
    pub control: bool,
    pub alt: bool,
    pub shift: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub endpoint: String,
    pub public_key_base64: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://github.com/wulfenbach-jpg/azazels-coe5-assistant/releases/latest/download/update.json".into(),
            public_key_base64: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfileDifference {
    pub field: String,
    pub profile: String,
    pub live: String,
}

fn config_path() -> Result<PathBuf> {
    let directories = ProjectDirs::from("dev", "Azazel", "AzazelsCoe5Assistant")
        .context("resolve application directories")?;
    Ok(directories.config_dir().join("config.toml"))
}

#[cfg(test)]
mod tests {
    use azazel_coe5_protocol::{
        GameSnapshot, LifecycleSnapshot, MapSnapshot, OptionsSnapshot, ParticipantSnapshot,
    };

    use super::*;

    fn live_snapshot() -> GameSnapshot {
        let mut participants = (0..32)
            .map(|slot| ParticipantSnapshot {
                slot,
                active: false,
                controller: -1,
                class_id: 0,
                start_x: -1,
                start_y: -1,
                team: (slot < 24).then_some(0),
                difficulty: (slot < 24).then_some(2),
            })
            .collect::<Vec<_>>();
        participants[0].controller = 0;
        participants[0].active = true;
        participants[0].class_id = 2;
        participants[1].controller = -4;
        participants[1].class_id = 24;
        participants[2].controller = -4;
        participants[2].class_id = 12;
        participants[3].controller = 1;
        participants[3].active = true;
        participants[3].class_id = 30;
        GameSnapshot {
            lifecycle: LifecycleSnapshot {
                world_state_unknown_abc: 0,
                turn: 83,
                plane: 0,
            },
            map: MapSnapshot {
                width: 614,
                height: 64,
                real_width: 556,
                random_map_launch_mode: 0,
            },
            options: OptionsSnapshot {
                flags_a: 1,
                flags_b: 8,
                society: 2,
                short_0c: 1,
                short_0e: 0,
                short_10: 5,
                int_14: 0,
                common_cause: 0,
                score_graphs: 0,
                int_20: 0,
                int_24: 31,
                int_28: 0,
                int_2c: 0,
                independent_strength: 1,
                int_34: 0,
                battle_reports: 0,
                north_percent_ui: -1,
                south_percent_ui: -1,
                start_policy_ui: 1,
                unique_random_classes: 0,
            },
            participants,
        }
    }

    #[test]
    fn eliminated_players_remain_part_of_original_span() {
        assert_eq!(configured_participant_count(&live_snapshot()), 4);
    }

    #[test]
    fn default_profile_matches_validated_live_shape() {
        let mut profile = Profile::default();
        profile.map.society = 2;
        assert!(profile.matches(&live_snapshot()));
        assert!(profile.differences(&live_snapshot()).is_empty());
    }

    #[test]
    fn ambiguous_profiles_do_not_auto_select() {
        let snapshot = live_snapshot();
        let mut config = AppConfig::default();
        config.profiles[0].map.society = 2;
        let mut duplicate = config.profiles[0].clone();
        duplicate.id = Uuid::new_v4();
        duplicate.name = "Duplicate".into();
        config.profiles.push(duplicate);
        assert_eq!(config.auto_select(&snapshot), None);
    }
}
