use std::{
    ffi::c_void,
    fs::File,
    io::{BufReader, Read},
    mem::{MaybeUninit, size_of},
    path::Path,
};

use anyhow::{Context, Result, bail};
use azazel_coe5_protocol::{
    CapabilityReport, CapabilityState, CapabilityStatus, GameSnapshot, LifecycleSnapshot,
    MapSnapshot, OptionsSnapshot, ParticipantSnapshot,
};
use azazel_coe5_symbols::{BuildManifest, GlobalSymbol, ParsedSignature, Rva};
use sha2::{Digest, Sha256};
use windows::Win32::System::{
    Diagnostics::Debug::ReadProcessMemory, LibraryLoader::GetModuleHandleW,
    Threading::GetCurrentProcess,
};

const MAX_MEMORY_READ: usize = 64 * 1024;
const PLAYER_STRIDE: u64 = 0x7884;

pub struct RuntimeState {
    module_base: usize,
    manifest: BuildManifest,
}

impl RuntimeState {
    pub fn initialize() -> Result<Self> {
        let manifest = BuildManifest::embedded_5_39()?;
        let executable = std::env::current_exe().context("resolve host executable")?;
        let sha256 = sha256_file(&executable)?;
        if !manifest.supports_sha256(&sha256) {
            bail!(
                "unsupported host executable: expected {}, found {sha256} at {}",
                manifest.target.sha256,
                executable.display()
            );
        }
        let module = unsafe { GetModuleHandleW(None) }.context("GetModuleHandleW(host)")?;
        Ok(Self {
            module_base: module.0 as usize,
            manifest,
        })
    }

    pub fn manifest(&self) -> &BuildManifest {
        &self.manifest
    }

    pub fn capability_report(&self, is_installed: impl Fn(&str) -> bool) -> CapabilityReport {
        let mut entries = vec![CapabilityStatus {
            id: "memory.read".into(),
            state: CapabilityState::Available,
            reason: None,
        }];

        for function in &self.manifest.functions {
            for capability in &function.capabilities {
                if capability == "memory.read"
                    || entries.iter().any(|entry| entry.id == *capability)
                {
                    continue;
                }
                // An installed MinHook detour patches the function prologue, so
                // the pristine signature no longer matches. The capability is
                // still healthy: report it as Available without re-validating.
                let status = if is_installed(&function.id) {
                    CapabilityStatus {
                        id: capability.clone(),
                        state: CapabilityState::Available,
                        reason: None,
                    }
                } else {
                    match self.validate_signature(&function.id) {
                        Ok(()) => CapabilityStatus {
                            id: capability.clone(),
                            state: CapabilityState::Available,
                            reason: None,
                        },
                        Err(error) => CapabilityStatus {
                            id: capability.clone(),
                            state: CapabilityState::Failed,
                            reason: Some(error.to_string()),
                        },
                    }
                };
                entries.push(status);
            }
        }

        for (capability, reason) in &self.manifest.disabled_capabilities {
            entries.push(CapabilityStatus {
                id: capability.clone(),
                state: CapabilityState::Disabled,
                reason: Some(reason.clone()),
            });
        }
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        CapabilityReport { entries }
    }

    pub fn validate_signature(&self, id: &str) -> Result<()> {
        let function = self.manifest.function(id)?;
        let signature = ParsedSignature::parse(&function.signature)?;
        let bytes = self.read_bytes(function.rva, signature.len())?;
        self.manifest.validate_function_bytes(id, &bytes)?;
        Ok(())
    }

    pub fn address_of_function(&self, id: &str) -> Result<*mut c_void> {
        self.validate_signature(id)?;
        let function = self.manifest.function(id)?;
        self.checked_address(function.rva, 1)
            .map(|address| address as *mut c_void)
    }

    pub fn read_bytes(&self, rva: Rva, length: usize) -> Result<Vec<u8>> {
        if length > MAX_MEMORY_READ {
            bail!("memory read length {length} exceeds {MAX_MEMORY_READ}");
        }
        let address = self.checked_address(rva, length)?;
        let mut bytes = vec![0u8; length];
        let mut bytes_read = 0usize;
        unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const c_void,
                bytes.as_mut_ptr().cast(),
                length,
                Some(&mut bytes_read),
            )
        }
        .with_context(|| format!("ReadProcessMemory({rva}, {length})"))?;
        if bytes_read != length {
            bail!("short read at {rva}: expected {length}, received {bytes_read}");
        }
        Ok(bytes)
    }

    pub fn snapshot(&self) -> Result<GameSnapshot> {
        let mut participants = Vec::with_capacity(32);
        let classes = self.global("participant_classes")?;
        let controllers = self.global("participant_controllers")?;
        let start_x = self.global("participant_start_x")?;
        let start_y = self.global("participant_start_y")?;
        let team = self.global("player_team_field")?;
        let difficulty = self.global("player_difficulty_field")?;

        for slot in 0..32u64 {
            let controller = self.read_at::<i16>(controllers.rva, slot * 2)?;
            participants.push(ParticipantSnapshot {
                slot: slot as u8,
                active: matches!(controller, 0 | 1),
                controller,
                class_id: self.read_at(classes.rva, slot * 2)?,
                start_x: self.read_at(start_x.rva, slot * 2)?,
                start_y: self.read_at(start_y.rva, slot * 2)?,
                team: (slot < 24)
                    .then(|| self.read_at(team.rva, slot * PLAYER_STRIDE))
                    .transpose()?,
                difficulty: (slot < 24)
                    .then(|| self.read_at(difficulty.rva, slot * PLAYER_STRIDE))
                    .transpose()?,
            });
        }

        Ok(GameSnapshot {
            lifecycle: LifecycleSnapshot {
                world_state_unknown_abc: self.read_global("world_state_unknown_abc")?,
                turn: self.read_global("game_turn")?,
                plane: self.read_global("active_plane")?,
            },
            map: MapSnapshot {
                width: self.read_global("map_width")?,
                height: self.read_global("map_height")?,
                real_width: self.read_global("map_real_width")?,
                random_map_launch_mode: self.read_global("random_map_launch_mode")?,
            },
            options: OptionsSnapshot {
                flags_a: self.read_global("options_flags_a")?,
                flags_b: self.read_global("options_flags_b")?,
                society: self.read_global("society_id")?,
                short_0c: self.read_global("options_short_0c")?,
                short_0e: self.read_global("options_short_0e")?,
                short_10: self.read_global("options_short_10")?,
                int_14: self.read_global("options_int_14")?,
                common_cause: self.read_global("common_cause")?,
                score_graphs: self.read_global("score_graphs")?,
                int_20: self.read_global("options_int_20")?,
                int_24: self.read_global("options_int_24")?,
                int_28: self.read_global("options_int_28")?,
                int_2c: self.read_global("options_int_2c")?,
                independent_strength: self.read_global("independent_strength")?,
                int_34: self.read_global("options_int_34")?,
                battle_reports: self.read_global("battle_reports")?,
                north_percent_ui: self.read_global("north_percent_ui")?,
                south_percent_ui: self.read_global("south_percent_ui")?,
                start_policy_ui: self.read_global("start_policy_ui")?,
                unique_random_classes: self.read_global("unique_random_classes")?,
            },
            participants,
        })
    }

    fn global(&self, id: &str) -> Result<&GlobalSymbol> {
        Ok(self.manifest.global(id)?)
    }

    fn read_global<T: Copy>(&self, id: &str) -> Result<T> {
        self.read_at(self.global(id)?.rva, 0)
    }

    fn read_at<T: Copy>(&self, rva: Rva, offset: u64) -> Result<T> {
        let rva = Rva(rva.0.checked_add(offset).context("RVA offset overflow")?);
        let address = self.checked_address(rva, size_of::<T>())?;
        let mut value = MaybeUninit::<T>::uninit();
        let mut bytes_read = 0usize;
        unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const c_void,
                value.as_mut_ptr().cast(),
                size_of::<T>(),
                Some(&mut bytes_read),
            )
        }
        .with_context(|| format!("ReadProcessMemory({rva}, {})", size_of::<T>()))?;
        if bytes_read != size_of::<T>() {
            bail!(
                "short read at {rva}: expected {}, received {bytes_read}",
                size_of::<T>()
            );
        }
        Ok(unsafe { value.assume_init() })
    }

    fn checked_address(&self, rva: Rva, length: usize) -> Result<usize> {
        let end = rva
            .0
            .checked_add(length as u64)
            .context("RVA range overflow")?;
        if end > self.manifest.target.size_of_image {
            bail!(
                "RVA range {}..0x{end:x} exceeds image size 0x{:x}",
                rva,
                self.manifest.target.size_of_image
            );
        }
        self.module_base
            .checked_add(rva.0 as usize)
            .context("loaded address overflow")
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
