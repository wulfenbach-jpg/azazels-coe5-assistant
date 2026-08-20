//! The playable role/class names for the supported CoE5 5.39 build.
//!
//! The names live inline at the start of each class definition struct:
//! RVA `0x2619e0`, stride `0x1f74`, in `.data` (file offset `0x2605e0` for
//! the supported SHA-256 `0b422183…`). Class `0` is the unset/"no class"
//! state the game displays as *Random*; classes `1..=30` are the playable
//! roles; `31` is the `end` sentinel. The table is stable because the
//! supported build is pinned by hash.

/// Class id → display name. Index 0 is the game's "Random" state.
pub const CLASS_NAMES: [&str; 31] = [
    "Random",        // 0: no class (game displays "Random")
    "Baron",         // 1
    "Necromancer",   // 2
    "Demonologist",  // 3
    "Witch",         // 4
    "High Priestess", // 5
    "Bakemono",      // 6
    "Barbarian",     // 7
    "Senator",       // 8
    "Pale One",      // 9
    "Druid",         // 10
    "Burgmeister",   // 11
    "Warlock",       // 12
    "Priest King",   // 13
    "Troll King",    // 14
    "Enchanter",     // 15
    "Beholder",      // 16
    "Archmage",      // 17
    "Goblin King",   // 18
    "High Cultist",  // 19
    "Dwarf Queen",   // 20
    "Voice of El",   // 21
    "Illusionist",   // 22
    "Markgraf",      // 23
    "Dryad Queen",   // 24
    "Scourge Lord",  // 25
    "Cloud Lord",    // 26
    "Kobold King",   // 27
    "Monkey Maharaja", // 28
    "Raksharaja",    // 29
    "Guildmaster",   // 30
];

/// Resolves a class id to its display name; unknown ids render as the raw
/// number so no value is ever hidden.
pub fn class_name(class_id: i16) -> String {
    match usize::try_from(class_id).ok().and_then(|id| CLASS_NAMES.get(id)) {
        Some(name) => (*name).to_string(),
        None => class_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_every_playable_class() {
        assert_eq!(CLASS_NAMES[0], "Random");
        assert_eq!(CLASS_NAMES[1], "Baron");
        assert_eq!(CLASS_NAMES[2], "Necromancer");
        assert_eq!(CLASS_NAMES[9], "Pale One");
        assert_eq!(CLASS_NAMES[12], "Warlock");
        assert_eq!(CLASS_NAMES[30], "Guildmaster");
    }

    #[test]
    fn unknown_ids_fall_back_to_number() {
        assert_eq!(class_name(2), "Necromancer");
        assert_eq!(class_name(-1), "-1");
        assert_eq!(class_name(99), "99");
    }
}
