use std::sync::Arc;

use anyhow::{Context, Result};
use azazel_coe5_protocol::GameSnapshot;
use mlua::{Lua, Value};
use parking_lot::RwLock;

const LUA_MEMORY_LIMIT: usize = 16 * 1024 * 1024;

pub struct LuaEngine {
    lua: Lua,
}

impl LuaEngine {
    pub fn new(snapshot: Arc<RwLock<Option<GameSnapshot>>>) -> Result<Self> {
        let lua = Lua::new();
        lua.set_memory_limit(LUA_MEMORY_LIMIT)
            .context("set Lua memory limit")?;

        let globals = lua.globals();
        for forbidden in [
            "os", "io", "package", "debug", "require", "dofile", "loadfile", "load",
        ] {
            globals.set(forbidden, Value::Nil)?;
        }

        let api = lua.create_table()?;
        let snapshot_reader = Arc::clone(&snapshot);
        api.set(
            "snapshot_json",
            lua.create_function(move |_, ()| {
                let value = snapshot_reader.read().clone();
                serde_json::to_string(&value).map_err(mlua::Error::external)
            })?,
        )?;
        api.set(
            "log",
            lua.create_function(|_, message: String| {
                tracing::info!(target: "lua", "{message}");
                Ok(())
            })?,
        )?;
        lua.globals().set("assistant", api)?;
        Ok(Self { lua })
    }

    pub fn execute(&self, source: &str) -> Result<String> {
        let value = self
            .lua
            .load(source)
            .set_name("assistant-console")
            .eval::<Value>()
            .context("execute Lua")?;
        Ok(display_value(value))
    }
}

fn display_value(value: Value) -> String {
    match value {
        Value::Nil => "nil".into(),
        Value::Boolean(value) => value.to_string(),
        Value::Integer(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value
            .to_str()
            .map(|value| value.to_owned())
            .unwrap_or_else(|_| "<non-UTF-8 string>".into()),
        other => format!("<{}>", other.type_name()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_exposes_snapshot_without_os_library() {
        let snapshot = Arc::new(RwLock::new(None));
        let engine = LuaEngine::new(snapshot).unwrap();
        assert_eq!(
            engine.execute("return assistant.snapshot_json()").unwrap(),
            "null"
        );
        assert!(engine.execute("return os.execute('whoami')").is_err());
    }
}
