//! Generates `src/schema/tables.rs` from the OCSF server's schema export.
//!
//! ```text
//! curl -sSL https://schema.ocsf.io/1.5.0/export/schema -o ocsf.json
//! cargo run -p goliath-ocsf --example generate_schema -- ocsf.json \
//!     > crates/goliath-ocsf/src/schema/tables.rs
//! ```
//!
//! The export includes the extensions the server hosts, such as `win`, so
//! extension classes resolve like core ones. Only names, types, and the
//! values of enumerated integers are kept; descriptions stay upstream.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;

use serde_json::{Map, Value};

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: generate_schema <export.json>")?;
    let export: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let version = export["version"].as_str().ok_or("export has no version")?;
    let types = export["types"].as_object().ok_or("export has no types")?;

    let mut classes = BTreeMap::new();
    for (name, class) in export["classes"]
        .as_object()
        .ok_or("export has no classes")?
    {
        let uid = class["uid"]
            .as_u64()
            .ok_or_else(|| format!("class {name} has no uid"))?;
        if classes
            .insert(uid, (name, attributes(class, types)?))
            .is_some()
        {
            return Err(format!("class uid {uid} is defined twice").into());
        }
    }
    let mut objects = BTreeMap::new();
    for (name, object) in export["objects"]
        .as_object()
        .ok_or("export has no objects")?
    {
        objects.insert(name, attributes(object, types)?);
    }

    let mut out = String::new();
    writeln!(
        out,
        "// OCSF {version} classes and objects, generated from the schema export"
    )?;
    writeln!(
        out,
        "// by `examples/generate_schema.rs`. Do not edit by hand."
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "use super::{{Attribute as A, Base as B, Class, Object}};"
    )?;
    writeln!(out)?;
    writeln!(out, "pub(crate) const VERSION: &str = {version:?};")?;
    writeln!(out)?;
    writeln!(out, "/// Sorted by uid.")?;
    writeln!(out, "pub(super) static CLASSES: &[Class] = &[")?;
    for (uid, (name, attributes)) in &classes {
        writeln!(out, "    Class::new({uid}, {name:?}, &[")?;
        write_attributes(&mut out, attributes)?;
        writeln!(out, "    ]),")?;
    }
    writeln!(out, "];")?;
    writeln!(out)?;
    writeln!(out, "/// Sorted by name.")?;
    writeln!(out, "pub(super) static OBJECTS: &[Object] = &[")?;
    for (name, attributes) in &objects {
        writeln!(out, "    Object::new({name:?}, &[")?;
        write_attributes(&mut out, attributes)?;
        writeln!(out, "    ]),")?;
    }
    writeln!(out, "];")?;
    print!("{out}");
    Ok(())
}

struct Attribute {
    type_name: String,
    base: &'static str,
    array: bool,
    values: Vec<i64>,
}

/// The attributes of a class or object, sorted by name.
fn attributes(
    definition: &Value,
    types: &Map<String, Value>,
) -> Result<BTreeMap<String, Attribute>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    let Some(attributes) = definition["attributes"].as_object() else {
        return Ok(out);
    };
    for (name, attribute) in attributes {
        let type_name = attribute["type"]
            .as_str()
            .ok_or_else(|| format!("{name} has no type"))?;
        let (type_name, base) = if type_name == "object_t" {
            let object = attribute["object_type"]
                .as_str()
                .ok_or_else(|| format!("{name} has no object type"))?;
            (object.to_owned(), "Object")
        } else {
            (type_name.to_owned(), base(type_name, types)?)
        };
        // Enumerations of integers only; the few string enumerations are
        // suggestions, not constraints. `type_uid` is left out: it is
        // arithmetic on the class and activity, and checked as such.
        let enumerated = (base == "Integer" || base == "Long") && name != "type_uid";
        let mut values = Vec::new();
        for key in attribute["enum"]
            .as_object()
            .filter(|_| enumerated)
            .into_iter()
            .flat_map(Map::keys)
        {
            values.push(key.parse::<i64>()?);
        }
        values.sort_unstable();
        let array = attribute["is_array"].as_bool().unwrap_or(false);
        out.insert(
            name.clone(),
            Attribute {
                type_name,
                base,
                array,
                values,
            },
        );
    }
    Ok(out)
}

/// The primitive a type is ultimately stored as.
fn base(type_name: &str, types: &Map<String, Value>) -> Result<&'static str, Box<dyn Error>> {
    let mut current = type_name;
    for _ in 0..8 {
        match current {
            "boolean_t" => return Ok("Boolean"),
            "integer_t" => return Ok("Integer"),
            "long_t" => return Ok("Long"),
            "float_t" => return Ok("Float"),
            "string_t" => return Ok("String"),
            "json_t" => return Ok("Json"),
            _ => {}
        }
        current = types
            .get(current)
            .and_then(|definition| definition["type"].as_str())
            .ok_or_else(|| format!("type {current} has no base"))?;
    }
    Err(format!("type {type_name} does not reach a primitive").into())
}

fn write_attributes(
    out: &mut String,
    attributes: &BTreeMap<String, Attribute>,
) -> Result<(), std::fmt::Error> {
    for (name, attribute) in attributes {
        let Attribute {
            type_name,
            base,
            array,
            values,
        } = attribute;
        writeln!(
            out,
            "        A::new({name:?}, {type_name:?}, B::{base}, {array}, &{values:?}),"
        )?;
    }
    Ok(())
}
