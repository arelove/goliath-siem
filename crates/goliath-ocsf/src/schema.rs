//! The OCSF schema itself: which attributes each class and object has, and
//! what type each attribute holds.
//!
//! The tables are generated from the OCSF server's export of
//! [`SCHEMA_VERSION`](crate::SCHEMA_VERSION), including the extensions it
//! hosts, such as `win`, by `examples/generate_schema.rs`. They are compiled
//! in: a lookup is a binary search, and nothing is parsed or can fail at run
//! time.
//!
//! Its purpose is to check configuration when it loads, such as a source
//! definition or a rule mapping, so that a misspelled attribute is an error
//! at startup rather than a field nobody ever matches.
//!
//! # Example
//!
//! ```
//! use goliath_ocsf::schema::{self, Base};
//!
//! let process_activity = schema::class(1007).ok_or("unknown class")?;
//! let found = process_activity.resolve("process.file.path")?;
//! assert_eq!(found.attribute.type_name(), "file_path_t");
//! assert_eq!(found.attribute.base(), Base::String);
//!
//! let error = process_activity.resolve("process.file.pth").unwrap_err();
//! assert_eq!(error.to_string(), "`process.file.pth`: object `file` has no attribute `pth`");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Generated: one line per attribute reads better than rustfmt's layout, and
// uids are written as OCSF writes them.
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
mod tables;

pub(crate) use tables::VERSION;

use thiserror::Error;

/// The primitive an attribute is stored as.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// `boolean_t`.
    Boolean,
    /// `integer_t` and the types built on it, such as `port_t`.
    Integer,
    /// `long_t` and the types built on it, such as `timestamp_t`.
    Long,
    /// `float_t`.
    Float,
    /// `string_t` and the types built on it, such as `file_path_t`.
    String,
    /// `json_t`: any JSON value.
    Json,
    /// An object; [`Attribute::object`] says which.
    Object,
}

/// An attribute of a class or object.
#[derive(Debug, PartialEq, Eq)]
pub struct Attribute {
    name: &'static str,
    type_name: &'static str,
    base: Base,
    array: bool,
    values: &'static [i64],
}

impl Attribute {
    const fn new(
        name: &'static str,
        type_name: &'static str,
        base: Base,
        array: bool,
        values: &'static [i64],
    ) -> Self {
        Self {
            name,
            type_name,
            base,
            array,
            values,
        }
    }

    /// The attribute's name, such as `cmd_line`.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The OCSF type, such as `file_path_t`, or for an object the object's
    /// name, such as `process`.
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// The primitive the type is stored as.
    pub fn base(&self) -> Base {
        self.base
    }

    /// Whether the attribute holds an array of its type.
    pub fn is_array(&self) -> bool {
        self.array
    }

    /// The values an enumerated integer attribute defines, such as the
    /// `activity_id` of a class, in ascending order. Empty for an attribute
    /// that is not an enumeration.
    pub fn enum_values(&self) -> &'static [i64] {
        self.values
    }

    /// The object an object attribute holds.
    pub fn object(&self) -> Option<&'static Object> {
        match self.base {
            Base::Object => object(self.type_name),
            _ => None,
        }
    }
}

/// An event class.
#[derive(Debug, PartialEq, Eq)]
pub struct Class {
    uid: u32,
    name: &'static str,
    attributes: &'static [Attribute],
}

impl Class {
    const fn new(uid: u32, name: &'static str, attributes: &'static [Attribute]) -> Self {
        Self {
            uid,
            name,
            attributes,
        }
    }

    /// `class_uid`.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The class name, such as `process_activity`. An extension class is
    /// prefixed with its extension, as in `win/registry_value_activity`.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The attributes, sorted by name.
    pub fn attributes(&self) -> &'static [Attribute] {
        self.attributes
    }

    /// The attribute with this name.
    pub fn attribute(&self, name: &str) -> Option<&'static Attribute> {
        find(self.attributes, name)
    }

    /// The attribute a dotted path such as `process.file.path` names.
    ///
    /// # Errors
    ///
    /// When a segment is empty, names no attribute of the object it is in,
    /// or continues past an attribute that holds no object.
    pub fn resolve(&self, path: &str) -> Result<Resolution, PathError> {
        let mut segments = path.split('.');
        let first = segments.next().unwrap_or_default();
        let mut attribute = lookup(path, self.attributes, first, || {
            format!("class `{}`", self.name)
        })?;
        let mut within_array = false;
        for segment in segments {
            within_array |= attribute.array;
            let object = match attribute.object() {
                Some(object) if !object.is_free_form() => object,
                Some(_) => {
                    return Ok(Resolution {
                        attribute,
                        within_array,
                        free_form: true,
                    });
                }
                None if attribute.base == Base::Json => {
                    return Ok(Resolution {
                        attribute,
                        within_array,
                        free_form: true,
                    });
                }
                None => {
                    return Err(PathError::NotAnObject {
                        path: path.to_owned(),
                        attribute: attribute.name.to_owned(),
                        type_name: attribute.type_name.to_owned(),
                    });
                }
            };
            attribute = lookup(path, object.attributes, segment, || {
                format!("object `{}`", object.name)
            })?;
        }
        Ok(Resolution {
            attribute,
            within_array,
            free_form: false,
        })
    }
}

/// An object, such as `process` or `file`.
#[derive(Debug, PartialEq, Eq)]
pub struct Object {
    name: &'static str,
    attributes: &'static [Attribute],
}

impl Object {
    const fn new(name: &'static str, attributes: &'static [Attribute]) -> Self {
        Self { name, attributes }
    }

    /// The object name, such as `process`, prefixed with its extension if it
    /// comes from one, as in `win/reg_value`.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The attributes, sorted by name.
    pub fn attributes(&self) -> &'static [Attribute] {
        self.attributes
    }

    /// The attribute with this name.
    pub fn attribute(&self, name: &str) -> Option<&'static Attribute> {
        find(self.attributes, name)
    }

    /// Whether the object takes any members, as `unmapped` does.
    pub fn is_free_form(&self) -> bool {
        self.name == "object"
    }
}

/// Where a path led.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    /// The attribute the path names, or, when [`free_form`](Self::free_form)
    /// is set, the free-form attribute it continues into.
    pub attribute: &'static Attribute,
    /// Whether the path passes through an array before its last attribute,
    /// as `attacks.technique.uid` does, so that it names a value in each
    /// element rather than one value.
    pub within_array: bool,
    /// Whether the path continues into an attribute that takes any members,
    /// such as `unmapped` or a `json_t`, whose type the schema leaves open.
    pub free_form: bool,
}

/// Why a path names no attribute.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    /// A segment names no attribute of the class or object it is in.
    #[error("`{path}`: {parent} has no attribute `{segment}`")]
    Unknown {
        /// The path.
        path: String,
        /// The class or object, such as ``object `file` ``.
        parent: String,
        /// The segment.
        segment: String,
    },
    /// The path continues past an attribute that holds no object.
    #[error("`{path}`: `{attribute}` is `{type_name}`, which has no attributes")]
    NotAnObject {
        /// The path.
        path: String,
        /// The attribute.
        attribute: String,
        /// Its type.
        type_name: String,
    },
}

/// The class with this `class_uid`.
pub fn class(uid: u32) -> Option<&'static Class> {
    tables::CLASSES
        .binary_search_by_key(&uid, |class| class.uid)
        .ok()
        .and_then(|index| tables::CLASSES.get(index))
}

/// Every class, sorted by `class_uid`.
pub fn classes() -> &'static [Class] {
    tables::CLASSES
}

/// The object with this name, such as `process`.
pub fn object(name: &str) -> Option<&'static Object> {
    tables::OBJECTS
        .binary_search_by_key(&name, |object| object.name)
        .ok()
        .and_then(|index| tables::OBJECTS.get(index))
}

fn find(attributes: &'static [Attribute], name: &str) -> Option<&'static Attribute> {
    attributes
        .binary_search_by_key(&name, |attribute| attribute.name)
        .ok()
        .and_then(|index| attributes.get(index))
}

fn lookup(
    path: &str,
    attributes: &'static [Attribute],
    segment: &str,
    parent: impl FnOnce() -> String,
) -> Result<&'static Attribute, PathError> {
    find(attributes, segment).ok_or_else(|| PathError::Unknown {
        path: path.to_owned(),
        parent: parent(),
        segment: segment.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted_for_binary_search() {
        assert!(
            tables::CLASSES
                .windows(2)
                .all(|pair| pair[0].uid < pair[1].uid)
        );
        assert!(
            tables::OBJECTS
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
        );
        let lists = tables::CLASSES
            .iter()
            .map(|class| class.attributes)
            .chain(tables::OBJECTS.iter().map(|object| object.attributes));
        for attributes in lists {
            assert!(
                attributes
                    .windows(2)
                    .all(|pair| pair[0].name < pair[1].name)
            );
        }
    }

    #[test]
    fn every_object_attribute_names_an_object() {
        let lists = tables::CLASSES
            .iter()
            .map(|class| class.attributes)
            .chain(tables::OBJECTS.iter().map(|object| object.attributes));
        for attribute in lists
            .flatten()
            .filter(|attribute| attribute.base == Base::Object)
        {
            assert!(attribute.object().is_some(), "{}", attribute.type_name);
        }
    }

    #[test]
    fn nested_paths_resolve_to_their_type() {
        let class = class(1007).unwrap();
        assert_eq!(class.name(), "process_activity");
        let found = class.resolve("process.parent_process.pid").unwrap();
        assert_eq!(
            (found.attribute.type_name(), found.attribute.base()),
            ("integer_t", Base::Integer)
        );
        assert!(!found.within_array && !found.free_form);
        assert_eq!(
            class.resolve("time").unwrap().attribute.type_name(),
            "timestamp_t"
        );
        assert_eq!(
            class
                .resolve("process")
                .unwrap()
                .attribute
                .object()
                .unwrap()
                .name(),
            "process"
        );
    }

    #[test]
    fn extension_classes_resolve() {
        let class = class(201_002).unwrap();
        assert_eq!(class.name(), "win/registry_value_activity");
        assert_eq!(
            class.resolve("reg_value.path").unwrap().attribute.base(),
            Base::String
        );
    }

    #[test]
    fn enumerations_keep_their_values() {
        let class = class(1007).unwrap();
        assert!(
            class
                .attribute("activity_id")
                .unwrap()
                .enum_values()
                .contains(&1)
        );
        let os_type = class.resolve("device.os.type_id").unwrap().attribute;
        assert!(os_type.enum_values().contains(&100));
        assert!(class.attribute("time").unwrap().enum_values().is_empty());
    }

    #[test]
    fn arrays_and_free_form_attributes_are_reported() {
        let class = class(1007).unwrap();
        let found = class.resolve("attacks.technique.uid").unwrap();
        assert!(found.within_array && !found.free_form);
        let found = class.resolve("unmapped.OriginalFileName").unwrap();
        assert!(found.free_form && !found.within_array);
        assert_eq!(found.attribute.name(), "unmapped");
    }

    #[test]
    fn bad_paths_say_where_they_went_wrong() {
        let class = class(1007).unwrap();
        assert_eq!(
            class.resolve("proces.pid").unwrap_err().to_string(),
            "`proces.pid`: class `process_activity` has no attribute `proces`"
        );
        assert_eq!(
            class.resolve("process.pid.value").unwrap_err().to_string(),
            "`process.pid.value`: `pid` is `integer_t`, which has no attributes"
        );
        assert!(matches!(class.resolve(""), Err(PathError::Unknown { .. })));
        assert!(matches!(
            class.resolve("process..pid"),
            Err(PathError::Unknown { .. })
        ));
    }

    #[test]
    fn unknown_classes_and_objects_are_absent() {
        assert!(class(9_999_999).is_none());
        assert!(object("no_such_object").is_none());
        assert!(!classes().is_empty());
    }
}
