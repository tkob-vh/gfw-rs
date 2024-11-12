//! Utils used in the engine crate.
//!

use nt_analyzer::{self, CombinedPropMap, PropMap, PropUpdate, PropUpdateType};

/// Processes a property update on the given CombinedPropMap.
///
/// # Arguments
///
/// * `cpm` - A mutable reference to the CombinedPropMap to be updated.
/// * `name` - The name of the property to be updated.
/// * `update` - An optional PropUpdate containing the update details.
///
/// # Returns
///
/// * `bool` - Returns true if the update was applied, false otherwise.
pub fn process_prop_update(
    cpm: &mut CombinedPropMap,
    name: &str,
    update: Option<PropUpdate>,
) -> bool {
    // Check if the update is Some and not None
    if let Some(update) = update {
        match update.update_type {
            // If the update type is None, return false
            PropUpdateType::None => false,

            // If the update type is Merge, merge the properties
            PropUpdateType::Merge => {
                let map = cpm.entry(name.to_string()).or_insert_with(PropMap::new);
                for (k, v) in update.map.iter() {
                    map.insert(k.to_owned(), v.to_owned());
                }
                true
            }

            // If the update type is Replace, replace the properties
            PropUpdateType::Replace => {
                cpm.insert(name.to_owned(), update.map);
                true
            }

            // If the update type is Delete, remove the properties
            PropUpdateType::Delete => {
                cpm.remove(name);
                true
            }
        }
    } else {
        // If the update is None, return false
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_analyzer::{CombinedPropMap, PropMap, PropUpdate, PropUpdateType};
    use std::{ops::Deref, rc::Rc};

    #[test]
    fn test_process_prop_update_none() {
        let mut cpm = CombinedPropMap::new();
        let update = PropUpdate {
            update_type: PropUpdateType::None,
            map: PropMap::new(),
        };
        assert!(!process_prop_update(&mut cpm, "test", Some(update)));
    }

    #[test]
    fn test_process_prop_update_merge() {
        let mut cpm = CombinedPropMap::new();
        let mut update_map = PropMap::new();
        update_map.insert("key1".to_string(), Rc::new("value1".to_string()));
        let update = PropUpdate {
            update_type: PropUpdateType::Merge,
            map: update_map,
        };
        assert!(process_prop_update(&mut cpm, "test", Some(update)));
        assert_eq!(
            cpm["test"]["key1"].downcast_ref::<String>().unwrap(),
            "value1"
        );
    }

    #[test]
    fn test_process_prop_update_replace() {
        let mut cpm = CombinedPropMap::new();
        let mut update_map = PropMap::new();
        update_map.insert("key1".to_string(), Rc::new("value1".to_string()));
        let update = PropUpdate {
            update_type: PropUpdateType::Replace,
            map: update_map,
        };
        assert!(process_prop_update(&mut cpm, "test", Some(update)));
        assert_eq!(
            cpm["test"]["key1"].downcast_ref::<String>().unwrap(),
            "value1"
        );
    }

    #[test]
    fn test_process_prop_update_delete() {
        let mut cpm = CombinedPropMap::new();
        let mut update_map = PropMap::new();
        update_map.insert("key1".to_string(), Rc::new("value1".to_string()));
        cpm.insert("test".to_string(), update_map);
        let update = PropUpdate {
            update_type: PropUpdateType::Delete,
            map: PropMap::new(),
        };
        assert!(process_prop_update(&mut cpm, "test", Some(update)));
        assert!(!cpm.contains_key("test"));
    }
}
