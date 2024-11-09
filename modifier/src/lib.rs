//! This module defines traits and error types for creating and handling UDP packet modifiers.
//!
//! The `Modifier` trait allows for the creation of new instances of modifiers with specific arguments.
//! The `Instance` trait is a marker trait for instances of modifiers.
//! The `UDPModifierInstance` trait extends `Instance` and provides a method for processing UDP packets.
//!
//! The module also defines two error types: `ErrInvalidPacket` and `ErrInvalidArgs`, which are used to
//! indicate errors related to invalid packets and invalid arguments, respectively.

pub mod udp;

use std::sync::Arc;
use std::{any::Any, collections::HashMap};

/// The `Modifier` trait allows for the creation of new instances of modifiers with specific arguments.
pub trait Modifier {
    /// Returns the name of the modifier.
    fn name(&self) -> &str;

    /// Creates a new instance of the modifier with the provided arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - A hashmap containing the arguments for the modifier.
    ///
    /// # Returns
    ///
    /// * `Option<Box<dyn Instance>>` - A boxed instance of the modifier or `None` if the arguments are invalid.
    fn new_instance(&self, args: HashMap<String, std::string::String>)
        -> Option<Arc<dyn Instance>>;
}

/// The `Instance` trait is a marker trait for instances of modifiers.
pub trait Instance: Any {
    fn as_any(&self) -> &dyn Any;
}

/// The `UDPModifierInstance` trait extends `Instance` and provides a method for processing UDP packets.
pub trait UDPModifierInstance: Instance {
    /// Processes a UDP packet and returns a modified UDP packet.
    ///
    /// # Arguments
    ///
    /// * `data` - A mutable reference to a byte slice representing the UDP packet.
    ///
    /// # Returns
    ///
    /// * `Option<Vec<u8>>` - A vector containing the modified UDP packet or `None` if the packet is invalid.
    fn process(&self, data: &mut [u8]) -> Option<Vec<u8>>;
}
