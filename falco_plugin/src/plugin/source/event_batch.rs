use falco_event::events::EventToBytes;

/// # An object that describes a batch of events
///
/// This is only available by reference, not by ownership, since the data needs to outlive
/// the plugin API call and is stored elsewhere (in a wrapper struct that's not exposed to
/// plugin developers)
#[derive(Debug)]
pub struct EventBatch<'a> {
    alloc: &'a bumpalo::Bump,
    pointers: bumpalo::collections::Vec<'a, *const u8>,
}

impl EventBatch<'_> {
    pub(in crate::plugin::source) fn new(alloc: &bumpalo::Bump) -> EventBatch<'_> {
        let pointers = bumpalo::collections::Vec::new_in(alloc);
        EventBatch { alloc, pointers }
    }

    /// # Add an event to a batch
    ///
    /// The event can be any type, but please note that the framework may have different
    /// opinions on this. For example, only source plugins with the `syscall` source can generate
    /// events other than [`source::PluginEvent`](`crate::source::PluginEvent`)
    ///
    /// **Note**: to generate such events, you may use
    /// the [`source::SourcePluginInstance::plugin_event`](`crate::source::SourcePluginInstance::plugin_event`)
    /// helper method.
    pub fn add(&mut self, event: impl EventToBytes) -> std::io::Result<()> {
        let mut event_buf =
            bumpalo::collections::Vec::with_capacity_in(event.binary_size(), self.alloc);
        event.write(&mut event_buf)?;
        self.pointers.push(event_buf.as_ptr());
        Ok(())
    }

    /// # Reserve space for a specific number of events
    ///
    /// If your plugin knows it's going to generate a specific number of events
    /// in a particular batch, it can call this method to preallocate some space
    /// and save a bit of overhead.
    ///
    /// The passed value is only a hint, the actual batch can be smaller or larger
    /// than the reserved size, but that mostly defeats the purpose of reserving
    /// space
    pub fn reserve(&mut self, num_events: usize) {
        self.pointers.reserve(num_events);
    }

    pub(in crate::plugin::source) fn get_events(&self) -> &[*const u8] {
        self.pointers.as_slice()
    }
}
