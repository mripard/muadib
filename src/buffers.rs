//! Write buffer pool for `io_uring` bulk-in submissions.

const MAX_BUFFER_SLOTS: usize = 8;

/// Fixed-size pool of write buffers for in-flight `io_uring` submissions.
///
/// Slots are 1-indexed so they can be stored in a [`NonZeroU32`](core::num::NonZeroU32).
pub(crate) struct BufferManager {
    slots: [Option<Vec<u8>>; MAX_BUFFER_SLOTS],
}

impl BufferManager {
    /// Creates a new buffer manager with all slots free.
    pub(crate) fn new() -> Self {
        BufferManager {
            slots: [const { None }; MAX_BUFFER_SLOTS],
        }
    }

    /// Allocates a slot and returns its 1-based index and a mutable reference to the buffer.
    pub(crate) fn alloc(&mut self, capacity: usize) -> (u32, &mut Vec<u8>) {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .expect("all write slots in use");

        self.slots[slot] = Some(Vec::with_capacity(capacity));

        let slot_id = u32::try_from(slot + 1).expect("MAX_BUFFER_SLOTS fits in u32");

        (
            slot_id,
            self.slots[slot]
                .as_mut()
                .expect("We just inserted into this slot"),
        )
    }

    /// Frees a previously allocated slot by its 1-based index.
    pub(crate) fn free(&mut self, slot: u32) {
        let idx = usize::try_from(slot - 1).expect("slot index fits in usize");
        self.slots[idx] = None;
    }
}
