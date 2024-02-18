use aya::Pod;

/// A [`bool`] that is [`Pod`]
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Bool(pub bool);

unsafe impl Pod for Bool {}
