/// Trait implemented for owned event types
///
/// Similar to [`std::borrow::Borrow`], but different
/// as the borrowed type does not need to be a reference
pub trait Borrow {
    type Borrowed<'a>: Sized
    where
        Self: 'a;

    fn borrow(&self) -> Self::Borrowed<'_>;
}

/// Trait implemented for owned *field* types
///
/// The result of [`BorrowDeref::borrow_deref`] is the borrowed
/// counterpart of the owned type in question. In many cases, it's the same type
/// (for all fixed-size fields).
pub trait BorrowDeref {
    type Target<'a>: Sized
    where
        Self: 'a;

    fn borrow_deref(&self) -> Self::Target<'_>;
}
