//! Field Accessors
//!
//! This module provides a wrapper to access fields in a packet.

/// Target trait
///
/// This trait is used to convert between the underlay type and the target type.
pub trait Target<U> {
    /// Convert from underlay to target
    fn from_underlay(x: U) -> Self;

    /// Convert from target to underlay
    fn into_underlay(self) -> U;
}

impl<T, U> Target<U> for T
where
    T: From<U> + Into<U>,
{
    fn from_underlay(x: U) -> Self {
        x.into()
    }
    fn into_underlay(self) -> U {
        self.into()
    }
}

/// Underlay trait
///
/// This trait marks the types that can be used as underlay for fields and
/// provides methods to operate on them.
pub trait Underlay: Copy {
    /// Convert from big-endian
    fn from_be(x: Self) -> Self;
    /// Convert from little-endian
    fn from_le(x: Self) -> Self;
    /// Convert to big-endian
    fn to_be(self) -> Self;
    /// Convert to little-endian
    fn to_le(self) -> Self;

    /// Shift left
    fn shl(self, shift: u8) -> Self;
    /// Shift right
    fn shr(self, shift: u8) -> Self;
    /// Mask
    ///
    /// This method is like `bitand` but it takes a `u64` as argument
    fn mask(self, mask: u64) -> Self;
    /// Bitwise and
    fn bitand(self, rhs: Self) -> Self;
    /// Bitwise or
    fn bitor(self, rhs: Self) -> Self;
}

/// Implement the Underlay trait for given types
macro_rules! impl_underlay {
    ($($t:ty),*) => {
        $(
            impl Underlay for $t {
                #[inline]
                fn from_be(x: Self) -> Self {
                    Self::from_be(x)
                }
                #[inline]
                fn from_le(x: Self) -> Self {
                    Self::from_le(x)
                }
                #[inline]
                fn to_be(self) -> Self {
                    Self::to_be(self)
                }
                #[inline]
                fn to_le(self) -> Self {
                    Self::to_le(self)
                }
                #[inline]
                fn shl(self, shift: u8) -> Self {
                    self << shift
                }
                #[inline]
                fn shr(self, shift: u8) -> Self {
                    self >> shift
                }
                #[inline]
                fn mask(self, mask: u64) -> Self {
                    self & mask as Self
                }
                #[inline]
                fn bitand(self, rhs: Self) -> Self {
                    self & rhs
                }
                #[inline]
                fn bitor(self, rhs: Self) -> Self {
                    self | rhs
                }
            }
        )*
    };
    ($($l:literal),*) => {
        $(
            impl Underlay for [u8; $l] {
                #[inline]
                fn from_be(x: Self) -> Self {
                    x
                }
                #[inline]
                fn from_le(x: Self) -> Self {
                    let mut x = x;
                    x.reverse();
                    x
                }
                #[inline]
                fn to_be(self) -> Self {
                    self
                }
                #[inline]
                fn to_le(self) -> Self {
                    let mut x = self;
                    x.reverse();
                    x
                }
                #[inline]
                fn shl(self, shift: u8) -> Self {
                    let mut tmp: [u8; 8] = [0; 8];
                    for i in 8-$l..8 {
                        tmp[i] = self[i-(8-$l)];
                    }
                    let mut tmp = u64::from_be_bytes(tmp);
                    tmp <<= shift;
                    let tmp = tmp.to_be_bytes();
                    let ret = tmp[8-$l..8].try_into().unwrap();
                    ret
                }
                #[inline]
                fn shr(self, shift: u8) -> Self {
                    let mut tmp: [u8; 8] = [0; 8];
                    for i in 8-$l..8 {
                        tmp[i] = self[i-(8-$l)];
                    }
                    let mut tmp = u64::from_be_bytes(tmp);
                    tmp >>= shift;
                    let tmp = tmp.to_be_bytes();
                    let ret = tmp[8-$l..8].try_into().unwrap();
                    ret
                }
                #[inline]
                fn mask(self, mask: u64) -> Self {
                    let mut ret = [0; $l];
                    let mask = mask.to_be_bytes();
                    for i in 0..$l {
                        ret[i] = self[i] & mask[8 - $l + i]
                    }
                    ret
                }
                #[inline]
                fn bitand(self, rhs: Self) -> Self {
                    let mut ret = [0; $l];
                    for i in 0..$l {
                        ret[i] = self[i] & rhs[i];
                    }
                    ret
                }
                #[inline]
                fn bitor(self, rhs: Self) -> Self {
                    let mut ret = [0; $l];
                    for i in 0..$l {
                        ret[i] = self[i] | rhs[i];
                    }
                    ret
                }
            }
        )*
    }
}
impl_underlay!(u8, u16, u32, u64);
impl_underlay!(3, 5, 6, 7);

/// Endianness trait
pub trait Endianness {}

/// Most significant byte first (big-endian)
#[derive(Debug, Clone, Copy)]
pub struct Msb;
/// Least significant byte first (little-endian)
#[derive(Debug, Clone, Copy)]
pub struct Lsb;

impl Endianness for Msb {}
impl Endianness for Lsb {}

/// Field specification
///
/// This trait wraps the field specification:
/// - The target type `T`
/// - The underlay type `U`
/// - The mask value `MASK`
/// - The shift value `SHIFT`
pub trait FieldSpec {
    /// The target type
    ///
    /// This is the type of the value that the field represents
    type T: Target<Self::U>;

    /// The underlay type
    ///
    /// This is the type of the value that the field is stored in
    type U: Underlay;

    /// The mask value
    const MASK: u64 = u64::MAX;

    /// The shift value
    const SHIFT: u8 = 0;
}

/// Field specification macro
///
/// This helper macro is used to define a field specification.
#[macro_export]
macro_rules! field_spec {
    // FieldSpec with only target and underlay
    ($name: ident, $t:ty, $u:ty) => {
        #[doc = stringify!($name)]
        // TODO: Add documentation
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl $crate::utils::field::FieldSpec for $name {
            type T = $t;
            type U = $u;
        }
    };

    // FieldSpec with target, underlay and mask
    ($name: ident, $t:ty, $u:ty, $m:expr) => {
        #[doc = stringify!($name)]
        // TODO: Add documentation
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl $crate::utils::field::FieldSpec for $name {
            type T = $t;
            type U = $u;
            const MASK: u64 = $m;
        }
    };

    // FieldSpec with target, underlay, mask and shift
    ($name: ident, $t:ty, $u:ty, $m:expr, $s:expr) => {
        #[doc = stringify!($name)]
        // TODO: Add documentation
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl $crate::utils::field::FieldSpec for $name {
            type T = $t;
            type U = $u;
            const MASK: u64 = $m;
            const SHIFT: u8 = $s;
        }
    };
}

/// Field accessor
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Field<F: FieldSpec, E: Endianness = Msb> {
    value: F::U,
    _marker: std::marker::PhantomData<(F::T, E)>,
}

impl<F: FieldSpec, E: Endianness> Field<F, E> {
    /// Get the inner value without any operations and conversions
    pub fn into_inner(self) -> F::U {
        self.value
    }
}

impl<F: FieldSpec> Field<F, Msb> {
    /// Get the **raw** value of the field
    ///
    /// **Note**: raw here means the mask and shift are applied but the value is
    /// not converted to the target type.
    pub fn raw(&self) -> F::U {
        if F::MASK == u64::MAX && F::SHIFT == 0 {
            F::U::from_be(self.value)
        } else if F::SHIFT == 0 {
            F::U::from_be(self.value).mask(F::MASK)
        } else {
            F::U::from_be(self.value).mask(F::MASK).shr(F::SHIFT)
        }
    }

    /// Get the value of the field
    pub fn get(&self) -> F::T {
        F::T::from_underlay(self.raw())
    }

    /// Set the value of the field
    pub fn set(&mut self, value: F::T) {
        if F::MASK == u64::MAX && F::SHIFT == 0 {
            self.value = value.into_underlay().to_be();
        } else if F::SHIFT == 0 {
            self.value = F::U::from_be(self.value)
                .mask(!F::MASK)
                .bitor(value.into_underlay())
                .to_be();
        } else {
            self.value = F::U::from_be(self.value)
                .mask(!F::MASK)
                .bitor(value.into_underlay().shl(F::SHIFT))
                .to_be();
        }
    }
}

impl<F: FieldSpec> Field<F, Lsb> {
    /// Get the **raw** value of the field
    ///
    /// **Note**: raw here means the mask and shift are applied but the value is
    /// not converted to the target type.
    pub fn raw(&self) -> F::U {
        if F::MASK == u64::MAX && F::SHIFT == 0 {
            F::U::from_le(self.value)
        } else if F::SHIFT == 0 {
            F::U::from_le(self.value).mask(F::MASK)
        } else {
            F::U::from_le(self.value).mask(F::MASK).shr(F::SHIFT)
        }
    }

    /// Get the value of the field
    pub fn get(&self) -> F::T {
        F::T::from_underlay(self.raw())
    }

    /// Set the value of the field
    pub fn set(&mut self, value: F::T) {
        if F::MASK == u64::MAX && F::SHIFT == 0 {
            self.value = value.into_underlay().to_le();
        } else if F::SHIFT == 0 {
            self.value = F::U::from_le(self.value)
                .mask(!F::MASK)
                .bitor(value.into_underlay())
                .to_le();
        } else {
            self.value = F::U::from_le(self.value)
                .mask(!F::MASK)
                .bitor(value.into_underlay().shl(F::SHIFT))
                .to_le();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field() {
        field_spec!(TestField, u16, u16, 0x0F00, 8);

        let mut field = Field::<TestField> {
            value: 0,
            _marker: std::marker::PhantomData,
        };
        assert_eq!(field.raw(), 0);
        assert_eq!(field.get(), 0);
        field.set(0x0F);
        assert_eq!(field.into_inner(), 0x000F);
        assert_eq!(field.raw(), 0x000F);
        assert_eq!(field.get(), 0x0F);
        field.set(0x0A);
        assert_eq!(field.into_inner(), 0x000A);
        assert_eq!(field.raw(), 0x000A);
        assert_eq!(field.get(), 0x0A);

        let mut field = Field::<TestField, Lsb> {
            value: 0,
            _marker: std::marker::PhantomData,
        };
        assert_eq!(field.raw(), 0);
        assert_eq!(field.get(), 0);
        field.set(0x0F);
        assert_eq!(field.into_inner(), 0x0F00);
        assert_eq!(field.raw(), 0x000F);
        assert_eq!(field.get(), 0x0F);
        field.set(0x0A);
        assert_eq!(field.into_inner(), 0x0A00);
        assert_eq!(field.raw(), 0x000A);
        assert_eq!(field.get(), 0x0A);
    }
}
