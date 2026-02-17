#![allow(dead_code)]

use std::mem;

use paste::paste;

pub(crate) trait BinaryToInt<T> {
    fn to_int<const START: usize, const END: usize>(self) -> T;
}

macro_rules! int_binary_convert_impl {
    ($($type:ty),+) => {
        $(
            impl BinaryToInt<$type> for &[u8] {
                fn to_int<const START: usize, const END: usize>(self) -> $type {
                    const { assert!(END - START == mem::size_of::<$type>()) }
                    <$type>::from_be_bytes(unsafe { to_array(&self[START..END]) })
                }
            }
        )+

        paste! {
            pub(crate) trait BinaryToIntN {
                $(
                    fn [<to_ $type>]<const START: usize>(self) -> $type;
                )+
            }

            impl BinaryToIntN for &[u8] {
                $(
                    fn [<to_ $type>]<const START: usize>(self) -> $type {
                        $type::from_be_bytes(unsafe { to_array(&self[START..START + mem::size_of::<$type>()]) })
                    }
                )+
            }
        }
    };
}

int_binary_convert_impl!(u8, u16, u32, u64, u128);

unsafe fn to_array<const N: usize>(s: &[u8]) -> [u8; N] {
    unsafe { *(s.as_ptr() as *const [u8; N]) }
}
