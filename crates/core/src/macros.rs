//! Macros shared across `sec_core`.

/// Declares a `#[repr(u8)]` enum whose values go on the wire, with
/// `ALL`, every variant in declaration order, and `from_u8`, the inverse
/// of `as u8`, both generated from the one variant list.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident = $value:literal,)*
        }
    ) => {
        $(#[$meta])*
        #[repr(u8)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant = $value,)*
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: [Self; [$($name::$variant),*].len()] = [$($name::$variant),*];

            /// The variant whose wire value is `value`, if any.
            pub const fn from_u8(value: u8) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    wire_enum! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Signal {
            Stop = 3,
            Go = 7,
        }
    }

    #[test]
    fn every_variant_reads_back_from_its_wire_value() {
        for signal in Signal::ALL {
            assert_eq!(Signal::from_u8(signal as u8), Some(signal));
        }
        assert_eq!(Signal::ALL, [Signal::Stop, Signal::Go]);
    }

    #[test]
    fn a_value_no_variant_has_reads_as_none() {
        assert_eq!(Signal::from_u8(4), None);
    }
}
