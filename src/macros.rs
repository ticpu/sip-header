/// Generates a non-exhaustive enum mapping Rust variants to canonical protocol strings.
///
/// Produces: enum definition + `as_str()` + `Display` + `AsRef<str>` + `FromStr`.
/// `FromStr` uses `eq_ignore_ascii_case` — appropriate for user-facing catalog
/// types (header names, variable names) where input may come from config files.
/// Wire protocol state types use hand-written strict `FromStr` instead.
/// The error type must be defined separately (matching existing crate patterns like
/// `ParseEventHeaderError`, `ParseChannelVariableError`).
///
/// # Example
///
/// ```ignore
/// define_header_enum! {
///     error_type: ParseMyEnumError,
///     /// Doc comment for the enum.
///     pub enum MyEnum {
///         Foo => "foo-wire",
///         Bar => "bar-wire",
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_header_enum {
    (
        error_type: $Err:ident,
        $(#[$enum_meta:meta])*
        $vis:vis enum $Name:ident {
            $(
                $(#[$var_meta:meta])*
                $variant:ident => $wire:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[non_exhaustive]
        #[allow(missing_docs)]
        $vis enum $Name {
            $(
                $(#[$var_meta])*
                $variant,
            )+
        }

        impl $Name {
            /// Canonical protocol string.
            // allow(unused_doc_comments): variant doc attrs are propagated into
            // match arms so that #[cfg] attrs also propagate; the doc attrs
            // are harmless noise here.
            #[allow(unused_doc_comments)]
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        $(#[$var_meta])*
                        $Name::$variant => $wire,
                    )+
                }
            }
        }

        impl std::fmt::Display for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl AsRef<str> for $Name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl std::str::FromStr for $Name {
            type Err = $Err;

            #[allow(unused_doc_comments)]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $(
                    $(#[$var_meta])*
                    if s.eq_ignore_ascii_case($wire) {
                        return Ok($Name::$variant);
                    }
                )+
                Err($Err(s.to_string()))
            }
        }
    };
}

/// Implements `FromStr` by delegating to an inherent `parse(&str)` method.
macro_rules! impl_from_str_via_parse {
    ($Type:ty, $Err:ty) => {
        impl std::str::FromStr for $Type {
            type Err = $Err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    define_header_enum! {
        tests_mod: test_enum_generated,
        error_type: ParseTestEnumError => "unknown test value",
        /// Exercises generated error newtype, `ALL`, and test module.
        pub(crate) enum TestEnum {
            /// `Foo-Wire`.
            Foo => "Foo-Wire",
            /// `Bar-Wire`.
            Bar => "Bar-Wire",
            /// `Draft-Wire`.
            #[cfg(feature = "draft")]
            Draft => "Draft-Wire",
        }
    }

    /// Hand-written error for the old-form invocation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct ParseOldEnumError(pub String);

    impl std::fmt::Display for ParseOldEnumError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "unknown old value: {}", self.0)
        }
    }

    impl std::error::Error for ParseOldEnumError {}

    define_header_enum! {
        error_type: ParseOldEnumError,
        /// Old-form invocation stays source-compatible.
        pub(crate) enum OldEnum {
            /// `Old-Wire`.
            One => "Old-Wire",
        }
    }

    #[test]
    fn generated_error_display() {
        let e = ParseTestEnumError("nope".to_string());
        assert_eq!(e.to_string(), "unknown test value: nope");
    }

    #[test]
    fn all_const_respects_cfg() {
        #[cfg(not(feature = "draft"))]
        assert_eq!(TestEnum::ALL, &[TestEnum::Foo, TestEnum::Bar]);
        #[cfg(feature = "draft")]
        assert_eq!(
            TestEnum::ALL,
            &[TestEnum::Foo, TestEnum::Bar, TestEnum::Draft]
        );
    }

    #[test]
    fn old_form_generates_all() {
        assert_eq!(OldEnum::ALL, &[OldEnum::One]);
        assert_eq!("old-wire".parse::<OldEnum>(), Ok(OldEnum::One));
    }
}
