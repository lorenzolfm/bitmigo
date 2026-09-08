// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`RegtestOverrides`]: the activation knobs regtest exposes, spelled as Core spells them.
//!
//! The differential harness starts `bitcoind -regtest` and bitmigo from the same command
//! line, so this parser accepts exactly Core's `-testactivationheight=name@height` and
//! `-test=bip94` values and rejects everything else with Core's wording (`ReadRegTestArgs`,
//! `GetBuriedDeployment`, `init.cpp`; verified against bitcoind v31.1.0). It is pure: the
//! node's CLI hands it the text after the `=`. There is no versionbits knob, because there
//! is no versionbits machine.

use core::fmt;

use super::Height;

/// Longest value the parser looks at. Core has no such bound; a longer value cannot be a
/// valid knob, so it is reported as a format error rather than scanned.
const VALUE_LENGTH_MAX: usize = 256;

/// The buried heights regtest lets the operator move, plus BIP94. `None` means Core's
/// default, which [`super::ChainParams::regtest`] fills in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegtestOverrides {
    /// `bip34@height`; Core's default is 1.
    pub bip34: Option<Height>,
    /// `dersig@height`; Core's default is 1.
    pub bip66: Option<Height>,
    /// `cltv@height`; Core's default is 1.
    pub bip65: Option<Height>,
    /// `csv@height`; Core's default is 1.
    pub csv: Option<Height>,
    /// `segwit@height`; Core's default is 0.
    pub segwit: Option<Height>,
    /// `-test=bip94`: enforce BIP94's timewarp and first-block retarget rules.
    pub bip94: bool,
}

/// Why a regtest value was refused. `Display` gives Core's message, so the node can print
/// what bitcoind would have printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegtestArgError {
    /// No `@` in the value, or the value is longer than [`VALUE_LENGTH_MAX`].
    InvalidFormat(String),
    /// The text after `@` is not a height in `0..i32::MAX`.
    InvalidHeightValue(String),
    /// The text before `@` names no buried deployment.
    InvalidName(String),
    /// A `-test=` option that is not `bip94`. Core's other test options are node-side and
    /// never reach this crate; Core only warns about an unknown one, so the node decides
    /// whether this is fatal.
    UnrecognisedTestOption(String),
}

impl fmt::Display for RegtestArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(value) => {
                write!(
                    f,
                    "Invalid format ({value}) for -testactivationheight=name@height."
                )
            }
            Self::InvalidHeightValue(value) => {
                write!(
                    f,
                    "Invalid height value ({value}) for -testactivationheight=name@height."
                )
            }
            Self::InvalidName(value) => {
                write!(
                    f,
                    "Invalid name ({value}) for -testactivationheight=name@height."
                )
            }
            Self::UnrecognisedTestOption(option) => {
                write!(
                    f,
                    "Unrecognised option \"{option}\" provided in -test=<option>."
                )
            }
        }
    }
}

impl std::error::Error for RegtestArgError {}

impl RegtestOverrides {
    /// Applies one `-testactivationheight=` value. Core checks the format, then the height,
    /// then the name, so a bad height in a bad name reports the height. A later value for
    /// the same name replaces an earlier one, as Core's map assignment does.
    pub fn apply_test_activation_height(&mut self, value: &str) -> Result<(), RegtestArgError> {
        if value.len() > VALUE_LENGTH_MAX {
            return Err(RegtestArgError::InvalidFormat(value.to_owned()));
        }
        let Some((name, height_text)) = value.split_once('@') else {
            return Err(RegtestArgError::InvalidFormat(value.to_owned()));
        };
        let Some(height) = parse_height(height_text) else {
            return Err(RegtestArgError::InvalidHeightValue(value.to_owned()));
        };
        let slot = match name {
            "segwit" => &mut self.segwit,
            "bip34" => &mut self.bip34,
            "dersig" => &mut self.bip66,
            "cltv" => &mut self.bip65,
            "csv" => &mut self.csv,
            _ => return Err(RegtestArgError::InvalidName(value.to_owned())),
        };
        *slot = Some(height);
        Ok(())
    }

    /// Applies one `-test=` value.
    pub fn apply_test_option(&mut self, option: &str) -> Result<(), RegtestArgError> {
        if option == "bip94" {
            self.bip94 = true;
            Ok(())
        } else {
            Err(RegtestArgError::UnrecognisedTestOption(option.to_owned()))
        }
    }
}

/// Core's `ParseInt32` followed by `height < 0 || height >= INT_MAX`: decimal digits with
/// one optional sign, no whitespace, and a result in `0..i32::MAX`. Parsing as `u32` has
/// the same grammar and rejects the negative values in the same breath.
fn parse_height(text: &str) -> Option<Height> {
    let Ok(height) = text.parse::<u32>() else {
        return None;
    };
    if height >= Height::MAX.get() {
        return None;
    }
    Some(Height::new(height))
}

#[cfg(test)]
mod tests {
    use super::{Height, RegtestArgError, RegtestOverrides, VALUE_LENGTH_MAX};

    #[test]
    fn every_name_lands_in_its_slot() {
        let mut overrides = RegtestOverrides::default();
        overrides.apply_test_activation_height("segwit@10").unwrap();
        overrides.apply_test_activation_height("bip34@20").unwrap();
        overrides.apply_test_activation_height("dersig@30").unwrap();
        overrides.apply_test_activation_height("cltv@40").unwrap();
        overrides.apply_test_activation_height("csv@50").unwrap();
        assert_eq!(
            overrides,
            RegtestOverrides {
                segwit: Some(Height::new(10)),
                bip34: Some(Height::new(20)),
                bip66: Some(Height::new(30)),
                bip65: Some(Height::new(40)),
                csv: Some(Height::new(50)),
                bip94: false,
            }
        );
    }

    #[test]
    fn a_later_value_replaces_an_earlier_one() {
        let mut overrides = RegtestOverrides::default();
        overrides.apply_test_activation_height("segwit@10").unwrap();
        overrides.apply_test_activation_height("segwit@0").unwrap();
        assert_eq!(overrides.segwit, Some(Height::GENESIS));
    }

    /// Core's `ParseInt32` grammar: a leading `+` is fine, and the largest height is one
    /// below `INT_MAX` (bitcoind v31.1.0 rejects `segwit@2147483647`).
    #[test]
    fn height_grammar_is_cores() {
        let mut overrides = RegtestOverrides::default();
        overrides.apply_test_activation_height("csv@+5").unwrap();
        assert_eq!(overrides.csv, Some(Height::new(5)));
        overrides
            .apply_test_activation_height("csv@2147483646")
            .unwrap();
        assert_eq!(overrides.csv, Some(Height::new(2_147_483_646)));
    }

    /// The messages are bitcoind v31.1.0's, byte for byte, for the values it was fed.
    #[test]
    fn errors_carry_cores_messages() {
        let mut overrides = RegtestOverrides::default();
        let cases = [
            (
                "segwit",
                "Invalid format (segwit) for -testactivationheight=name@height.",
            ),
            (
                "foo@10",
                "Invalid name (foo@10) for -testactivationheight=name@height.",
            ),
            (
                "segwit@abc",
                "Invalid height value (segwit@abc) for -testactivationheight=name@height.",
            ),
            (
                "segwit@-1",
                "Invalid height value (segwit@-1) for -testactivationheight=name@height.",
            ),
            (
                "segwit@2147483647",
                "Invalid height value (segwit@2147483647) for -testactivationheight=name@height.",
            ),
        ];
        for (value, message) in cases {
            let error = overrides.apply_test_activation_height(value).unwrap_err();
            assert_eq!(error.to_string(), message, "{value}");
        }
        assert_eq!(overrides, RegtestOverrides::default());

        let error = overrides.apply_test_option("foo").unwrap_err();
        assert_eq!(
            error.to_string(),
            "Unrecognised option \"foo\" provided in -test=<option>."
        );
    }

    #[test]
    fn height_is_checked_before_name() {
        let mut overrides = RegtestOverrides::default();
        assert_eq!(
            overrides.apply_test_activation_height("foo@abc"),
            Err(RegtestArgError::InvalidHeightValue("foo@abc".to_owned())),
        );
        assert_eq!(
            overrides.apply_test_activation_height("@10"),
            Err(RegtestArgError::InvalidName("@10".to_owned())),
        );
        assert_eq!(
            overrides.apply_test_activation_height("segwit@1@2"),
            Err(RegtestArgError::InvalidHeightValue("segwit@1@2".to_owned())),
        );
        assert_eq!(
            overrides.apply_test_activation_height("segwit@ 1"),
            Err(RegtestArgError::InvalidHeightValue("segwit@ 1".to_owned())),
        );
        assert_eq!(
            overrides.apply_test_activation_height("segwit@"),
            Err(RegtestArgError::InvalidHeightValue("segwit@".to_owned())),
        );
    }

    #[test]
    fn an_overlong_value_is_a_format_error() {
        let mut overrides = RegtestOverrides::default();
        let value = format!("{}@1", "a".repeat(VALUE_LENGTH_MAX));
        assert_eq!(
            overrides.apply_test_activation_height(&value),
            Err(RegtestArgError::InvalidFormat(value.clone())),
        );
    }

    #[test]
    fn bip94_is_the_only_test_option() {
        let mut overrides = RegtestOverrides::default();
        overrides.apply_test_option("bip94").unwrap();
        assert!(overrides.bip94);
        assert_eq!(
            overrides.apply_test_option("addrman"),
            Err(RegtestArgError::UnrecognisedTestOption(
                "addrman".to_owned()
            )),
        );
        assert!(overrides.bip94);
    }
}
