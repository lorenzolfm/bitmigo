use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version = "0.1.0", about = "A CLI tool to decode/encode various formats", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a target
    Decode {
        /// Decode a base58check encoded string
        #[arg(long)]
        base58check: String,
    },
}

#[derive(Debug)]
struct Base58Check {
    kind: Option<Base58CheckKind>,
    //version: u8,
    //payload: Vec<u8>,
    //checksum: Vec<u8>,
}

#[derive(Debug)]
enum Base58CheckKind {
    P2PKH { network: Network },
    P2SH { network: Network },
    WIF { network: Network },
    Bip32Pubkey { network: Network },
    Bip32Privkey { network: Network },
}

#[derive(Debug)]
enum Network {
    Mainnet,
    Testnet,
}

fn decode_base58(target: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();

    for c in target.chars() {
        match c {
            '1' => result.push(0),
            '2' => result.push(1),
            '3' => result.push(2),
            '4' => result.push(3),
            '5' => result.push(4),
            '6' => result.push(5),
            '7' => result.push(6),
            '8' => result.push(7),
            '9' => result.push(8),
            'A' => result.push(9),
            'B' => result.push(10),
            'C' => result.push(11),
            'D' => result.push(12),
            'E' => result.push(13),
            'F' => result.push(14),
            'G' => result.push(15),
            'H' => result.push(16),
            'J' => result.push(17),
            'K' => result.push(18),
            'L' => result.push(19),
            'M' => result.push(20),
            'N' => result.push(21),
            'P' => result.push(22),
            'Q' => result.push(23),
            'R' => result.push(24),
            'S' => result.push(25),
            'T' => result.push(26),
            'U' => result.push(27),
            'V' => result.push(28),
            'W' => result.push(29),
            'X' => result.push(30),
            'Y' => result.push(31),
            'Z' => result.push(32),
            'a' => result.push(33),
            'b' => result.push(34),
            'c' => result.push(35),
            'd' => result.push(36),
            'e' => result.push(37),
            'f' => result.push(38),
            'g' => result.push(39),
            'h' => result.push(40),
            'i' => result.push(41),
            'j' => result.push(42),
            'k' => result.push(43),
            'm' => result.push(44),
            'n' => result.push(45),
            'o' => result.push(46),
            'p' => result.push(47),
            'q' => result.push(48),
            'r' => result.push(49),
            's' => result.push(50),
            't' => result.push(51),
            'u' => result.push(52),
            'v' => result.push(53),
            'w' => result.push(54),
            'x' => result.push(55),
            'y' => result.push(56),
            'z' => result.push(57),
            _ => return Err(format!("Invalid base58 character: {}", c).into()),
        }
    }

    println!("{result:?}");

    Ok(result)
}

fn decode_base58check(target: &str) -> Result<Base58Check, Box<dyn std::error::Error>> {
    let bytes = decode_base58(target)?;

    let Some(version) = bytes.first() else {
        return Err("Invalid base58 string".into());
    };

    println!("version: {version}");

    let base58check = match version {
        0x00 => Base58Check {
            kind: Some(Base58CheckKind::P2PKH {
                network: Network::Mainnet,
            }),
        },
        0x05 => Base58Check {
            kind: Some(Base58CheckKind::P2SH {
                network: Network::Mainnet,
            }),
        },
        0x80 => Base58Check {
            // There's several version of private key enconding
            kind: Some(Base58CheckKind::WIF {
                network: Network::Mainnet,
            }),
        },
        0x6F => Base58Check {
            kind: Some(Base58CheckKind::P2PKH {
                network: Network::Testnet,
            }),
        },
        0xC4 => Base58Check {
            kind: Some(Base58CheckKind::P2SH {
                network: Network::Testnet,
            }),
        },
        0xEF => Base58Check {
            // Can be compressed or uncompressed, need to check
            kind: Some(Base58CheckKind::WIF {
                network: Network::Testnet,
            }),
        },
        _ => {
            let another = bytes.into_iter().take(4).collect::<Vec<u8>>();

            match another.as_slice() {
                [0x04, 0x88, 0xB2, 0x1E] => Base58Check {
                    kind: Some(Base58CheckKind::Bip32Pubkey {
                        network: Network::Mainnet,
                    }),
                },
                [0x04, 0x88, 0xAD, 0xE4] => Base58Check {
                    kind: Some(Base58CheckKind::Bip32Privkey {
                        network: Network::Mainnet,
                    }),
                },
                [0x04, 0x35, 0x87, 0xCF] => Base58Check {
                    kind: Some(Base58CheckKind::Bip32Pubkey {
                        network: Network::Testnet,
                    }),
                },
                [0x04, 0x35, 0x83, 0x94] => Base58Check {
                    kind: Some(Base58CheckKind::Bip32Privkey {
                        network: Network::Testnet,
                    }),
                },
                _ => Base58Check { kind: None },
            }
        }
    };

    Ok(base58check)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let outcome = match &cli.command {
        Commands::Decode { base58check } => decode_base58check(base58check)?,
    };

    println!("{outcome:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_decode_base58check() {
        let outcome = super::decode_base58check("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem").unwrap();

        assert!(matches!(
            outcome.kind.unwrap(),
            super::Base58CheckKind::P2PKH {
                network: super::Network::Mainnet
            }
        ));

        let outcome = super::decode_base58check("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX").unwrap();

        assert!(matches!(
            outcome.kind.unwrap(),
            super::Base58CheckKind::P2PKH {
                network: super::Network::Mainnet
            }
        ));
    }
}
