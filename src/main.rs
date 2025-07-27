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
    // These fields are currently not used in our tests
    // version: u8,
    // payload: Vec<u8>,
    // checksum: Vec<u8>,
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

fn decode_base58(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const ALPHABET: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if input.is_empty() {
        return Ok(Vec::new());
    }

    let Some(zero) = ALPHABET.chars().nth(0) else {
        return Err("Empty vec should have been checked earlier".into());
    };

    let leading_zeros = input.chars().take_while(|&c| c == zero).count();

    let significant_chars = input.chars().skip(leading_zeros).collect::<String>();

    if significant_chars.is_empty() {
        return Ok(vec![0; leading_zeros]);
    }

    /*
    let zeros = target.chars().take_while(|&c| c == '1').count();

    let mut result: Vec<u8> = vec![0];

    for c in target.chars().skip_while(|&c| c == '1') {
        let idx = match ALPHABET.find(c) {
            Some(idx) => idx,
            None => return Err(format!("Invalid base58 character: {}", c).into()),
        };

        let mut carry = idx;
        for byte in result.iter_mut() {
            let x = (*byte as usize) * 58 + carry;
            *byte = (x & 0xff) as u8;
            carry = x >> 8;
        }

        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut final_result = vec![0; zeros];

    final_result.extend(result.into_iter().rev());

    Ok(final_result)
    */
    Ok(Vec::new())
}

fn decode_base58check(target: &str) -> Result<Base58Check, Box<dyn std::error::Error>> {
    let bytes = decode_base58(target)?;

    /*
    if bytes.len() < 5 {
        return Err("Invalid base58check string: too short".into());
    }

    let version = bytes[0];

    let kind = match version {
        0x00 => Some(Base58CheckKind::P2PKH {
            network: Network::Mainnet,
        }),
        0x05 => Some(Base58CheckKind::P2SH {
            network: Network::Mainnet,
        }),
        0x80 => Some(Base58CheckKind::WIF {
            network: Network::Mainnet,
        }),
        0x6F => Some(Base58CheckKind::P2PKH {
            network: Network::Testnet,
        }),
        0xC4 => Some(Base58CheckKind::P2SH {
            network: Network::Testnet,
        }),
        0xEF => Some(Base58CheckKind::WIF {
            network: Network::Testnet,
        }),
        _ => {
            if bytes.len() >= 8 && bytes[0] == 0x04 {
                let version_bytes = &bytes[0..4];
                match version_bytes {
                    [0x04, 0x88, 0xB2, 0x1E] => Some(Base58CheckKind::Bip32Pubkey {
                        network: Network::Mainnet,
                    }),
                    [0x04, 0x88, 0xAD, 0xE4] => Some(Base58CheckKind::Bip32Privkey {
                        network: Network::Mainnet,
                    }),
                    [0x04, 0x35, 0x87, 0xCF] => Some(Base58CheckKind::Bip32Pubkey {
                        network: Network::Testnet,
                    }),
                    [0x04, 0x35, 0x83, 0x94] => Some(Base58CheckKind::Bip32Privkey {
                        network: Network::Testnet,
                    }),
                    _ => None,
                }
            } else {
                None
            }
        }
    };
    */

    let base58check = Base58Check { kind: None };

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

        //let outcome = super::decode_base58check("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX").unwrap();

        //assert!(matches!(
        //outcome.kind.unwrap(),
        //super::Base58CheckKind::P2SH {
        //network: super::Network::Mainnet
        //}
        //));
    }
}
