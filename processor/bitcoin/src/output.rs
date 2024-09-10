use std::io;

use ciphersuite::{Ciphersuite, Secp256k1};

use bitcoin_serai::{
  bitcoin::{
    hashes::Hash as HashTrait,
    key::{Parity, XOnlyPublicKey},
    consensus::Encodable,
    script::Instruction,
  },
  wallet::ReceivedOutput as WalletOutput,
};

use scale::{Encode, Decode, IoReader};
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{Coin, Amount, Balance, ExternalAddress},
  networks::bitcoin::Address,
};

use primitives::{OutputType, ReceivedOutput};

#[derive(Clone, PartialEq, Eq, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize)]
pub(crate) struct OutputId([u8; 36]);
impl Default for OutputId {
  fn default() -> Self {
    Self([0; 36])
  }
}
impl AsRef<[u8]> for OutputId {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
impl AsMut<[u8]> for OutputId {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Output {
  kind: OutputType,
  presumed_origin: Option<Address>,
  output: WalletOutput,
  data: Vec<u8>,
}

impl ReceivedOutput<<Secp256k1 as Ciphersuite>::G, Address> for Output {
  type Id = OutputId;
  type TransactionId = [u8; 32];

  fn kind(&self) -> OutputType {
    self.kind
  }

  fn id(&self) -> Self::Id {
    let mut id = OutputId::default();
    self.output.outpoint().consensus_encode(&mut id.as_mut()).unwrap();
    id
  }

  fn transaction_id(&self) -> Self::TransactionId {
    self.output.outpoint().txid.to_raw_hash().to_byte_array()
  }

  fn key(&self) -> <Secp256k1 as Ciphersuite>::G {
    // We read the key from the script pubkey so we don't have to independently store it
    let script = &self.output.output().script_pubkey;

    // These assumptions are safe since it's an output we successfully scanned
    assert!(script.is_p2tr());
    let Instruction::PushBytes(key) = script.instructions_minimal().last().unwrap().unwrap() else {
      panic!("last item in v1 Taproot script wasn't bytes")
    };
    let key = XOnlyPublicKey::from_slice(key.as_ref())
      .expect("last item in v1 Taproot script wasn't a valid x-only public key");

    // Convert to a full key
    let key = key.public_key(Parity::Even);
    // Convert to a k256 key (from libsecp256k1)
    let output_key = Secp256k1::read_G(&mut key.serialize().as_slice()).unwrap();
    // The output's key minus the output's offset is the root key
    output_key - (<Secp256k1 as Ciphersuite>::G::GENERATOR * self.output.offset())
  }

  fn presumed_origin(&self) -> Option<Address> {
    self.presumed_origin.clone()
  }

  fn balance(&self) -> Balance {
    Balance { coin: Coin::Bitcoin, amount: Amount(self.output.value()) }
  }

  fn data(&self) -> &[u8] {
    &self.data
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.kind.write(writer)?;
    let presumed_origin: Option<ExternalAddress> = self.presumed_origin.clone().map(Into::into);
    writer.write_all(&presumed_origin.encode())?;
    self.output.write(writer)?;
    writer.write_all(&u16::try_from(self.data.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.data)
  }

  fn read<R: io::Read>(mut reader: &mut R) -> io::Result<Self> {
    Ok(Output {
      kind: OutputType::read(reader)?,
      presumed_origin: {
        Option::<ExternalAddress>::decode(&mut IoReader(&mut reader))
          .map_err(|e| io::Error::other(format!("couldn't decode ExternalAddress: {e:?}")))?
          .map(|address| {
            Address::try_from(address)
              .map_err(|()| io::Error::other("couldn't decode Address from ExternalAddress"))
          })
          .transpose()?
      },
      output: WalletOutput::read(reader)?,
      data: {
        let mut data_len = [0; 2];
        reader.read_exact(&mut data_len)?;

        let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
        reader.read_exact(&mut data)?;
        data
      },
    })
  }
}
