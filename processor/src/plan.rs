use std::io;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::group::GroupEncoding;
use frost::curve::Ciphersuite;

use crate::networks::{Output, Network};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<N: Network> {
  pub address: N::Address,
  pub data: Option<Vec<u8>>,
  pub amount: u64,
}

impl<N: Network> Payment<N> {
  pub fn transcript<T: Transcript>(&self, transcript: &mut T) {
    transcript.domain_separate(b"payment");
    transcript.append_message(b"address", self.address.to_string().as_bytes());
    if let Some(data) = self.data.as_ref() {
      transcript.append_message(b"data", data);
    }
    transcript.append_message(b"amount", self.amount.to_le_bytes());
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    // TODO: Don't allow creating Payments with an Address which can't be serialized
    let address: Vec<u8> = self
      .address
      .clone()
      .try_into()
      .map_err(|_| io::Error::new(io::ErrorKind::Other, "address couldn't be serialized"))?;
    writer.write_all(&u32::try_from(address.len()).unwrap().to_le_bytes())?;
    writer.write_all(&address)?;

    writer.write_all(&[u8::from(self.data.is_some())])?;
    if let Some(data) = &self.data {
      writer.write_all(&u32::try_from(data.len()).unwrap().to_le_bytes())?;
      writer.write_all(data)?;
    }

    writer.write_all(&self.amount.to_le_bytes())
  }

  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut buf = [0; 4];
    reader.read_exact(&mut buf)?;
    let mut address = vec![0; usize::try_from(u32::from_le_bytes(buf)).unwrap()];
    reader.read_exact(&mut address)?;
    let address = N::Address::try_from(address)
      .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid address"))?;

    let mut buf = [0; 1];
    reader.read_exact(&mut buf)?;
    let data = if buf[0] == 1 {
      let mut buf = [0; 4];
      reader.read_exact(&mut buf)?;
      let mut data = vec![0; usize::try_from(u32::from_le_bytes(buf)).unwrap()];
      reader.read_exact(&mut data)?;
      Some(data)
    } else {
      None
    };

    let mut buf = [0; 8];
    reader.read_exact(&mut buf)?;
    let amount = u64::from_le_bytes(buf);

    Ok(Payment { address, data, amount })
  }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Plan<N: Network> {
  pub key: <N::Curve as Ciphersuite>::G,
  pub inputs: Vec<N::Output>,
  pub payments: Vec<Payment<N>>,
  pub change: Option<N::Address>,
}
impl<N: Network> core::fmt::Debug for Plan<N> {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("Plan")
      .field("key", &hex::encode(self.key.to_bytes()))
      .field("inputs", &self.inputs)
      .field("payments", &self.payments)
      .field("change", &self.change.as_ref().map(|change| change.to_string()))
      .finish()
  }
}

impl<N: Network> Plan<N> {
  pub fn transcript(&self) -> RecommendedTranscript {
    let mut transcript = RecommendedTranscript::new(b"Serai Processor Plan ID");
    transcript.domain_separate(b"meta");
    transcript.append_message(b"network", N::ID);
    transcript.append_message(b"key", self.key.to_bytes());

    transcript.domain_separate(b"inputs");
    for input in &self.inputs {
      transcript.append_message(b"input", input.id());
    }

    transcript.domain_separate(b"payments");
    for payment in &self.payments {
      payment.transcript(&mut transcript);
    }

    if let Some(change) = &self.change {
      transcript.append_message(b"change", change.to_string());
    }

    transcript
  }

  pub fn id(&self) -> [u8; 32] {
    let challenge = self.transcript().challenge(b"id");
    let mut res = [0; 32];
    res.copy_from_slice(&challenge[.. 32]);
    res
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.key.to_bytes().as_ref())?;

    writer.write_all(&u32::try_from(self.inputs.len()).unwrap().to_le_bytes())?;
    for input in &self.inputs {
      input.write(writer)?;
    }

    writer.write_all(&u32::try_from(self.payments.len()).unwrap().to_le_bytes())?;
    for payment in &self.payments {
      payment.write(writer)?;
    }

    // TODO: Have Plan construction fail if change cannot be serialized
    let change = if let Some(change) = &self.change {
      change.clone().try_into().map_err(|_| {
        io::Error::new(
          io::ErrorKind::Other,
          format!(
            "an address we said to use as change couldn't be convered to a Vec<u8>: {}",
            change.to_string(),
          ),
        )
      })?
    } else {
      vec![]
    };
    assert!(serai_client::primitives::MAX_ADDRESS_LEN <= u8::MAX.into());
    writer.write_all(&[u8::try_from(change.len()).unwrap()])?;
    writer.write_all(&change)
  }

  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let key = N::Curve::read_G(reader)?;

    let mut inputs = vec![];
    let mut buf = [0; 4];
    reader.read_exact(&mut buf)?;
    for _ in 0 .. u32::from_le_bytes(buf) {
      inputs.push(N::Output::read(reader)?);
    }

    let mut payments = vec![];
    reader.read_exact(&mut buf)?;
    for _ in 0 .. u32::from_le_bytes(buf) {
      payments.push(Payment::<N>::read(reader)?);
    }

    let mut len = [0; 1];
    reader.read_exact(&mut len)?;
    let mut change = vec![0; usize::from(len[0])];
    reader.read_exact(&mut change)?;
    let change = if change.is_empty() {
      None
    } else {
      Some(N::Address::try_from(change).map_err(|_| {
        io::Error::new(
          io::ErrorKind::Other,
          "couldn't deserialize an Address serialized into a Plan",
        )
      })?)
    };

    Ok(Plan { key, inputs, payments, change })
  }
}
