#![cfg_attr(not(feature = "std"), no_std)]

use std::io::{self, Read, Write};

use scale::{Input, Encode, Decode, IoReader};

/*
#[derive(Clone, PartialEq, Eq]
pub struct InInstruction {
  pub destination: [u8; 32],
  pub amount: u64,
  pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq]
pub struct RefundableInInstruction<A: EncodedAddress> {
  pub origin: Option<A>,
  pub instruction: InInstruction,
}
*/

pub trait EncodedAddress: Clone + PartialEq + Eq {
  fn read<R: Read>(reader: &mut R) -> io::Result<Self>;
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;
}

pub struct Context<A: EncodedAddress> {
  pub origin: Option<A>,
  pub amount: u64,
}

impl<A: EncodedAddress> Context<A> {
  fn new(origin: Option<A>, amount: u64) -> Context<A> {
    Context { origin, amount }
  }
}

struct EncodedInInstruction<A: EncodedAddress> {
  target: [u8; 32],
  data: Vec<u8>,
  origin: Option<A>,
}

struct InInstruction<A: EncodedAddress> {
  origin: Option<A>,
  amount: u64,

  target: [u8; 32],
  data: Vec<u8>,
}

impl<A: EncodedAddress> EncodedInInstruction<A> {
  fn contextualize(self, context: Context<A>) -> InInstruction<A> {
    let Context { origin, amount } = context;
    let EncodedInInstruction { target, data, origin: encoded_origin } = self;
    InInstruction { origin: encoded_origin.or(origin), amount, target, data }
  }

  // TODO: Are these equal to scale::Encode/Decode?
  fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    let err = |err| io::Error::new(io::ErrorKind::Other, err);

    let mut reader = IoReader(reader);

    let mut target = [0; 32];
    reader.read(&mut target).map_err(|_| err("failed to read target"))?;

    let data_len = usize::from(u16::decode(&mut reader).map_err(|_| err("data exceeds 64 KiB"))?);
    let mut data = vec![0; data_len];
    reader.read(&mut data).map_err(|_| err("failed to read data"))?;

    let origin = match reader.read_byte().map_err(|_| err("failed to read origin's presence"))? {
      0 => None,
      1 => Some(A::read(reader.0)?),
      _ => Err(err("failed to read origin"))?,
    };

    Ok(Self { target, data, origin })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.target)?;

    writer.write_all(
      &u16::try_from(self.data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "data exceeds 64 KiB"))?
        .encode(),
    )?;
    writer.write_all(&self.data)?;

    match &self.origin {
      Some(origin) => {
        writer.write_all(&[1])?;
        origin.write(writer)
      }
      None => writer.write_all(&[0]),
    }
  }
}
