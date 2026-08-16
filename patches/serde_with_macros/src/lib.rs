#![no_std]

extern crate proc_macro;
use proc_macro::{TokenTree, TokenStream};

use syn::{Meta, Data, DeriveInput};
use quote::ToTokens as _;

/// Implement [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) by
/// serializing as the string obtained by [`core::format::Display`].
///
/// This actually uses [`alloc::string::ToString`] to obtain the string, as
/// [`alloc::string::ToString`] is automatically implemented for `T: Display` by deferring to its
/// display implementation.
///
/// This is intended to have semantic equality to
/// [`serde_with::SerializeDisplay`](
///   https://docs.rs/serde_with/3/serde_with/derive.SerializeDisplay.html
/// ), as necessary within Serai's dependency tree.
#[proc_macro_derive(SerializeDisplay)]
pub fn derive_serialize_display(input: TokenStream) -> TokenStream {
  let input = syn::parse_macro_input!(input as DeriveInput);
  let name = input.ident;
  let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
  (quote::quote! {
    impl #impl_generics serde_with::serde::Serialize for #name #ty_generics #where_clause {
      fn serialize<S>(&self, serializer: S) -> Result<
        <S as serde_with::serde::Serializer>::Ok,
        <S as serde_with::serde::Serializer>::Error
      > where S: serde_with::serde::Serializer {
        extern crate alloc;
        serializer.serialize_str(&alloc::string::ToString::to_string(self))
      }
    }
  })
  .into()
}

/// Implement [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) by
/// deserializing a string and then converting via [`core::str::FromStr`].
///
/// This is intended to have semantic equality to
/// [`serde_with::DeserializeFromStr`](
///   https://docs.rs/serde_with/3/serde_with/derive.DeserializeFromStr.html
/// ), as necessary within Serai's dependency tree.
#[proc_macro_derive(DeserializeFromStr)]
pub fn derive_deserialize_from_str(input: TokenStream) -> TokenStream {
  let input = syn::parse_macro_input!(input as DeriveInput);
  let name = input.ident;
  let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

  // Extend the generics clause with the `'de` lifetime necessary for `Deserialize`
  let mut impl_generics = TokenStream::from(impl_generics.into_token_stream()).into_iter();
  let impl_generics = proc_macro2::TokenStream::from(match impl_generics.next() {
    None => <TokenStream as core::str::FromStr>::from_str("<'de>").unwrap(),
    Some(lt) => {
      assert!(matches!(lt, TokenTree::Punct(punct) if punct == '<'));
      <TokenStream as core::str::FromStr>::from_str("<'de, ")
        .unwrap()
        .into_iter()
        .chain(impl_generics)
        .collect::<TokenStream>()
    }
  });

  (quote::quote! {
    impl #impl_generics serde_with::serde::Deserialize<'de> for #name #ty_generics #where_clause {
      fn deserialize<D>(deserializer: D) -> Result<
        Self,
        <D as serde_with::serde::Deserializer<'de>>::Error
      > where D: serde_with::serde::Deserializer<'de> {
        extern crate alloc;
        let string = <
          alloc::string::String as serde_with::serde::Deserialize<'de>
        >::deserialize(deserializer)?;
        <Self as core::str::FromStr>::from_str(&string)
          .map_err(
            <
              <D as serde_with::serde::Deserializer<'de>
            >::Error as serde_with::serde::de::Error>::custom
        )
      }
    }
  })
  .into()
}

/// A semantic equivalivent to [`serde_with::serde_as`](
///   https://docs.rs/serde_with/3/serde_with/attr.serde_as.html
/// ), as necessary within Serai's dependency tree.
#[proc_macro_attribute]
pub fn serde_as(attribute: TokenStream, input: TokenStream) -> TokenStream {
  extern crate alloc;
  use alloc::string::ToString;

  assert!(attribute.is_empty());

  let mut input = syn::parse_macro_input!(input as DeriveInput);

  // Find and replace all inner `serde_as` attributes
  match &mut input.data {
    Data::Struct(data) => {
      for field in data.fields.iter_mut() {
        for attr in field.attrs.iter_mut() {
          match &mut attr.meta {
            Meta::List(meta)
              if meta.path.get_ident().map(ToString::to_string) == Some("serde_as".to_string()) =>
            {
              let mut iter = TokenStream::from(meta.tokens.clone()).into_iter();

              // Confirm this has the correct syntax
              assert!(
                matches!(iter.next(), Some(TokenTree::Ident(ident)) if ident.to_string() == "as")
              );
              assert!(matches!(iter.next(), Some(TokenTree::Punct(punct)) if punct == '='));

              // Parse out the type this is `as`
              let TokenTree::Literal(ty) = iter.next().unwrap() else { panic!() };
              let ty = ty.to_string();
              let ty = ty.strip_prefix('"').unwrap().strip_suffix('"').unwrap();

              // Replace with `serde(with = As<{ty}>)`
              let meta = alloc::format!(r#"serde(with = "::serde_with::As::<{ty}>")"#);
              attr.meta = syn::parse_str(&meta).unwrap();

              assert!(iter.next().is_none());
            }
            _ => {}
          }
        }
      }
    }
    _ => unimplemented!(),
  }

  TokenStream::from(input.into_token_stream())
}
