use zeroize::Zeroizing;

use crate::wallet::seed::{Seed, LanguageName};

#[test]
fn test_classic_seed_english() {
  // keys
  let spend = "c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403";
  let _view = "513ba91c538a5a9069e0094de90e927c0cd147fa10428ce3ac1afd49f63e3b01";

  // seed string
  let mut seed = String::from("washing thirsty occur lectures tuesday fainted toxic adapt ");
  seed.push_str("abnormal memoir nylon mostly building shrugged online ember northern ");
  seed.push_str("ruby woes dauntless boil family illness inroads northern");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::English);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_german() {
  // keys
  let spend = "79801b7a1b9796856e2397d862a113862e1fdc289a205e79d8d70995b276db06";
  let _view = "99f0ec556643bd9c038a4ed86edcb9c6c16032c4622ed2e000299d527a792701";

  // seed string
  let mut seed = String::from("Kaliber Gabelung Tapir Liveband Favorit Specht Enklave Nabel ");
  seed.push_str("Jupiter Foliant Chronik nisten löten Vase Aussage Rekord ");
  seed.push_str("Yeti Gesetz Eleganz Alraune Künstler Almweide Jahr Kastanie Almweide");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::German);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_dutch() {
  // keys
  let spend = "e2d2873085c447c2bc7664222ac8f7d240df3aeac137f5ff2022eaa629e5b10a";
  let _view = "eac30b69477e3f68093d131c7fd961564458401b07f8c87ff8f6030c1a0c7301";

  // seed string
  let mut seed = String::from("setwinst riphagen vimmetje extase blief tuitelig fuiven meifeest ");
  seed.push_str("ponywagen zesmaal ripdeal matverf codetaal leut ivoor rotten ");
  seed.push_str("wisgerhof winzucht typograaf atrium rein zilt traktaat verzaagd setwinst");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Dutch);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_french() {
  // keys
  let spend = "2dd39ff1a4628a94b5c2ec3e42fb3dfe15c2b2f010154dc3b3de6791e805b904";
  let _view = "6725b32230400a1032f31d622b44c3a227f88258939b14a7c72e00939e7bdf0e";

  // seed string
  let mut seed = String::from("poids vaseux tarte bazar poivre effet entier nuance ");
  seed.push_str("sensuel ennui pacte osselet poudre battre alibi mouton ");
  seed.push_str("stade paquet pliage gibier type question position projet pliage");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::French);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_italian() {
  // keys
  let spend = "5e7fd774eb00fa5877e2a8b4dc9c7ffe111008a3891220b56a6e49ac816d650a";
  let _view = "698a1dce6018aef5516e82ca0cb3e3ec7778d17dfb41a137567bfa2e55e63a03";

  // seed string
  let mut seed = String::from("cavo pancetta auto fulmine alleanza filmato diavolo prato ");
  seed.push_str("forzare meritare litigare lezione segreto evasione votare buio ");
  seed.push_str("licenza cliente dorso natale crescere vento tutelare vetta evasione");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Italian);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_spanish() {
  // keys
  let spend = "ae2c9bebdddac067d73ec0180147fc92bdf9ac7337f1bcafbbe57dd13558eb02";
  let _view = "18deafb34d55b7a43cae2c1c1c206a3c80c12cc9d1f84640b484b95b7fec3e05";

  // seed string
  let mut seed = String::from("minero ocupar mirar evadir octubre cal logro miope ");
  seed.push_str("opaco disco ancla litio clase cuello nasal clase ");
  seed.push_str("fiar avance deseo mente grumo negro cordón croqueta clase");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Spanish);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_russian() {
  // keys
  let spend = "7cb5492df5eb2db4c84af20766391cd3e3662ab1a241c70fc881f3d02c381f05";
  let _view = "fcd53e41ec0df995ab43927f7c44bc3359c93523d5009fb3f5ba87431d545a03";

  // seed string
  let mut seed = String::from("шатер икра нация ехать получать инерция доза реальный ");
  seed.push_str("рыжий таможня лопата душа веселый клетка атлас лекция ");
  seed.push_str("обгонять паек наивный лыжный дурак стать ежик задача паек");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Russian);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_portuguese() {
  // keys
  let spend = "13b3115f37e35c6aa1db97428b897e584698670c1b27854568d678e729200c0f";
  let _view = "ad1b4fd35270f5f36c4da7166672b347e75c3f4d41346ec2a06d1d0193632801";

  // seed string
  let mut seed = String::from("agito eventualidade onus itrio holograma sodomizar objetos dobro ");
  seed.push_str("iugoslavo bcrepuscular odalisca abjeto iuane darwinista eczema acetona ");
  seed.push_str("cibernetico hoquei gleba driver buffer azoto megera nogueira agito");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Portuguese);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_esperanto() {
  // keys
  let spend = "82ebf0336d3b152701964ed41df6b6e9a035e57fc98b84039ed0bd4611c58904";
  let _view = "cd4d120e1ea34360af528f6a3e6156063312d9cefc9aa6b5218d366c0ed6a201";

  // seed string
  let mut seed = String::from("ukazo klini peco etikedo fabriko imitado onklino urino ");
  seed.push_str("pudro incidento kumuluso ikono smirgi hirundo uretro krii ");
  seed.push_str("sparkado super speciala pupo alpinisto cvana vokegi zombio fabriko");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Esperanto);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_lojban() {
  // keys
  let spend = "e4f8c6819ab6cf792cebb858caabac9307fd646901d72123e0367ebc0a79c200";
  let _view = "c806ce62bafaa7b2d597f1a1e2dbe4a2f96bfd804bf6f8420fc7f4a6bd700c00";

  // seed string
  let mut seed = String::from("jetnu vensa julne xrotu xamsi julne cutci dakli ");
  seed.push_str("mlatu xedja muvgau palpi xindo sfubu ciste cinri ");
  seed.push_str("blabi darno dembi janli blabi fenki bukpu burcu blabi");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Lojban);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_english_old() {
  //////// compare with monero ////////////////
  // keys
  let spend = "647f4765b66b636ff07170ab6280a9a6804dfbaf19db2ad37d23be024a18730b";
  let _view = "045da65316a906a8c30046053119c18020b07a7a3a6ef5c01ab2a8755416bd02";

  // seed string
  let mut seed = String::from("glorious especially puff son moment add youth nowhere ");
  seed.push_str("throw glide grip wrong rhythm consume very swear ");
  seed.push_str("bitter heavy eventually begin reason flirt type unable");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::EnglishOld);
  assert_eq!(s1, s2);

  //////// compare with self ////////////////////////
  // create new seed
  let new_seed = Seed::new(LanguageName::EnglishOld);
  let seed_from_key = Seed::from_entropy(&new_seed.entropy(), LanguageName::EnglishOld);
  assert_eq!(new_seed, seed_from_key);
}

#[test]
fn test_classic_seed_japanese() {
  // keys
  let spend = "c56e895cdb13007eda8399222974cdbab493640663804b93cbef3d8c3df80b0b";
  let _view = "6c3634a313ec2ee979d565c33888fd7c3502d696ce0134a8bc1a2698c7f2c508";

  // seed string
  let mut seed =
    String::from("ぜんぶ どうぐ おたがい せんきょ おうじ そんちょう じゅしん いろえんぴつ ");
  seed.push_str("かほう つかれる えらぶ にちじょう くのう にちようび ぬまえび さんきゃく ");
  seed.push_str("おおや ちぬき うすめる いがく せつでん さうな すいえい せつだん おおや");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Japanese);
  assert_eq!(s1, s2);
}

#[test]
fn test_classic_seed_chinese() {
  // keys
  let spend = "a5e4fff1706ef9212993a69f246f5c95ad6d84371692d63e9bb0ea112a58340d";
  let _view = "1176c43ce541477ea2f3ef0b49b25112b084e26b8a843e1304ac4677b74cdf02";

  // seed string
  let mut seed = String::from("摇 曲 艺 武 滴 然 效 似 ");
  seed.push_str("赏 式 祥 歌 买 疑 小 碧 ");
  seed.push_str("堆 博 键 房 鲜 悲 付 喷 武");

  // string -> key
  let s1 = Seed::from_string(Zeroizing::new(seed)).unwrap();
  let spend_bytes = Zeroizing::new(hex::decode(spend).unwrap().try_into().unwrap());
  assert_eq!(s1.entropy(), spend_bytes);

  // key -> string
  let s2 = Seed::from_entropy(&spend_bytes, LanguageName::Chinese);
  assert_eq!(s1, s2);
}
