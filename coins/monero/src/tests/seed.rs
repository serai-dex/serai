use zeroize::Zeroizing;

use rand_core::OsRng;

use curve25519_dalek::scalar::Scalar;

use crate::{
  hash,
  wallet::seed::{
    Seed, SeedType,
    classic::{self, trim_by_lang},
    polyseed,
  },
};

#[test]
fn test_classic_seed() {
  struct Vector {
    language: classic::Language,
    seed: String,
    spend: String,
    view: String,
  }

  let vectors = [
    Vector {
      language: classic::Language::Chinese,
      seed: "摇 曲 艺 武 滴 然 效 似 赏 式 祥 歌 买 疑 小 碧 堆 博 键 房 鲜 悲 付 喷 武".into(),
      spend: "a5e4fff1706ef9212993a69f246f5c95ad6d84371692d63e9bb0ea112a58340d".into(),
      view: "1176c43ce541477ea2f3ef0b49b25112b084e26b8a843e1304ac4677b74cdf02".into(),
    },
    Vector {
      language: classic::Language::English,
      seed: "washing thirsty occur lectures tuesday fainted toxic adapt \
               abnormal memoir nylon mostly building shrugged online ember northern \
               ruby woes dauntless boil family illness inroads northern"
        .into(),
      spend: "c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403".into(),
      view: "513ba91c538a5a9069e0094de90e927c0cd147fa10428ce3ac1afd49f63e3b01".into(),
    },
    Vector {
      language: classic::Language::Dutch,
      seed: "setwinst riphagen vimmetje extase blief tuitelig fuiven meifeest \
               ponywagen zesmaal ripdeal matverf codetaal leut ivoor rotten \
               wisgerhof winzucht typograaf atrium rein zilt traktaat verzaagd setwinst"
        .into(),
      spend: "e2d2873085c447c2bc7664222ac8f7d240df3aeac137f5ff2022eaa629e5b10a".into(),
      view: "eac30b69477e3f68093d131c7fd961564458401b07f8c87ff8f6030c1a0c7301".into(),
    },
    Vector {
      language: classic::Language::French,
      seed: "poids vaseux tarte bazar poivre effet entier nuance \
               sensuel ennui pacte osselet poudre battre alibi mouton \
               stade paquet pliage gibier type question position projet pliage"
        .into(),
      spend: "2dd39ff1a4628a94b5c2ec3e42fb3dfe15c2b2f010154dc3b3de6791e805b904".into(),
      view: "6725b32230400a1032f31d622b44c3a227f88258939b14a7c72e00939e7bdf0e".into(),
    },
    Vector {
      language: classic::Language::Spanish,
      seed: "minero ocupar mirar evadir octubre cal logro miope \
               opaco disco ancla litio clase cuello nasal clase \
               fiar avance deseo mente grumo negro cordón croqueta clase"
        .into(),
      spend: "ae2c9bebdddac067d73ec0180147fc92bdf9ac7337f1bcafbbe57dd13558eb02".into(),
      view: "18deafb34d55b7a43cae2c1c1c206a3c80c12cc9d1f84640b484b95b7fec3e05".into(),
    },
    Vector {
      language: classic::Language::German,
      seed: "Kaliber Gabelung Tapir Liveband Favorit Specht Enklave Nabel \
               Jupiter Foliant Chronik nisten löten Vase Aussage Rekord \
               Yeti Gesetz Eleganz Alraune Künstler Almweide Jahr Kastanie Almweide"
        .into(),
      spend: "79801b7a1b9796856e2397d862a113862e1fdc289a205e79d8d70995b276db06".into(),
      view: "99f0ec556643bd9c038a4ed86edcb9c6c16032c4622ed2e000299d527a792701".into(),
    },
    Vector {
      language: classic::Language::Italian,
      seed: "cavo pancetta auto fulmine alleanza filmato diavolo prato \
               forzare meritare litigare lezione segreto evasione votare buio \
               licenza cliente dorso natale crescere vento tutelare vetta evasione"
        .into(),
      spend: "5e7fd774eb00fa5877e2a8b4dc9c7ffe111008a3891220b56a6e49ac816d650a".into(),
      view: "698a1dce6018aef5516e82ca0cb3e3ec7778d17dfb41a137567bfa2e55e63a03".into(),
    },
    Vector {
      language: classic::Language::Portuguese,
      seed: "agito eventualidade onus itrio holograma sodomizar objetos dobro \
               iugoslavo bcrepuscular odalisca abjeto iuane darwinista eczema acetona \
               cibernetico hoquei gleba driver buffer azoto megera nogueira agito"
        .into(),
      spend: "13b3115f37e35c6aa1db97428b897e584698670c1b27854568d678e729200c0f".into(),
      view: "ad1b4fd35270f5f36c4da7166672b347e75c3f4d41346ec2a06d1d0193632801".into(),
    },
    Vector {
      language: classic::Language::Japanese,
      seed: "ぜんぶ どうぐ おたがい せんきょ おうじ そんちょう じゅしん いろえんぴつ \
               かほう つかれる えらぶ にちじょう くのう にちようび ぬまえび さんきゃく \
               おおや ちぬき うすめる いがく せつでん さうな すいえい せつだん おおや"
        .into(),
      spend: "c56e895cdb13007eda8399222974cdbab493640663804b93cbef3d8c3df80b0b".into(),
      view: "6c3634a313ec2ee979d565c33888fd7c3502d696ce0134a8bc1a2698c7f2c508".into(),
    },
    Vector {
      language: classic::Language::Russian,
      seed: "шатер икра нация ехать получать инерция доза реальный \
               рыжий таможня лопата душа веселый клетка атлас лекция \
               обгонять паек наивный лыжный дурак стать ежик задача паек"
        .into(),
      spend: "7cb5492df5eb2db4c84af20766391cd3e3662ab1a241c70fc881f3d02c381f05".into(),
      view: "fcd53e41ec0df995ab43927f7c44bc3359c93523d5009fb3f5ba87431d545a03".into(),
    },
    Vector {
      language: classic::Language::Esperanto,
      seed: "ukazo klini peco etikedo fabriko imitado onklino urino \
               pudro incidento kumuluso ikono smirgi hirundo uretro krii \
               sparkado super speciala pupo alpinisto cvana vokegi zombio fabriko"
        .into(),
      spend: "82ebf0336d3b152701964ed41df6b6e9a035e57fc98b84039ed0bd4611c58904".into(),
      view: "cd4d120e1ea34360af528f6a3e6156063312d9cefc9aa6b5218d366c0ed6a201".into(),
    },
    Vector {
      language: classic::Language::Lojban,
      seed: "jetnu vensa julne xrotu xamsi julne cutci dakli \
               mlatu xedja muvgau palpi xindo sfubu ciste cinri \
               blabi darno dembi janli blabi fenki bukpu burcu blabi"
        .into(),
      spend: "e4f8c6819ab6cf792cebb858caabac9307fd646901d72123e0367ebc0a79c200".into(),
      view: "c806ce62bafaa7b2d597f1a1e2dbe4a2f96bfd804bf6f8420fc7f4a6bd700c00".into(),
    },
    Vector {
      language: classic::Language::EnglishOld,
      seed: "glorious especially puff son moment add youth nowhere \
               throw glide grip wrong rhythm consume very swear \
               bitter heavy eventually begin reason flirt type unable"
        .into(),
      spend: "647f4765b66b636ff07170ab6280a9a6804dfbaf19db2ad37d23be024a18730b".into(),
      view: "045da65316a906a8c30046053119c18020b07a7a3a6ef5c01ab2a8755416bd02".into(),
    },
  ];

  for vector in vectors {
    let trim_seed = |seed: &str| {
      seed
        .split_whitespace()
        .map(|word| trim_by_lang(word, vector.language))
        .collect::<Vec<_>>()
        .join(" ")
    };

    // Test against Monero
    {
      let seed = Seed::from_string(Zeroizing::new(vector.seed.clone())).unwrap();
      let trim = trim_seed(&vector.seed);
      println!(
        "{}. seed: {}, entropy: {:?}, trim: {trim}",
        line!(),
        *seed.to_string(),
        *seed.entropy()
      );
      assert_eq!(seed, Seed::from_string(Zeroizing::new(trim)).unwrap());

      let spend: [u8; 32] = hex::decode(vector.spend).unwrap().try_into().unwrap();
      // For classical seeds, Monero directly uses the entropy as a spend key
      assert_eq!(
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*seed.entropy())),
        Option::<Scalar>::from(Scalar::from_canonical_bytes(spend)),
      );

      let view: [u8; 32] = hex::decode(vector.view).unwrap().try_into().unwrap();
      // Monero then derives the view key as H(spend)
      assert_eq!(
        Scalar::from_bytes_mod_order(hash(&spend)),
        Scalar::from_canonical_bytes(view).unwrap()
      );

      assert_eq!(
        Seed::from_entropy(SeedType::Classic(vector.language), Zeroizing::new(spend), None)
          .unwrap(),
        seed
      );
    }

    // Test against ourselves
    {
      let seed = Seed::new(&mut OsRng, SeedType::Classic(vector.language));
      let trim = trim_seed(&seed.to_string());
      println!(
        "{}. seed: {}, entropy: {:?}, trim: {trim}",
        line!(),
        *seed.to_string(),
        *seed.entropy()
      );
      assert_eq!(seed, Seed::from_string(Zeroizing::new(trim)).unwrap());
      assert_eq!(
        seed,
        Seed::from_entropy(SeedType::Classic(vector.language), seed.entropy(), None).unwrap()
      );
      assert_eq!(seed, Seed::from_string(seed.to_string()).unwrap());
    }
  }
}

#[test]
fn test_polyseed() {
  struct Vector {
    language: polyseed::Language,
    seed: String,
    entropy: String,
    birthday: u64,
    has_prefix: bool,
    has_accent: bool,
  }

  let vectors = [
    Vector {
      language: polyseed::Language::English,
      seed: "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language"
        .into(),
      entropy: "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000".into(),
      birthday: 1638446400,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::Spanish,
      seed: "eje fin parte célebre tabú pestaña lienzo puma \
      prisión hora regalo lengua existir lápiz lote sonoro"
        .into(),
      entropy: "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000".into(),
      birthday: 3118651200,
      has_prefix: true,
      has_accent: true,
    },
    Vector {
      language: polyseed::Language::French,
      seed: "valable arracher décaler jeudi amusant dresser mener épaissir risible \
      prouesse réserve ampleur ajuster muter caméra enchère"
        .into(),
      entropy: "11cfd870324b26657342c37360c424a14a050b00000000000000000000000000".into(),
      birthday: 1679314966,
      has_prefix: true,
      has_accent: true,
    },
    Vector {
      language: polyseed::Language::Italian,
      seed: "caduco midollo copione meninge isotopo illogico riflesso tartaruga fermento \
      olandese normale tristezza episodio voragine forbito achille"
        .into(),
      entropy: "7ecc57c9b4652d4e31428f62bec91cfd55500600000000000000000000000000".into(),
      birthday: 1679316358,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::Portuguese,
      seed: "caverna custear azedo adeus senador apertada sedoso omitir \
      sujeito aurora videira molho cartaz gesso dentista tapar"
        .into(),
      entropy: "45473063711376cae38f1b3eba18c874124e1d00000000000000000000000000".into(),
      birthday: 1679316657,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::Czech,
      seed: "usmrtit nora dotaz komunita zavalit funkce mzda sotva akce \
      vesta kabel herna stodola uvolnit ustrnout email"
        .into(),
      entropy: "7ac8a4efd62d9c3c4c02e350d32326df37821c00000000000000000000000000".into(),
      birthday: 1679316898,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::Korean,
      seed: "전망 선풍기 국제 무궁화 설사 기름 이론적 해안 절망 예선 \
        지우개 보관 절망 말기 시각 귀신"
        .into(),
      entropy: "684663fda420298f42ed94b2c512ed38ddf12b00000000000000000000000000".into(),
      birthday: 1679317073,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::Japanese,
      seed: "うちあわせ　ちつじょ　つごう　しはい　けんこう　とおる　てみやげ　はんとし　たんとう \
      といれ　おさない　おさえる　むかう　ぬぐう　なふだ　せまる"
        .into(),
      entropy: "94e6665518a6286c6e3ba508a2279eb62b771f00000000000000000000000000".into(),
      birthday: 1679318722,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::ChineseTraditional,
      seed: "亂 挖 斤 柄 代 圈 枝 轄 魯 論 函 開 勘 番 榮 壁".into(),
      entropy: "b1594f585987ab0fd5a31da1f0d377dae5283f00000000000000000000000000".into(),
      birthday: 1679426433,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: polyseed::Language::ChineseSimplified,
      seed: "啊 百 族 府 票 划 伪 仓 叶 虾 借 溜 晨 左 等 鬼".into(),
      entropy: "21cdd366f337b89b8d1bc1df9fe73047c22b0300000000000000000000000000".into(),
      birthday: 1679426817,
      has_prefix: false,
      has_accent: false,
    },
  ];

  for vector in vectors {
    let add_whitespace = |mut seed: String| {
      seed.push(' ');
      seed
    };

    let seed_without_accents = |seed: &str| {
      seed
        .split_whitespace()
        .map(|w| w.chars().filter(|c| c.is_ascii()).collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
    };

    let trim_seed = |seed: &str| {
      let seed_to_trim =
        if vector.has_accent { seed_without_accents(seed) } else { seed.to_string() };
      seed_to_trim
        .split_whitespace()
        .map(|w| {
          let mut ascii = 0;
          let mut to_take = w.len();
          for (i, char) in w.chars().enumerate() {
            if char.is_ascii() {
              ascii += 1;
            }
            if ascii == polyseed::PREFIX_LEN {
              // +1 to include this character, which put us at the prefix length
              to_take = i + 1;
              break;
            }
          }
          w.chars().take(to_take).collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
    };

    // String -> Seed
    let seed = Seed::from_string(Zeroizing::new(vector.seed.clone())).unwrap();
    let trim = trim_seed(&vector.seed);
    let add_whitespace = add_whitespace(vector.seed.clone());
    let seed_without_accents = seed_without_accents(&vector.seed);
    println!(
      "{}. seed: {}, entropy: {:?}, trim: {}, add_whitespace: {}, seed_without_accents: {}",
      line!(),
      *seed.to_string(),
      *seed.entropy(),
      trim,
      add_whitespace,
      seed_without_accents,
    );

    // Make sure a version with added whitespace still works
    let whitespaced_seed = Seed::from_string(Zeroizing::new(add_whitespace)).unwrap();
    assert_eq!(seed, whitespaced_seed);
    // Check trimmed versions works
    if vector.has_prefix {
      let trimmed_seed = Seed::from_string(Zeroizing::new(trim)).unwrap();
      assert_eq!(seed, trimmed_seed);
    }
    // Check versions without accents work
    if vector.has_accent {
      let seed_without_accents = Seed::from_string(Zeroizing::new(seed_without_accents)).unwrap();
      assert_eq!(seed, seed_without_accents);
    }

    let entropy = Zeroizing::new(hex::decode(vector.entropy).unwrap().try_into().unwrap());
    assert_eq!(seed.entropy(), entropy);
    assert!(seed.birthday().abs_diff(vector.birthday) < polyseed::TIME_STEP);

    // Entropy -> Seed
    let from_entropy =
      Seed::from_entropy(SeedType::Polyseed(vector.language), entropy, Some(seed.birthday()))
        .unwrap();
    assert_eq!(seed.to_string(), from_entropy.to_string());

    // Check against ourselves
    {
      let seed = Seed::new(&mut OsRng, SeedType::Polyseed(vector.language));
      println!("{}. seed: {}, key: {:?}", line!(), *seed.to_string(), *seed.key());
      assert_eq!(seed, Seed::from_string(seed.to_string()).unwrap());
      assert_eq!(
        seed,
        Seed::from_entropy(
          SeedType::Polyseed(vector.language),
          seed.entropy(),
          Some(seed.birthday())
        )
        .unwrap()
      );
    }
  }
}
