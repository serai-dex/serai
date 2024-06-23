use zeroize::Zeroizing;
use rand_core::OsRng;

use crate::*;

#[test]
fn test_polyseed() {
  struct Vector {
    language: Language,
    seed: String,
    entropy: String,
    birthday: u64,
    has_prefix: bool,
    has_accent: bool,
  }

  let vectors = [
    Vector {
      language: Language::English,
      seed: "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language"
        .into(),
      entropy: "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000".into(),
      birthday: 1638446400,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Spanish,
      seed: "eje fin parte célebre tabú pestaña lienzo puma \
      prisión hora regalo lengua existir lápiz lote sonoro"
        .into(),
      entropy: "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000".into(),
      birthday: 3118651200,
      has_prefix: true,
      has_accent: true,
    },
    Vector {
      language: Language::French,
      seed: "valable arracher décaler jeudi amusant dresser mener épaissir risible \
      prouesse réserve ampleur ajuster muter caméra enchère"
        .into(),
      entropy: "11cfd870324b26657342c37360c424a14a050b00000000000000000000000000".into(),
      birthday: 1679314966,
      has_prefix: true,
      has_accent: true,
    },
    Vector {
      language: Language::Italian,
      seed: "caduco midollo copione meninge isotopo illogico riflesso tartaruga fermento \
      olandese normale tristezza episodio voragine forbito achille"
        .into(),
      entropy: "7ecc57c9b4652d4e31428f62bec91cfd55500600000000000000000000000000".into(),
      birthday: 1679316358,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Portuguese,
      seed: "caverna custear azedo adeus senador apertada sedoso omitir \
      sujeito aurora videira molho cartaz gesso dentista tapar"
        .into(),
      entropy: "45473063711376cae38f1b3eba18c874124e1d00000000000000000000000000".into(),
      birthday: 1679316657,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Czech,
      seed: "usmrtit nora dotaz komunita zavalit funkce mzda sotva akce \
      vesta kabel herna stodola uvolnit ustrnout email"
        .into(),
      entropy: "7ac8a4efd62d9c3c4c02e350d32326df37821c00000000000000000000000000".into(),
      birthday: 1679316898,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Korean,
      seed: "전망 선풍기 국제 무궁화 설사 기름 이론적 해안 절망 예선 \
        지우개 보관 절망 말기 시각 귀신"
        .into(),
      entropy: "684663fda420298f42ed94b2c512ed38ddf12b00000000000000000000000000".into(),
      birthday: 1679317073,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: Language::Japanese,
      seed: "うちあわせ　ちつじょ　つごう　しはい　けんこう　とおる　てみやげ　はんとし　たんとう \
      といれ　おさない　おさえる　むかう　ぬぐう　なふだ　せまる"
        .into(),
      entropy: "94e6665518a6286c6e3ba508a2279eb62b771f00000000000000000000000000".into(),
      birthday: 1679318722,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: Language::ChineseTraditional,
      seed: "亂 挖 斤 柄 代 圈 枝 轄 魯 論 函 開 勘 番 榮 壁".into(),
      entropy: "b1594f585987ab0fd5a31da1f0d377dae5283f00000000000000000000000000".into(),
      birthday: 1679426433,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: Language::ChineseSimplified,
      seed: "啊 百 族 府 票 划 伪 仓 叶 虾 借 溜 晨 左 等 鬼".into(),
      entropy: "21cdd366f337b89b8d1bc1df9fe73047c22b0300000000000000000000000000".into(),
      birthday: 1679426817,
      has_prefix: false,
      has_accent: false,
    },
    // The following seed requires the language specification in order to calculate
    // a single valid checksum
    Vector {
      language: Language::Spanish,
      seed: "impo sort usua cabi venu nobl oliv clim \
        cont barr marc auto prod vaca torn fati"
        .into(),
      entropy: "dbfce25fe09b68a340e01c62417eeef43ad51800000000000000000000000000".into(),
      birthday: 1701511650,
      has_prefix: true,
      has_accent: true,
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
        .map(|w| w.chars().filter(char::is_ascii).collect::<String>())
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
            if ascii == PREFIX_LEN {
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
    println!("{}. language: {:?}, seed: {}", line!(), vector.language, vector.seed.clone());
    let seed = Polyseed::from_string(vector.language, Zeroizing::new(vector.seed.clone())).unwrap();
    let trim = trim_seed(&vector.seed);
    let add_whitespace = add_whitespace(vector.seed.clone());
    let seed_without_accents = seed_without_accents(&vector.seed);

    // Make sure a version with added whitespace still works
    let whitespaced_seed =
      Polyseed::from_string(vector.language, Zeroizing::new(add_whitespace)).unwrap();
    assert_eq!(seed, whitespaced_seed);
    // Check trimmed versions works
    if vector.has_prefix {
      let trimmed_seed = Polyseed::from_string(vector.language, Zeroizing::new(trim)).unwrap();
      assert_eq!(seed, trimmed_seed);
    }
    // Check versions without accents work
    if vector.has_accent {
      let seed_without_accents =
        Polyseed::from_string(vector.language, Zeroizing::new(seed_without_accents)).unwrap();
      assert_eq!(seed, seed_without_accents);
    }

    let entropy = Zeroizing::new(hex::decode(vector.entropy).unwrap().try_into().unwrap());
    assert_eq!(*seed.entropy(), entropy);
    assert!(seed.birthday().abs_diff(vector.birthday) < TIME_STEP);

    // Entropy -> Seed
    let from_entropy = Polyseed::from(vector.language, 0, seed.birthday(), entropy).unwrap();
    assert_eq!(seed.to_string(), from_entropy.to_string());

    // Check against ourselves
    {
      let seed = Polyseed::new(&mut OsRng, vector.language);
      println!("{}. seed: {}", line!(), *seed.to_string());
      assert_eq!(seed, Polyseed::from_string(vector.language, seed.to_string()).unwrap());
      assert_eq!(
        seed,
        Polyseed::from(vector.language, 0, seed.birthday(), seed.entropy().clone(),).unwrap()
      );
    }
  }
}

#[test]
fn test_invalid_polyseed() {
  // This seed includes unsupported features bits and should error on decode
  let seed = "include domain claim resemble urban hire lunch bird \
    crucial fire best wife ring warm ignore model"
    .into();
  let res = Polyseed::from_string(Language::English, Zeroizing::new(seed));
  assert_eq!(res, Err(PolyseedError::UnsupportedFeatures));
}
