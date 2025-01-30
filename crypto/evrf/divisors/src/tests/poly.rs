use rand_core::OsRng;

use group::ff::Field;
use pasta_curves::Ep;

use crate::{DivisorCurve, Poly};

type F = <Ep as DivisorCurve>::FieldElement;

#[test]
fn test_poly() {
  let zero = F::ZERO;
  let one = F::ONE;

  {
    let mut poly = Poly::zero();
    poly.y_coefficients = vec![zero, one];

    let mut modulus = Poly::zero();
    modulus.y_coefficients = vec![one];
    assert_eq!(
      poly.clone().div_rem(&modulus).0,
      Poly {
        y_coefficients: vec![one],
        yx_coefficients: vec![],
        x_coefficients: vec![],
        zero_coefficient: zero
      }
    );
    assert_eq!(
      poly % &modulus,
      Poly {
        y_coefficients: vec![],
        yx_coefficients: vec![],
        x_coefficients: vec![],
        zero_coefficient: zero
      }
    );
  }

  {
    let mut poly = Poly::zero();
    poly.y_coefficients = vec![zero, one];

    let mut squared = Poly::zero();
    squared.y_coefficients = vec![zero, zero, zero, one];
    assert_eq!(poly.clone() * &poly, squared);
  }

  {
    let mut a = Poly::zero();
    a.zero_coefficient = F::from(2u64);

    let mut b = Poly::zero();
    b.zero_coefficient = F::from(3u64);

    let mut res = Poly::zero();
    res.zero_coefficient = F::from(6u64);
    assert_eq!(a.clone() * &b, res);

    b.y_coefficients = vec![F::from(4u64)];
    res.y_coefficients = vec![F::from(8u64)];
    assert_eq!(a.clone() * &b, res);
    assert_eq!(b.clone() * &a, res);

    a.x_coefficients = vec![F::from(5u64)];
    res.x_coefficients = vec![F::from(15u64)];
    res.yx_coefficients = vec![vec![F::from(20u64)]];
    assert_eq!(a.clone() * &b, res);
    assert_eq!(b * &a, res);

    // res is now 20xy + 8*y + 15*x + 6
    // res ** 2 =
    //   400*x^2*y^2 + 320*x*y^2 + 64*y^2 + 600*x^2*y + 480*x*y + 96*y + 225*x^2 + 180*x + 36

    let mut squared = Poly::zero();
    squared.y_coefficients = vec![F::from(96u64), F::from(64u64)];
    squared.yx_coefficients =
      vec![vec![F::from(480u64), F::from(600u64)], vec![F::from(320u64), F::from(400u64)]];
    squared.x_coefficients = vec![F::from(180u64), F::from(225u64)];
    squared.zero_coefficient = F::from(36u64);
    assert_eq!(res.clone() * &res, squared);
  }
}

#[test]
fn test_differentation() {
  let random = || F::random(&mut OsRng);

  let input = Poly {
    y_coefficients: vec![random()],
    yx_coefficients: vec![vec![random()]],
    x_coefficients: vec![random(), random(), random()],
    zero_coefficient: random(),
  };
  let (diff_x, diff_y) = input.differentiate();
  assert_eq!(
    diff_x,
    Poly {
      y_coefficients: vec![input.yx_coefficients[0][0]],
      yx_coefficients: vec![],
      x_coefficients: vec![
        F::from(2) * input.x_coefficients[1],
        F::from(3) * input.x_coefficients[2]
      ],
      zero_coefficient: input.x_coefficients[0],
    }
  );
  assert_eq!(
    diff_y,
    Poly {
      y_coefficients: vec![],
      yx_coefficients: vec![],
      x_coefficients: vec![input.yx_coefficients[0][0]],
      zero_coefficient: input.y_coefficients[0],
    }
  );

  let input = Poly {
    y_coefficients: vec![random()],
    yx_coefficients: vec![vec![random(), random()]],
    x_coefficients: vec![random(), random(), random(), random()],
    zero_coefficient: random(),
  };
  let (diff_x, diff_y) = input.differentiate();
  assert_eq!(
    diff_x,
    Poly {
      y_coefficients: vec![input.yx_coefficients[0][0]],
      yx_coefficients: vec![vec![F::from(2) * input.yx_coefficients[0][1]]],
      x_coefficients: vec![
        F::from(2) * input.x_coefficients[1],
        F::from(3) * input.x_coefficients[2],
        F::from(4) * input.x_coefficients[3],
      ],
      zero_coefficient: input.x_coefficients[0],
    }
  );
  assert_eq!(
    diff_y,
    Poly {
      y_coefficients: vec![],
      yx_coefficients: vec![],
      x_coefficients: vec![input.yx_coefficients[0][0], input.yx_coefficients[0][1]],
      zero_coefficient: input.y_coefficients[0],
    }
  );
}
