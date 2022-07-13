use subtle::ConditionallySelectable;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

use dalek_ff_group::field::FieldElement;
use group::ff::{Field, PrimeField};

use crate::hash;

pub fn hash_to_point(point: EdwardsPoint) -> EdwardsPoint {
    let mut bytes = point.compress().to_bytes();
    unsafe {
        #[link(name = "wrapper")]
        extern "C" {
            fn c_hash_to_point(point: *const u8);
        }

        c_hash_to_point(bytes.as_mut_ptr());
    }
    CompressedEdwardsY::from_slice(&bytes).decompress().unwrap()
}

// This works without issue. It's also 140 times slower (@ 3.5ms), and despite checking it passes
// for all branches, there still could be *some* discrepancy somewhere. There's no reason to use it
// unless we're trying to purge that section of the C static library, which we aren't right now
#[allow(dead_code)]
pub(crate) fn rust_hash_to_point(key: EdwardsPoint) -> EdwardsPoint {
    #[allow(non_snake_case)]
    let A = FieldElement::from(486662u64);

    let v = FieldElement::from_square(hash(&key.compress().to_bytes())).double();
    let w = v + FieldElement::one();
    let x = w.square() + (-A.square() * v);

    // This isn't the complete X, yet its initial value
    // We don't calculate the full X, and instead solely calculate Y, letting dalek reconstruct X
    // While inefficient, it solves API boundaries and reduces the amount of work done here
    #[allow(non_snake_case)]
    let X = {
        let u = w;
        let v = x;
        let v3 = v * v * v;
        let uv3 = u * v3;
        let v7 = v3 * v3 * v;
        let uv7 = u * v7;
        uv3 * uv7.pow((-FieldElement::from(5u8)) * FieldElement::from(8u8).invert().unwrap())
    };
    let x = X.square() * x;

    let y = w - x;
    let non_zero_0 = !y.is_zero();
    let y_if_non_zero_0 = w + x;
    let sign = non_zero_0 & (!y_if_non_zero_0.is_zero());

    let mut z = -A;
    z *= FieldElement::conditional_select(&v, &FieldElement::from(1u8), sign);
    #[allow(non_snake_case)]
    let Z = z + w;
    #[allow(non_snake_case)]
    let mut Y = z - w;

    Y = Y * Z.invert().unwrap();
    let mut bytes = Y.to_repr();
    bytes[31] |= sign.unwrap_u8() << 7;

    CompressedEdwardsY(bytes)
        .decompress()
        .unwrap()
        .mul_by_cofactor()
}
