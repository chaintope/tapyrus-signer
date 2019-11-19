use curv::GE;

pub fn sum_point(points: &Vec<GE>) -> GE {
    let mut iter = points.iter();
    let head = iter.next().unwrap();
    let tail = iter;
    tail.fold(head.clone(), |acc, x| acc + x)
}

#[test]
fn test_sum_point() {
    use curv::elliptic::curves::secp256_k1::*;
    use curv::elliptic::curves::traits::ECPoint;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::BigInt;
    use std::str::FromStr;

    // scalar values
    let s1 = ECScalar::from(&BigInt::from_str("1").unwrap());
    let s2 = ECScalar::from(&BigInt::from_str("2").unwrap());
    let s3 = ECScalar::from(&BigInt::from_str("3").unwrap());

    // point
    let p1 = GE::generator() * &s1;
    let p2 = GE::generator() * &s2;
    let p3 = GE::generator() * &s3;

    let sum = sum_point(&vec![p1, p2, p3]);

    let s6 = ECScalar::from(&BigInt::from_str("6").unwrap());
    let p6 = GE::generator() * &s6;
    assert_eq!(sum, p6);
}
