use curv::{BigInt, GE};

pub fn sum_point(points: &Vec<GE>) -> GE {
    let mut iter = points.iter();
    let head = iter.next().unwrap();
    let tail = iter;
    tail.fold(head.clone(), |acc, x| acc + x)
}

pub fn jacobi(a: &BigInt, n: &BigInt) -> i8 {
    assert!(*n >= BigInt::from(3));
    assert!(a < n);

    if a.is_zero() {
        return 0;
    }
    if *a == BigInt::from(1) {
        return 1;
    }

    let mut a1: BigInt = a.clone();
    let mut e = 0;
    while a1.is_multiple_of(&BigInt::from(2)) {
        a1 = a1 >> 1;
        e += 1;
    }
    let mut s: i8 = if e & 1 == 0
        || n.modulus(&BigInt::from(8)) == BigInt::from(1)
        || n.modulus(&BigInt::from(8)) == BigInt::from(7)
    {
        1
    } else if n.modulus(&BigInt::from(8)) == BigInt::from(3)
        || n.modulus(&BigInt::from(8)) == BigInt::from(5)
    {
        -1
    } else {
        0
    };
    if n.modulus(&BigInt::from(4)) == BigInt::from(3)
        && a1.modulus(&BigInt::from(4)) == BigInt::from(3)
    {
        s = -s
    }

    if a1 == BigInt::from(1) {
        s
    } else {
        s * jacobi(&(n % a1.clone()), &a1.clone())
    }
}

#[test]
fn test_sum_point() {
    use curv::elliptic::curves::secp256_k1::*;
    use curv::elliptic::curves::traits::ECPoint;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::BigInt;

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

#[test]
fn test_jacobi() {
    assert_eq!(jacobi(&BigInt::from(158), &BigInt::from(235)), -1);
    assert_eq!(jacobi(&BigInt::from(5), &BigInt::from(12)), -1);
    assert_eq!(jacobi(&BigInt::from(16), &BigInt::from(60)), 1);
}
