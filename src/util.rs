use curv::{BigInt, GE};
use std::convert::TryFrom;
use std::os::raw::c_int;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

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

const STOP_SIGNALS: [usize; 6] = [
    signal_hook::SIGABRT as usize,
    signal_hook::SIGHUP as usize,
    signal_hook::SIGINT as usize,
    signal_hook::SIGQUIT as usize,
    signal_hook::SIGTERM as usize,
    signal_hook::SIGTRAP as usize,
];

pub fn set_stop_signal_handler() -> Result<Arc<AtomicUsize>, std::io::Error> {
    let handler = Arc::new(AtomicUsize::new(0));

    for signal in &STOP_SIGNALS {
        signal_hook::flag::register_usize(
            *signal as c_int,
            Arc::clone(&handler),
            *signal as usize,
        )?;
    }
    Ok(handler)
}

pub fn signal_to_string(signal: usize) -> &'static str {
    let signal: u32 = TryFrom::try_from(signal).unwrap();
    match signal as i32 {
        signal_hook::SIGABRT => "SIGABRT",
        signal_hook::SIGHUP => "SIGHUP",
        signal_hook::SIGINT => "SIGINT",
        signal_hook::SIGQUIT => "SIGQUIT",
        signal_hook::SIGTERM => "SIGTERM",
        signal_hook::SIGTRAP => "SIGTRAP",
        _ => unreachable!("unregistered signal received"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_sum_point() {
        use curv::elliptic::curves::secp256_k1::*;
        use curv::elliptic::curves::traits::ECPoint;
        use curv::elliptic::curves::traits::ECScalar;
        use curv::BigInt;

        // scalar values
        let s1 = ECScalar::from(&BigInt::from(1));
        let s2 = ECScalar::from(&BigInt::from(2));
        let s3 = ECScalar::from(&BigInt::from(3));

        // point
        let p1 = GE::generator() * &s1;
        let p2 = GE::generator() * &s2;
        let p3 = GE::generator() * &s3;

        let sum = sum_point(&vec![p1, p2, p3]);

        let s6 = ECScalar::from(&BigInt::from(6));
        let p6 = GE::generator() * &s6;
        assert_eq!(sum, p6);
    }

    #[test]
    fn test_jacobi() {
        assert_eq!(jacobi(&BigInt::from(158), &BigInt::from(235)), -1);
        assert_eq!(jacobi(&BigInt::from(5), &BigInt::from(12)), -1);
        assert_eq!(jacobi(&BigInt::from(16), &BigInt::from(60)), 1);
    }

    #[test]
    fn test_signals() {
        let handler = set_stop_signal_handler().unwrap();

        unsafe {
            libc::raise(signal_hook::SIGINT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGINT as usize
            );

            libc::raise(signal_hook::SIGABRT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGABRT as usize
            );

            libc::raise(signal_hook::SIGHUP);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGHUP as usize
            );

            libc::raise(signal_hook::SIGQUIT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGQUIT as usize
            );

            libc::raise(signal_hook::SIGTERM);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGTERM as usize
            );

            libc::raise(signal_hook::SIGTRAP);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::SIGTRAP as usize
            );
        }
    }
}
