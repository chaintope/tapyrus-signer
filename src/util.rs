use curv::GE;
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

const STOP_SIGNALS: [usize; 6] = [
    signal_hook::consts::SIGABRT as usize,
    signal_hook::consts::SIGHUP as usize,
    signal_hook::consts::SIGINT as usize,
    signal_hook::consts::SIGQUIT as usize,
    signal_hook::consts::SIGTERM as usize,
    signal_hook::consts::SIGTRAP as usize,
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
        signal_hook::consts::SIGABRT => "SIGABRT",
        signal_hook::consts::SIGHUP => "SIGHUP",
        signal_hook::consts::SIGINT => "SIGINT",
        signal_hook::consts::SIGQUIT => "SIGQUIT",
        signal_hook::consts::SIGTERM => "SIGTERM",
        signal_hook::consts::SIGTRAP => "SIGTRAP",
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
    fn test_signals() {
        let handler = set_stop_signal_handler().unwrap();

        unsafe {
            libc::raise(signal_hook::consts::SIGINT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::consts::SIGINT as usize
            );

            libc::raise(signal_hook::consts::SIGABRT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::consts::SIGABRT as usize
            );

            libc::raise(signal_hook::consts::SIGHUP);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::consts::SIGHUP as usize
            );

            libc::raise(signal_hook::consts::SIGQUIT);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::consts::SIGQUIT as usize
            );

            libc::raise(signal_hook::consts::SIGTERM);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::consts::SIGTERM as usize
            );

            libc::raise(signal_hook::consts::SIGTRAP);
            assert_eq!(
                handler.load(Ordering::Relaxed),
                signal_hook::consts::SIGTRAP as usize
            );
        }
    }
}
