use std::collections::HashMap;

use curv::GE;

use crate::net::SignerID;

pub fn sort_value_by_signer_id<S>(map: HashMap<SignerID, S>) -> Vec<S> {
    let mut array = Vec::new();
    for a in map {
        array.push(a);
    }
    array.sort_by(|a, b| a.0.pubkey.partial_cmp(&b.0.pubkey).unwrap());
    let mut values: Vec<S> = Vec::new();
    for e in array {
        values.push(e.1);
    }
    values
}

pub fn sum_point(points: &Vec<GE>) -> GE {
    let mut iter = points.iter();
    let head = iter.next().unwrap();
    let tail = iter;
    tail.fold(head.clone(), |acc, x| acc + x)
}
