// Fixed check (supporting numbers and lowercase a-f)
match b {
    b'0'..=b'9' | b'a'..=b'f' => { /* valid */ }
    _ => return None, // or return an error depending on your function signature
}
