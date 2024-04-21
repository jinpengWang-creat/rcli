use rand::{rngs::ThreadRng, seq::SliceRandom};

const UPPER: &[u8] = b"QWERTYUPLKJHGFDSAZXCVBNM";
const LOWER: &[u8] = b"mnbvcxzasdfghjkpiuytrewq";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$%^&*_+";

pub fn process_genpass(
    length: u8,
    no_upper: bool,
    no_lower: bool,
    no_number: bool,
    no_symbol: bool,
) -> anyhow::Result<String> {
    let mut rng = rand::thread_rng();
    let mut password = Vec::new();
    let mut chars = Vec::new();

    let mut cur_length = 0;
    if cur_length < length && !no_upper {
        chars.extend_from_slice(UPPER);
        password.push(generate_rand_char(&mut rng, UPPER));
        cur_length += 1;
    }

    if cur_length < length && !no_lower {
        chars.extend_from_slice(LOWER);
        password.push(generate_rand_char(&mut rng, LOWER));
        cur_length += 1;
    }
    if cur_length < length && !no_number {
        chars.extend_from_slice(NUMBER);
        password.push(generate_rand_char(&mut rng, NUMBER));
        cur_length += 1;
    }
    if cur_length < length && !no_symbol {
        chars.extend_from_slice(SYMBOL);
        password.push(generate_rand_char(&mut rng, SYMBOL));
        cur_length += 1;
    }

    for _ in cur_length..length {
        password.push(generate_rand_char(&mut rng, &chars));
    }
    password.shuffle(&mut rng);
    Ok(String::from_utf8(password)?)
}

fn generate_rand_char(rng: &mut ThreadRng, chars: &[u8]) -> u8 {
    *(chars
        .choose(rng)
        .expect("chars won't be empty in this context"))
}
