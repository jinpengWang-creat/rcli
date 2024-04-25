use crate::cli::ExpireTime;
use anyhow::Result;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::{hmac, rand};
use serde::{Deserialize, Serialize};

pub fn process_jwt_sign(
    alg: Algorithm,
    aut: Option<&str>,
    expr: ExpireTime,
    iat: Option<usize>,
    iss: Option<&str>,
    sub: Option<&str>,
    secret: &str,
) -> Result<String> {
    let mut claims = Claims::default();
    let claims = claims.aud(aut).expr(expr).sub(sub).iat(iat).iss(iss);
    let header = Header::new(alg);
    let rng = rand::SystemRandom::new();
    let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)?;
    let tag = hmac::sign(&key, secret.as_bytes());
    let token = encode(&header, claims, &EncodingKey::from_secret(tag.as_ref()))?;
    Ok(token)
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Claims {
    aud: String,
    expr: usize,
    iat: usize,
    iss: String,
    sub: String,
}

impl Claims {
    fn aud(&mut self, aud: Option<&str>) -> &mut Self {
        if let Some(aud) = aud {
            self.aud = aud.to_string();
        }
        self
    }

    fn expr(&mut self, expr: ExpireTime) -> &mut Self {
        self.expr = expr.0;
        self
    }

    fn iat(&mut self, iat: Option<usize>) -> &mut Self {
        if let Some(iat) = iat {
            self.iat = iat;
        }
        self
    }
    fn iss(&mut self, iss: Option<&str>) -> &mut Self {
        if let Some(iss) = iss {
            self.iss = iss.to_string();
        }
        self
    }
    fn sub(&mut self, sub: Option<&str>) -> &mut Self {
        if let Some(sub) = sub {
            self.sub = sub.to_string();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        company: String,
        exp: u64,
    }

    #[test]
    fn test_jwt() {
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned(),
            exp: 10000000000,
        };
        let key = b"secret";

        let header = Header {
            kid: Some("signing_key".to_owned()),
            alg: Algorithm::HS512,
            ..Default::default()
        };

        let token = match encode(&header, &my_claims, &EncodingKey::from_secret(key)) {
            Ok(t) => t,
            Err(_) => panic!(), // in practice you would return the error
        };
        println!("{:?}", token);

        // let token_data = match decode::<Claims>(
        //     &token,
        //     &DecodingKey::from_secret(key),
        //     &Validation::new(Algorithm::HS512),
        // ) {
        //     Ok(c) => c,
        //     Err(err) => match *err.kind() {
        //         ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
        //         _ => panic!(),
        //     },
        // };
        // println!("{:?}", token_data.claims);
        // println!("{:?}", token_data.header);
    }
}
