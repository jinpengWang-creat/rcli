use crate::cli::ExpireTime;
use crate::utils::get_reader;
use anyhow::Result;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub fn process_jwt_sign(
    alg: Algorithm,
    aud: Option<&str>,
    exp: ExpireTime,
    sub: Option<&str>,
    secret: &str,
) -> Result<String> {
    let mut claims = Claims::default();
    let claims = claims.aud(aud).exp(exp).sub(sub);
    let header = Header::new(alg);
    let token = encode(&header, claims, &EncodingKey::from_secret(secret.as_ref()))?;
    Ok(token)
}

pub fn process_jwt_verify(
    alg: Algorithm,
    auds: Option<&[String]>,
    input: &str,
    secret: &str,
) -> Result<()> {
    let mut reader = get_reader(input)?;
    let mut token = String::new();
    reader.read_to_string(&mut token)?;
    let token = token.trim();
    let mut validation = Validation::new(alg);
    if let Some(auds) = auds {
        validation.set_audience(auds);
    }
    println!("{:?}", validation.aud);
    let token_message = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    );
    println!("message: {:?}", token_message);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Claims {
    aud: String,
    exp: usize,
    sub: String,
}

impl Claims {
    fn aud(&mut self, aud: Option<&str>) -> &mut Self {
        if let Some(aud) = aud {
            self.aud = aud.to_string();
        }
        self
    }

    fn exp(&mut self, exp: ExpireTime) -> &mut Self {
        self.exp = exp.0;
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
