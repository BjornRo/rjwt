use jsonwebtoken::{decode, encode, Validation};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData};
use pyo3::prelude::*;
use pyo3::types::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use serde_pyobject::from_pyobject;
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use unsafe_unwrap::UnsafeUnwrap;

macro_rules! add_classes {
        ($module:ident, $($class:ty),+)
        => {$($module.add_class::<$class>()?;)+
    };
}

// macro_rules! add_functions {
//         ($module:ident, $($function:ident),+)
//         => {$($module.add_wrapped(wrap_pyfunction!($function))?;)+
//     };
// }

#[pymodule]
fn rjwt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_classes!(m, HashAlgorithms, HMAC);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims(BTreeMap<String, Value>);

#[pyclass]
#[derive(Clone)]
enum HashAlgorithms {
    SHA256,
    SHA384,
    ES256,
    ES384,
}

#[pyclass(module = "rjwt")]
// #[derive(Clone)]
struct HMAC {
    privkey: EncodingKey, // For HMAC same secret for both
    pubkey: DecodingKey,
    validation: Validation,
    header: Header,
}

#[pymethods]
impl HMAC {
    #[new]
    #[pyo3(signature = (key, algorithm_type))]
    fn new(key: &Bound<'_, PyBytes>, algorithm_type: HashAlgorithms) -> Self {
        let algo = match algorithm_type {
            HashAlgorithms::SHA256 => Algorithm::HS256,
            HashAlgorithms::SHA384 => Algorithm::HS384,
            _ => panic!("Should not be used"),
        };
        let mut val = Validation::new(algo);
        val.validate_aud = false;

        HMAC {
            privkey: EncodingKey::from_secret(key.as_bytes()),
            pubkey: DecodingKey::from_secret(key.as_bytes()),
            validation: val,
            header: Header::new(algo),
        }
    }

    #[pyo3(signature = (timedelta, custom_claims=None))]
    fn sign(
        &self,
        timedelta: &Bound<'_, PyDelta>,
        custom_claims: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<String> {
        let token = generate_token(&timedelta, self.header.clone(), custom_claims);
        Ok(unsafe { encode(&token.header, &token.claims, &self.privkey).unsafe_unwrap() })
    }

    // If valid, returns a dict, else None
    #[pyo3(signature = (token_str))]
    fn verify(&self, token_str: &Bound<'_, PyString>) -> Option<HashMap<String, Py<PyAny>>> {
        if let Ok(token_rstr) = token_str.to_str() {
            match decode::<TokenClaims>(&token_rstr, &self.pubkey, &self.validation) {
                Ok(token) => Some(Python::with_gil(|py| {
                    claims_to_pyhashmap(py, &token.claims)
                })),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}

#[pyclass(module = "rjwt")]
struct ECDSA {
    privkey: EncodingKey,
    pubkey: DecodingKey,
    validation: Validation,
    header: Header,
}

#[pymethods]
impl ECDSA {
    #[new]
    #[pyo3(signature = (priv_pem, pub_pem, algorithm_type))]
    fn new(
        priv_pem: &Bound<'_, PyBytes>,
        pub_pem: &Bound<'_, PyBytes>,
        algorithm_type: HashAlgorithms,
    ) -> Self {
        let algo = match algorithm_type {
            HashAlgorithms::ES256 => Algorithm::ES256,
            HashAlgorithms::ES384 => Algorithm::ES384,
            _ => panic!("Should not be used"),
        };
        let mut val = Validation::new(algo);
        val.validate_aud = false;

        ECDSA {
            privkey: EncodingKey::from_secret(priv_pem.as_bytes()),
            pubkey: DecodingKey::from_secret(pub_pem.as_bytes()),
            validation: val,
            header: Header::new(algo),
        }
    }

    #[pyo3(signature = (timedelta, custom_claims=None))]
    fn encode(
        &self,
        timedelta: &Bound<'_, PyDelta>,
        custom_claims: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<String> {
        let token = generate_token(&timedelta, self.header.clone(), custom_claims);
        Ok(unsafe { encode(&token.header, &token.claims, &self.privkey).unsafe_unwrap() })
    }

    // If valid, returns a dict, else None
    #[pyo3(signature = (token_str))]
    fn decode(&self, token_str: &Bound<'_, PyString>) -> Option<HashMap<String, Py<PyAny>>> {
        if let Ok(token_rstr) = token_str.to_str() {
            match decode::<TokenClaims>(&token_rstr, &self.pubkey, &self.validation) {
                Ok(token) => Some(Python::with_gil(|py| {
                    claims_to_pyhashmap(py, &token.claims)
                })),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}

/*
Functions
*/

fn generate_token(
    timedelta: &Bound<'_, PyDelta>,
    header: Header,
    custom_claims: Option<&Bound<'_, PyDict>>,
) -> TokenData<BTreeMap<String, Value>> {
    let mut claims: BTreeMap<String, Value> = BTreeMap::new();

    let iat = unsafe {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unsafe_unwrap()
            .as_secs()
    };
    claims.insert("iat".to_string(), json!(iat));
    claims.insert(
        "exp".to_string(),
        json!(iat + (timedelta.get_seconds() as u64)),
    );
    if let Some(cc) = custom_claims {
        for (k, v) in cc {
            unsafe {
                claims.insert(
                    k.str().unsafe_unwrap().to_string(),
                    from_pyobject(v).unsafe_unwrap(),
                )
            };
        }
    };
    TokenData { header, claims }
}

fn jsonvalue_to_pyobj(py: Python, value: &Value) -> Py<PyAny> {
    match value {
        Value::Null => py.None(),
        Value::Bool(v) => v.into_py(py),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py(py)
            } else {
                unsafe { n.as_f64().unsafe_unwrap().into_py(py) }
            }
        }
        Value::String(s) => s.into_py(py),
        Value::Array(arr) => {
            let list = PyList::new_bound(py, arr.iter().map(|elem| jsonvalue_to_pyobj(py, elem)));
            list.into_py(py)
        }
        Value::Object(obj) => {
            let dict = PyDict::new_bound(py);
            for (inner_key, inner_val) in obj {
                unsafe {
                    dict.set_item(inner_key, jsonvalue_to_pyobj(py, inner_val))
                        .unsafe_unwrap()
                };
            }
            dict.into_py(py)
        }
    }
}

fn claims_to_pyhashmap(py: Python, hashmap: &TokenClaims) -> HashMap<String, Py<PyAny>> {
    hashmap
        .0
        .iter()
        .map(|(k, v)| (k.clone(), jsonvalue_to_pyobj(py, &v)))
        .collect::<HashMap<String, Py<PyAny>>>()
}
