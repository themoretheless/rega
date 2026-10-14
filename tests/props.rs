//! Property tests: parsing and mapping never panic on arbitrary input.

use proptest::prelude::*;
use rega::profile::{map_apple, map_profile};
use rega::{Callback, Provider};
use serde_json::{json, Value};

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        ".{0,16}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::hash_map(
                prop_oneof![
                    Just("sub".to_string()),
                    Just("id".to_string()),
                    Just("email".to_string()),
                    Just("data".to_string()),
                    Just("user".to_string()),
                    Just("email_verified".to_string()),
                    ".{0,8}"
                ],
                inner,
                0..6
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn callback_parse_never_panics(s in ".{0,256}") {
        let cb = Callback::parse(&s);
        let _ = cb.get("state");
    }

    #[test]
    fn map_profile_never_panics(p in arb_json(), idx in 0usize..12) {
        let provider = Provider::ALL[idx];
        if let Ok(i) = map_profile(provider, p.clone()) {
            prop_assert!(!i.subject.is_empty());
            prop_assert!(!i.email_verified || i.email.is_some());
            if let Some(e) = &i.email {
                prop_assert_eq!(e, &e.trim().to_lowercase());
            }
        }
        let _ = map_apple(p.clone(), Some(p));
    }
}
