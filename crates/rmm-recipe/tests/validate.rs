use std::collections::BTreeMap;

use ciborium::Value;
use rmm_recipe::RecipeError;
use rmm_recipe::definition::{Arg, Definition, OnFail, ParamKind, ParamSpec, Step};
use rmm_recipe::result::{ActionResult, Outcome, RejectReason, StageOutcome};
use rmm_recipe::validate::{BLOCKS, validate_definition, validate_params};

const SPOOLER: &str = include_str!("../../../catalog/printing.spooler-restart.json");

fn spooler() -> Definition {
    serde_json::from_str(SPOOLER).expect("spooler draft parses")
}

fn lit(s: &str) -> Arg {
    Arg::Lit(Value::Text(s.into()))
}

fn step(block: &str, args: &[(&str, Arg)]) -> Step {
    Step {
        block: block.into(),
        args: args
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
        retries: 0,
        on_fail: OnFail::Abort,
    }
}

fn query(name: &str) -> Step {
    step("service.query", &[("name", lit(name))])
}

fn param(name: &str, kind: ParamKind) -> ParamSpec {
    ParamSpec {
        name: name.into(),
        kind,
        required: true,
        enum_values: vec![],
        max_len: None,
        min: None,
        max: None,
    }
}

fn simple() -> Definition {
    let mut d = spooler();
    d.precheck.clear();
    d.verify.clear();
    d.rollback.clear();
    d.steps = vec![query("Spooler")];
    d
}

#[test]
fn spooler_draft_validates_and_round_trips() {
    let d = spooler();
    validate_definition(&d, BLOCKS).expect("valid");
    let bytes = d.to_canonical().expect("encode");
    assert_eq!(
        Definition::from_envelope_payload(&bytes).expect("decode"),
        d
    );
}

#[test]
fn unknown_block() {
    let mut d = simple();
    d.steps.push(step("shell.exec", &[]));
    assert_eq!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::UnknownBlock("shell.exec".into()))
    );
}

#[test]
fn param_not_declared() {
    let mut d = simple();
    d.steps = vec![step("service.query", &[("name", Arg::Param("svc".into()))])];
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidArg(_))
    ));
}

#[test]
fn param_wrong_kind_for_arg() {
    let mut d = simple();
    d.params = vec![param("svc", ParamKind::Int)];
    d.steps = vec![step("service.query", &[("name", Arg::Param("svc".into()))])];
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidArg(_))
    ));
    d.params = vec![param("svc", ParamKind::String)];
    validate_definition(&d, BLOCKS).expect("string param fits a text arg");
}

#[test]
fn literal_wrong_type_missing_and_unknown_args() {
    let mut d = simple();
    d.steps = vec![step(
        "service.query",
        &[("name", Arg::Lit(Value::Integer(1.into())))],
    )];
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidArg(_))
    ));
    d.steps = vec![step("service.query", &[])];
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidArg(_))
    ));
    d.steps = vec![step(
        "service.query",
        &[("name", lit("a")), ("extra", lit("b"))],
    )];
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidArg(_))
    ));
}

#[test]
fn snapshot_before_producer_is_rejected() {
    let mut d = simple();
    d.steps = vec![step(
        "service.wait",
        &[
            ("name", lit("Spooler")),
            ("state", Arg::Snapshot("service.query".into())),
            ("timeout_s", Arg::Lit(Value::Integer(5.into()))),
        ],
    )];
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidArg(_))
    ));
    d.precheck = vec![query("Spooler")];
    validate_definition(&d, BLOCKS).expect("snapshot after producer");
}

#[test]
fn too_many_steps() {
    let mut d = simple();
    d.steps = (0..33).map(|_| query("Spooler")).collect();
    assert_eq!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::TooManySteps)
    );
    d.steps.pop();
    d.steps.pop();
    validate_definition(&d, BLOCKS).expect("31 steps fit");
    d.steps.push(query("Spooler"));
    validate_definition(&d, BLOCKS).expect("32 steps fit");
}

#[test]
fn retries_bound() {
    let mut d = simple();
    d.steps[0].retries = 3;
    validate_definition(&d, BLOCKS).expect("3 retries fit");
    d.steps[0].retries = 4;
    assert_eq!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidRetries)
    );
}

#[test]
fn capability_group_must_be_allowed() {
    let mut d = simple();
    d.capability = "files.write".into();
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::CapabilityMismatch(_))
    ));
}

#[test]
fn definition_field_bounds() {
    let mut d = simple();
    d.timeout_s = 901;
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidDefinition(_))
    ));
    let mut d = simple();
    d.min_agent_version = "latest".into();
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidDefinition(_))
    ));
    let mut d = simple();
    d.id = "Bad Name".into();
    assert!(matches!(
        validate_definition(&d, BLOCKS),
        Err(RecipeError::InvalidDefinition(_))
    ));
}

#[test]
fn unknown_field_is_a_decode_error() {
    let mut v: serde_json::Value = serde_json::from_str(SPOOLER).expect("json");
    v["surprise"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Definition>(v).is_err());

    // and in canonical CBOR
    let d = spooler();
    let Value::Map(mut m) = Value::serialized(&d).expect("value") else {
        panic!("definition is a map");
    };
    m.push((Value::Text("surprise".into()), Value::Integer(1.into())));
    let bytes = rmm_proto::canonical::encode_value(&Value::Map(m)).expect("encode");
    assert!(matches!(
        Definition::from_envelope_payload(&bytes),
        Err(RecipeError::Decode(_))
    ));
}

#[test]
fn non_canonical_payload_is_rejected() {
    let mut bytes = spooler().to_canonical().expect("encode");
    bytes.push(0);
    assert!(matches!(
        Definition::from_envelope_payload(&bytes),
        Err(RecipeError::Decode(_))
    ));
}

fn params(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn with_params(specs: Vec<ParamSpec>) -> Definition {
    let mut d = simple();
    d.params = specs;
    d
}

#[test]
fn string_params() {
    let mut p = param("label", ParamKind::String);
    p.max_len = Some(4);
    let d = with_params(vec![p]);
    validate_params(&d, &params(&[("label", Value::Text("abcd".into()))])).expect("fits");
    for bad in [Value::Text("abcde".into()), Value::Integer(1.into())] {
        assert!(matches!(
            validate_params(&d, &params(&[("label", bad)])),
            Err(RecipeError::InvalidParam(_))
        ));
    }
}

#[test]
fn enum_params() {
    let mut p = param("mode", ParamKind::Enum);
    p.enum_values = vec!["fast".into(), "safe".into()];
    let d = with_params(vec![p]);
    validate_definition(&d, BLOCKS).expect("valid");
    validate_params(&d, &params(&[("mode", Value::Text("safe".into()))])).expect("member");
    assert!(matches!(
        validate_params(&d, &params(&[("mode", Value::Text("other".into()))])),
        Err(RecipeError::InvalidParam(_))
    ));
}

#[test]
fn int_params() {
    let mut p = param("n", ParamKind::Int);
    p.min = Some(1);
    p.max = Some(10);
    let d = with_params(vec![p]);
    for ok in [1, 10] {
        validate_params(&d, &params(&[("n", Value::Integer(ok.into()))])).expect("in range");
    }
    for bad in [0, 11, -5] {
        assert!(matches!(
            validate_params(&d, &params(&[("n", Value::Integer(bad.into()))])),
            Err(RecipeError::InvalidParam(_))
        ));
    }
    assert!(matches!(
        validate_params(&d, &params(&[("n", Value::Text("3".into()))])),
        Err(RecipeError::InvalidParam(_))
    ));
}

#[test]
fn bool_params_missing_and_undeclared() {
    let mut opt = param("force", ParamKind::Bool);
    opt.required = false;
    let d = with_params(vec![opt, param("must", ParamKind::Bool)]);
    validate_params(&d, &params(&[("must", Value::Bool(true))])).expect("optional may be absent");
    assert!(matches!(
        validate_params(&d, &params(&[])),
        Err(RecipeError::InvalidParam(_))
    ));
    assert!(matches!(
        validate_params(
            &d,
            &params(&[("must", Value::Bool(true)), ("zzz", Value::Bool(true))])
        ),
        Err(RecipeError::InvalidParam(_))
    ));
    assert!(matches!(
        validate_params(&d, &params(&[("must", Value::Text("yes".into()))])),
        Err(RecipeError::InvalidParam(_))
    ));
}

#[test]
fn result_round_trip_and_rules() {
    let r = ActionResult {
        cmd_id: rmm_trust::keys::Bytes(vec![7; 16]),
        agent_id: "agent_x".into(),
        definition_content_id: rmm_trust::keys::KeyId([1; 32]),
        outcome: Outcome::Rejected,
        reason: Some(RejectReason::Expired),
        stages: vec![StageOutcome {
            stage: rmm_recipe::definition::Stage::Precheck,
            ok: false,
            started_at: 1,
            finished_at: 2,
            detail: "x".into(),
        }],
        finished_at: 3,
    };
    r.validate().expect("valid");
    let bytes = r.to_canonical().expect("encode");
    assert_eq!(
        ActionResult::from_envelope_payload(&bytes).expect("decode"),
        r
    );
    let mut bad = r.clone();
    bad.reason = None;
    assert!(bad.validate().is_err());
    let mut bad = r;
    bad.stages[0].detail = "x".repeat(4097);
    assert!(bad.validate().is_err());
}
