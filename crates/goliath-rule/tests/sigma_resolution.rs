//! Resolving Sigma rules through the shipped Windows mapping set.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_rule::{
    Comparison, Expr, FieldPath, MappingError, MappingSet, Number, Predicate, ResolveError,
    StringTest, Test, sigma,
};
use goliath_sigma::{Pattern, PatternPart, parse_rule};

const SIGMA_WINDOWS: &str = goliath_rule::SIGMA_WINDOWS;

fn resolve(detection: &str) -> Result<Expr, ResolveError> {
    let source = format!(
        "title: t\nlogsource: {{ category: process_creation, product: windows }}\ndetection:\n{detection}"
    );
    let rule = parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(SIGMA_WINDOWS).expect("mapping loads");
    sigma::resolve(&rule, &mappings).map(|resolved| resolved.condition)
}

fn resolved(detection: &str) -> Expr {
    resolve(detection).expect("rule resolves")
}

fn paths(texts: &[&str]) -> Vec<FieldPath> {
    texts
        .iter()
        .map(|text| FieldPath::parse(text).expect("valid path"))
        .collect()
}

fn field(expr: &Expr) -> &Predicate {
    match expr {
        Expr::Field(predicate) => predicate,
        other => panic!("expected a field predicate, got {other:?}"),
    }
}

fn string(expr: &Expr) -> &StringTest {
    match &field(expr).test {
        Test::String(test) => test,
        other => panic!("expected a string test, got {other:?}"),
    }
}

fn operands(expr: &Expr) -> &[Expr] {
    match expr {
        Expr::And(operands) | Expr::Or(operands) => operands,
        other => panic!("expected a conjunction or disjunction, got {other:?}"),
    }
}

#[test]
fn a_whole_rule_resolves_to_paths_and_folded_patterns() {
    let condition = resolved(
        r"
  selection_image:
    Image|endswith: '\PowerShell.exe'
  selection_flag:
    CommandLine|contains: ' -enc '
  filter:
    - ParentImage|endswith: '\ccmexec.exe'
    - User: SYSTEM
  condition: all of selection_* and not filter
",
    );

    // Searches are resolved in name order: selection_flag, then selection_image.
    let [flag, image, not_filter] = operands(&condition) else {
        panic!("expected three operands: {condition:?}");
    };

    assert_eq!(
        field(image).paths,
        paths(&["process.file.path", "process.path"])
    );
    let image = string(image);
    assert!(!image.cased);
    assert_eq!(image.pattern, Pattern::parse(r"*\\powershell.exe"));

    assert_eq!(field(flag).paths, paths(&["process.cmd_line"]));
    assert_eq!(string(flag).pattern, Pattern::parse("* -enc *"));

    let Expr::Not(filter) = not_filter else {
        panic!("expected a negation: {not_filter:?}");
    };
    let [parent, user] = operands(filter) else {
        panic!("expected two alternatives: {filter:?}");
    };
    assert_eq!(
        field(parent).paths.len(),
        4,
        "every parent path is searched"
    );
    assert_eq!(string(user).pattern, Pattern::parse("system"));
}

#[test]
fn cased_keeps_the_literal_case() {
    let condition =
        resolved("  sel:\n    CommandLine|cased|contains: 'PowerShell'\n  condition: sel\n");
    let test = string(&condition);
    assert!(test.cased);
    assert_eq!(test.pattern, Pattern::parse("*PowerShell*"));
}

#[test]
fn base64offset_becomes_three_cased_variants() {
    let condition =
        resolved("  sel:\n    CommandLine|base64offset|contains: 'ping'\n  condition: sel\n");
    let variants: Vec<_> = operands(&condition).iter().map(string).collect();
    assert_eq!(variants.len(), 3);
    assert!(
        variants.iter().all(|test| test.cased),
        "base64 is case sensitive"
    );
    assert_eq!(variants[0].pattern, Pattern::parse("*cGluZ*"));
}

#[test]
fn windash_becomes_one_variant_per_dash() {
    let condition =
        resolved("  sel:\n    CommandLine|windash|contains: ' -enc '\n  condition: sel\n");
    assert_eq!(operands(&condition).len(), 5);
}

#[test]
fn all_requires_every_value() {
    let condition = resolved(
        "  sel:\n    CommandLine|contains|all:\n      - ' -nop '\n      - ' -w hidden '\n  condition: sel\n",
    );
    assert!(matches!(condition, Expr::And(ref operands) if operands.len() == 2));
}

#[test]
fn regex_keeps_the_expression_as_written() {
    let condition = resolved("  sel:\n    CommandLine|re: '\\\\d+ a.*b'\n  condition: sel\n");
    let Test::Regex { pattern, .. } = &field(&condition).test else {
        panic!("expected a regex: {condition:?}");
    };
    assert_eq!(pattern, r"\\d+ a.*b");
}

#[test]
fn numbers_compare_as_numbers_or_as_text() {
    let equals = resolved("  sel:\n    ProcessId: 4\n  condition: sel\n");
    assert_eq!(field(&equals).test, Test::Equals(Number::Integer(4)));

    let prefix = resolved("  sel:\n    ProcessId|startswith: 4\n  condition: sel\n");
    assert_eq!(string(&prefix).pattern, Pattern::parse("4*"));

    let greater = resolved("  sel:\n    ProcessId|gt: 1000\n  condition: sel\n");
    assert_eq!(
        field(&greater).test,
        Test::Compare {
            op: Comparison::Greater,
            value: Number::Integer(1000)
        }
    );
}

#[test]
fn fieldref_resolves_the_other_field_too() {
    let condition = resolved("  sel:\n    ParentUser|fieldref: User\n  condition: sel\n");
    assert_eq!(
        field(&condition).test,
        Test::FieldRef {
            paths: paths(&["process.user.name"]),
            cased: false
        }
    );
}

#[test]
fn keywords_search_every_string_for_folded_text() {
    let condition = resolved("  keywords:\n    - 'Mimi'\n  condition: keywords\n");
    let Expr::Keyword(test) = condition else {
        panic!("expected a keyword: {condition:?}");
    };
    assert_eq!(
        test.pattern.parts(),
        [
            PatternPart::AnySequence,
            PatternPart::Literal("mimi".to_owned()),
            PatternPart::AnySequence
        ]
    );
}

#[test]
fn keywords_under_all_must_every_one_appear() {
    let condition =
        resolved("  keywords:\n    '|all':\n      - 'a'\n      - 'b'\n  condition: keywords\n");
    let Expr::And(keywords) = condition else {
        panic!("expected a conjunction: {condition:?}");
    };
    assert_eq!(keywords.len(), 2);
    assert!(
        keywords
            .iter()
            .all(|keyword| matches!(keyword, Expr::Keyword(_)))
    );

    let error = resolve("  keywords:\n    '|startswith': 'a'\n  condition: keywords\n")
        .expect_err("startswith has no meaning without a field");
    assert!(matches!(
        error,
        ResolveError::UnsupportedModifier {
            modifier: "startswith",
            ..
        }
    ));
}

#[test]
fn them_leaves_out_underscore_searches() {
    let condition =
        resolved("  sel:\n    Image: a\n  _helper:\n    Image: b\n  condition: 1 of them\n");
    assert_eq!(string(&condition).pattern, Pattern::parse("a"));
}

#[test]
fn an_unmapped_field_is_refused() {
    let error = resolve("  sel:\n    NoSuchField: a\n  condition: sel\n").expect_err("unmapped");
    assert!(
        matches!(error, ResolveError::UnmappedField { ref field, .. } if field == "NoSuchField")
    );
}

#[test]
fn a_log_source_without_a_mapping_is_refused() {
    let rule = parse_rule(
        "title: t\nlogsource: { category: process_creation, product: linux }\ndetection:\n  sel:\n    Image: a\n  condition: sel\n",
    )
    .expect("parses");
    let mappings = MappingSet::from_yaml(SIGMA_WINDOWS).expect("loads");
    assert!(matches!(
        sigma::resolve(&rule, &mappings),
        Err(ResolveError::Mapping(MappingError::NoMapping { .. }))
    ));
}

#[test]
fn expand_is_refused() {
    let error =
        resolve("  sel:\n    User|expand: '%admins%'\n  condition: sel\n").expect_err("expand");
    assert!(matches!(
        error,
        ResolveError::UnsupportedModifier {
            modifier: "expand",
            ..
        }
    ));
}

#[test]
fn the_class_condition_and_mapping_version_are_carried() {
    let rule = parse_rule(
        "title: t\nid: abc\nlogsource: { category: process_creation, product: windows }\ndetection:\n  sel:\n    Image: a\n  condition: sel\n",
    )
    .expect("parses");
    let mappings = MappingSet::from_yaml(SIGMA_WINDOWS).expect("loads");
    let resolved = sigma::resolve(&rule, &mappings).expect("resolves");
    assert_eq!(resolved.id.as_deref(), Some("abc"));
    assert_eq!(resolved.mapping.name, "sigma-windows");
    assert_eq!(resolved.class.len(), 3);
}
