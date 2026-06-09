//! Parser for preset invocation strings of the form
//! `'<name>[:<key>=<val>,<key>=<val>,...]'`.
//!
//! The colon separator is optional for parameterless presets: `ubuntu`
//! and `ubuntu:` are both accepted and produce identical
//! `ParsedInvocation` values (empty params, `raw` preserved verbatim).
//!
//! The parser is fail-loud on raw `,`, `:`, and `=` inside values:
//! there is no escape mechanism, and a value containing any of those
//! three characters produces a [`PresetError::ForbiddenChar`] rather
//! than being silently interpreted.
//!
//! Grammar:
//!
//! ```text
//! invocation  = name [ ":" [ params ] ]
//! name        = any non-empty string not containing ":"
//! params      = param ("," param)*
//! param       = key "=" value
//! key         = any non-empty string not containing "=" or "," or ":"
//! value       = any (possibly empty) string not containing "=" or "," or ":"
//! ```
//!
//! Whitespace inside values is preserved verbatim — no trimming. Repeated
//! keys are allowed and their values stack in invocation order (e.g. for
//! the built-in `github-repo` preset's repeatable `repo=` param).

use super::PresetError;

/// Result of parsing a `'name[:k=v,...]'` invocation string.
///
/// The `raw` field preserves the caller's original string so it can be
/// transmitted to the daemon as part of the `source_presets` field on
/// create/update requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInvocation {
    /// The preset name (before the `:` separator, or the whole input
    /// when no `:` is present).
    pub name: String,
    /// The `(key, value)` pairs, in the order they were provided.
    /// Repeated keys preserve their order of appearance.
    pub params: Vec<(String, String)>,
    /// The original invocation string, used verbatim for
    /// `source_presets` wire transmission.
    pub raw: String,
}

impl ParsedInvocation {
    /// Parse a preset invocation string.
    ///
    /// See the module-level docs for the grammar and error cases.
    pub fn parse(input: &str) -> Result<Self, PresetError> {
        // A bare name with no `:` is valid — treat it as name + empty
        // params. This allows `--preset ubuntu` as equivalent to
        // `--preset ubuntu:`.
        let (name, params_str) = match input.find(':') {
            Some(colon_idx) => (&input[..colon_idx], &input[colon_idx + 1..]),
            None => (input, ""),
        };

        if name.is_empty() {
            return Err(PresetError::MalformedInvocation {
                raw: input.to_string(),
                reason: "preset name is empty".to_string(),
            });
        }

        let mut params = Vec::new();
        if !params_str.is_empty() {
            for segment in params_str.split(',') {
                // Each segment must be `key=value`.
                let Some(eq_idx) = segment.find('=') else {
                    return Err(PresetError::MalformedInvocation {
                        raw: input.to_string(),
                        reason: format!(
                            "param segment '{segment}' is missing '=' between key and value; \
                             try '{name}:key=value'"
                        ),
                    });
                };

                let key = &segment[..eq_idx];
                let value = &segment[eq_idx + 1..];

                if key.is_empty() {
                    return Err(PresetError::MalformedInvocation {
                        raw: input.to_string(),
                        reason: format!("param segment '{segment}' has an empty key"),
                    });
                }

                // Reject raw `,`, `:`, `=` in values (D-2).
                //
                // The `,` arm is defensive: the current grammar splits
                // on `,` before reaching here, so a literal comma in
                // the value never arrives as a `ForbiddenChar`. The
                // arm is kept to localize the "forbidden value chars"
                // list to one place — if the split grammar is revised
                // in the future, the check still fires.
                if let Some(ch) = value.chars().find(|c| matches!(c, ',' | ':' | '=')) {
                    return Err(PresetError::ForbiddenChar {
                        preset: name.to_string(),
                        key: key.to_string(),
                        value: value.to_string(),
                        ch,
                    });
                }

                params.push((key.to_string(), value.to_string()));
            }
        }

        Ok(ParsedInvocation {
            name: name.to_string(),
            params,
            raw: input.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy paths ------------------------------------------------

    #[test]
    fn parse_empty_params_trailing_colon() {
        let inv = ParsedInvocation::parse("name:").expect("should parse");
        assert_eq!(inv.name, "name");
        assert!(inv.params.is_empty());
        assert_eq!(inv.raw, "name:");
    }

    #[test]
    fn parse_bare_name_no_colon() {
        // A bare name without `:` is equivalent to `name:` — empty params.
        let inv = ParsedInvocation::parse("ubuntu").expect("should parse");
        assert_eq!(inv.name, "ubuntu");
        assert!(inv.params.is_empty());
        assert_eq!(inv.raw, "ubuntu");
    }

    #[test]
    fn parse_bare_name_and_colon_form_are_equivalent() {
        let bare = ParsedInvocation::parse("npm").expect("bare form");
        let colon = ParsedInvocation::parse("npm:").expect("colon form");
        assert_eq!(bare.name, colon.name);
        assert_eq!(bare.params, colon.params);
        // `raw` differs by design (it preserves the exact input).
    }

    #[test]
    fn parse_single_param() {
        let inv = ParsedInvocation::parse("name:k=v").expect("should parse");
        assert_eq!(inv.name, "name");
        assert_eq!(inv.params, vec![("k".to_string(), "v".to_string())]);
    }

    #[test]
    fn parse_two_distinct_keys() {
        let inv = ParsedInvocation::parse("name:k=v,k2=v2").expect("should parse");
        assert_eq!(inv.name, "name");
        assert_eq!(
            inv.params,
            vec![
                ("k".to_string(), "v".to_string()),
                ("k2".to_string(), "v2".to_string()),
            ]
        );
    }

    #[test]
    fn parse_repeated_key_stacks_values_in_order() {
        let inv = ParsedInvocation::parse("name:k=v1,k=v2").expect("should parse");
        assert_eq!(
            inv.params,
            vec![
                ("k".to_string(), "v1".to_string()),
                ("k".to_string(), "v2".to_string()),
            ]
        );
    }

    #[test]
    fn parse_empty_value_is_accepted() {
        let inv = ParsedInvocation::parse("name:k=").expect("should parse");
        assert_eq!(inv.params, vec![("k".to_string(), "".to_string())]);
    }

    // ----- error paths ------------------------------------------------

    #[test]
    fn parse_empty_input_is_empty_name() {
        let err = ParsedInvocation::parse("").expect_err("should reject");
        assert!(matches!(err, PresetError::MalformedInvocation { .. }));
    }

    #[test]
    fn parse_empty_name_with_colon_is_error() {
        let err = ParsedInvocation::parse(":k=v").expect_err("should reject");
        assert!(matches!(err, PresetError::MalformedInvocation { .. }));
    }

    #[test]
    fn parse_value_with_comma_is_forbidden_char() {
        // Splitting on `,` produces two segments — the second lacks '=',
        // so this is classified as a MalformedInvocation ("missing '=' ...")
        // rather than ForbiddenChar.  That is the correct user-facing
        // signal: the comma split breaks the structure, not the value.
        //
        // To exercise the ForbiddenChar path for a value containing `,`,
        // the only way the parser can see one is via a direct character
        // test — covered by the `:` and `=` cases below plus the
        // defensive re-check in `parse`.  We still assert the user-visible
        // outcome: some variety of parse error is returned.
        let err = ParsedInvocation::parse("name:k=v1,v2extra").expect_err("should reject");
        assert!(matches!(
            err,
            PresetError::MalformedInvocation { .. } | PresetError::ForbiddenChar { .. }
        ));
    }

    #[test]
    fn parse_value_with_raw_colon_is_forbidden_char() {
        // `'repo=foo/bar:extra'` — the second `:` lands inside the value.
        // Our splitter uses `.find(':')`, so the first colon cuts the
        // name off and the `:` survives in the remaining text as part of
        // the value `foo/bar:extra`.
        let err = ParsedInvocation::parse("name:repo=foo/bar:extra").expect_err("should reject");
        match err {
            PresetError::ForbiddenChar {
                preset,
                key,
                value,
                ch,
            } => {
                assert_eq!(preset, "name");
                assert_eq!(key, "repo");
                assert_eq!(value, "foo/bar:extra");
                assert_eq!(ch, ':');
            }
            other => panic!("expected ForbiddenChar, got {other:?}"),
        }
    }

    #[test]
    fn parse_value_with_raw_equals_is_forbidden_char() {
        // `k=v=extra` — the first `=` separates key from value; the
        // second `=` lands inside the value and is rejected.
        let err = ParsedInvocation::parse("name:k=v=extra").expect_err("should reject");
        match err {
            PresetError::ForbiddenChar {
                preset,
                key,
                value,
                ch,
            } => {
                assert_eq!(preset, "name");
                assert_eq!(key, "k");
                assert_eq!(value, "v=extra");
                assert_eq!(ch, '=');
            }
            other => panic!("expected ForbiddenChar, got {other:?}"),
        }
    }

    #[test]
    fn parse_empty_key_is_error() {
        let err = ParsedInvocation::parse("name:=v").expect_err("should reject");
        assert!(matches!(err, PresetError::MalformedInvocation { .. }));
    }

    // ----- additional behavior checks --------------------------------

    #[test]
    fn parse_preserves_whitespace_in_values() {
        let inv = ParsedInvocation::parse("name:k=hello world").expect("should parse");
        assert_eq!(
            inv.params,
            vec![("k".to_string(), "hello world".to_string())]
        );
    }

    #[test]
    fn parse_raw_field_matches_input_exactly() {
        let input = "github-repo:repo=foo/bar,repo=baz/qux";
        let inv = ParsedInvocation::parse(input).expect("should parse");
        assert_eq!(inv.raw, input);
    }

    #[test]
    fn forbidden_char_error_text_matches_spec() {
        // D-2 prescribes the exact wording.
        let err =
            ParsedInvocation::parse("github-repo:repo=foo/bar:extra").expect_err("should reject");
        let rendered = err.to_string();
        assert_eq!(
            rendered,
            "preset 'github-repo': param 'repo=foo/bar:extra' contains forbidden character ':' in value; preset params must not contain , : or ="
        );
    }

    #[test]
    fn malformed_param_error_suggests_key_value_form() {
        // A segment without '=' on a parameterized invocation should hint
        // at the correct invocation syntax.
        let err = ParsedInvocation::parse("github-repo:not-a-kv-pair").expect_err("should reject");
        let rendered = err.to_string();
        assert!(
            rendered.contains("github-repo:key=value"),
            "error should suggest the correct form; got: {rendered}"
        );
    }
}
