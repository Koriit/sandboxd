//! Docker volume-lifecycle argv builders.

/// `docker volume create [--label sandbox.session_id=…]
/// [--label sandboxd.owner=…] <name>`.
pub fn volume_create_argv(
    name: &str,
    session_id: Option<&str>,
    owner_pool: Option<&str>,
) -> Vec<String> {
    let mut argv = vec!["volume".to_string(), "create".to_string()];
    if let Some(session_id) = session_id {
        argv.push("--label".to_string());
        argv.push(format!("sandbox.session_id={session_id}"));
    }
    if let Some(pool) = owner_pool {
        argv.push("--label".to_string());
        argv.push(format!("sandboxd.owner={pool}"));
    }
    argv.push(name.to_string());
    argv
}

/// `docker volume rm <name>`.
pub fn volume_remove_argv(name: &str) -> Vec<String> {
    vec!["volume".to_string(), "rm".to_string(), name.to_string()]
}

/// `docker volume ls --filter name=<prefix>
/// [--filter label=sandboxd.owner=<pool>] --format {{.Name}}`.
pub fn volume_list_argv(name_prefix: &str, owner_pool: Option<&str>) -> Vec<String> {
    let mut argv = vec![
        "volume".to_string(),
        "ls".to_string(),
        "--filter".to_string(),
        format!("name={name_prefix}"),
    ];
    if let Some(pool) = owner_pool {
        argv.push("--filter".to_string());
        argv.push(format!("label=sandboxd.owner={pool}"));
    }
    argv.push("--format".to_string());
    argv.push("{{.Name}}".to_string());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_argv_places_the_name_last_and_labels_before_it() {
        let argv = volume_create_argv("sandbox-home-abc", Some("abc"), Some("10.209.128.0/24"));
        assert_eq!(argv.last().map(String::as_str), Some("sandbox-home-abc"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--label" && w[1] == "sandbox.session_id=abc")
        );
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--label" && w[1] == "sandboxd.owner=10.209.128.0/24")
        );
    }

    #[test]
    fn create_argv_omits_labels_that_were_not_supplied() {
        assert_eq!(
            volume_create_argv("v", None, None),
            vec!["volume", "create", "v"]
        );
    }

    #[test]
    fn remove_argv_is_the_two_token_subcommand() {
        assert_eq!(volume_remove_argv("v"), vec!["volume", "rm", "v"]);
    }

    #[test]
    fn list_argv_adds_the_owner_filter_only_when_a_pool_is_given() {
        assert_eq!(
            volume_list_argv("sandbox-home-", None),
            vec![
                "volume",
                "ls",
                "--filter",
                "name=sandbox-home-",
                "--format",
                "{{.Name}}"
            ]
        );
        let argv = volume_list_argv("sandbox-home-", Some("10.209.128.0/24"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--filter" && w[1] == "label=sandboxd.owner=10.209.128.0/24")
        );
    }
}
