//! Docker image-lifecycle and daemon-probe argv builders.

/// `docker image inspect <tag>`.
pub fn image_inspect_argv(tag: &str) -> Vec<String> {
    vec!["image".to_string(), "inspect".to_string(), tag.to_string()]
}

/// `docker load` — the tarball arrives on stdin.
///
/// The tarball is hundreds of megabytes, so it is never carried in the op
/// payload: the side that runs `docker load` opens the file and streams it
/// into the child's stdin. Which file that is comes from the typed op, not
/// from an argument on this command line.
pub fn image_load_argv() -> Vec<String> {
    vec!["load".to_string()]
}

/// `docker info` — the daemon-reachability probe.
pub fn daemon_info_argv() -> Vec<String> {
    vec!["info".to_string()]
}

/// The images the daemon stages into a VM as a tarball.
///
/// Enumerated rather than carried as a path so a compromised daemon cannot
/// ask the agent to read an arbitrary file: the side that runs `docker load`
/// resolves the variant to a filename in a directory it already owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedImage {
    /// The gateway container image.
    Gateway,
    /// The lite-mode sandbox container image.
    Lite,
}

impl StagedImage {
    /// The tarball's filename within the staging directory.
    pub fn tarball_filename(self) -> &'static str {
        match self {
            StagedImage::Gateway => "gateway-image.tar",
            StagedImage::Lite => "lite-image.tar",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_inspect_argv_is_the_three_token_subcommand() {
        assert_eq!(
            image_inspect_argv("sandbox-gateway:0.1.10"),
            vec!["image", "inspect", "sandbox-gateway:0.1.10"]
        );
    }

    #[test]
    fn load_argv_names_no_file_because_the_tarball_arrives_on_stdin() {
        let argv = image_load_argv();
        assert_eq!(argv, vec!["load"]);
        assert!(
            !argv.iter().any(|a| a == "-i" || a == "--input"),
            "a file argument here would make the caller's path the target: {argv:?}"
        );
    }

    #[test]
    fn info_argv_is_a_bare_subcommand() {
        assert_eq!(daemon_info_argv(), vec!["info"]);
    }

    #[test]
    fn staged_images_have_distinct_tarball_names() {
        assert_ne!(
            StagedImage::Gateway.tarball_filename(),
            StagedImage::Lite.tarball_filename()
        );
    }
}
