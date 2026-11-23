//! Exercise the real command routes with a local registry and fake executables.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::{os::unix::fs::PermissionsExt as _, process::Command};

use gm_miner_cli::{
    compose_hash::{compute_compose_hash, PINNED_OS_IMAGE_HASH},
    network::Network,
    terms::CURRENT_TERMS_VERSION,
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[derive(Clone, Copy, Debug)]
enum Route {
    Deploy,
    Add,
    Init,
    RetryPrimary,
    RetrySecondary,
}

const ROUTES: [Route; 5] = [
    Route::Deploy,
    Route::Add,
    Route::Init,
    Route::RetryPrimary,
    Route::RetrySecondary,
];

fn root(id: &str, default: bool, expiry: Option<&str>) -> Value {
    json!({
        "ca_pubkey": format!("ca-{id}"),
        "kms_contract_id": id,
        "is_default": default,
        "allowed_until": expiry
    })
}

fn allowed_roots() -> Value {
    json!({"roots": [
        root("other-allowed", false, None),
        root("registry-default", true, None),
        root("expiring", false, Some("2099-01-01T00:00:00Z")),
    ]})
}

fn image_versions(image_ref: &str) -> Value {
    let default_compose = compute_compose_hash(image_ref, Network::Testnet, "ca-registry-default")
        .expect("default-root compose hash");
    let other_compose = compute_compose_hash(image_ref, Network::Testnet, "ca-other-allowed")
        .expect("additional-root compose hash");
    json!({"versions": [
        {
            "git_tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "compose_hash": default_compose,
            "os_image_hash": PINNED_OS_IMAGE_HASH,
            "image_ref": image_ref,
            "status": "supported",
            "created_at": "2026-01-02T00:00:00Z",
            "features": ["upstream-key-slots", "bedrock-mantle-model-bindings-v1"],
        },
        {
            "git_tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "compose_hash": other_compose,
            "os_image_hash": PINNED_OS_IMAGE_HASH,
            "image_ref": image_ref,
            "status": "supported",
            "created_at": "2026-01-01T00:00:00Z",
            "features": ["upstream-model-hop"],
        }
    ]})
}

struct Fixture {
    dir: tempfile::TempDir,
    server: MockServer,
    route: Route,
}

impl Fixture {
    async fn new(route: Route, response: ResponseTemplate) -> Self {
        let dir = tempfile::tempdir().expect("isolated config, caller and executables");
        let server = MockServer::start().await;
        let worker = |name, registered, secondary| {
            json!({
                "app_name": name,
                "worker_id": if registered { "worker-1" } else { "" },
                "app_id": if registered { "app-1" } else { "" },
                "node_secret": "test-node-secret-1234",
                "backends": {},
                "provisional_secondary": secondary,
            })
        };
        let workers = match route {
            Route::Deploy | Route::Init => vec![],
            Route::Add => vec![worker("primary", true, false)],
            Route::RetryPrimary => vec![worker("gm-miner-1", false, false)],
            Route::RetrySecondary => vec![
                worker("primary", true, false),
                worker("gm-miner-1", false, true),
            ],
        };
        let config = json!({
            "active_network": "testnet",
            "networks": {"testnet": {
                "api_url": server.uri(),
                "tokens": {"access_token": "test-token"},
                "workers": workers,
            }},
            "provider_keys": {"anthropic": "test-key"},
            "accepted_terms": {"version": CURRENT_TERMS_VERSION, "timestamp": "2026-01-01T00:00:00Z"},
        });
        std::fs::write(dir.path().join("config.json"), config.to_string()).expect("write config");
        std::fs::write(dir.path().join("calls"), "").expect("initialize subprocess call log");
        std::fs::write(dir.path().join("phala.toml"), "id = 'existing-cvm'\n")
            .expect("write ambient caller project");
        for (name, script) in [
            (
                "phala",
                "#!/bin/sh\n\
                printf '%s\\n' \"$*\" >> \"$TEST_CALLS\"\n\
                [ ! -f phala.toml ] || exit 41\n\
                if [ \"$TEST_REQUIRE_CREDENTIALS\" = 1 ]; then\n\
                  [ -f \"$PHALA_CLOUD_DIR/credentials.json\" ] || exit 42\n\
                fi\n\
                case \"$1\" in\n\
                  --version) printf '1.2.1\\n';;\n\
                  whoami) exit 0;;\n\
                  cvms)\n\
                    case \"$2\" in\n\
                      list) printf '{\"items\":[],\"page\":1,\"totalPages\":0}\\n';;\n\
                      get) printf '{\"app_id\":\"app-created\",\"compose_hash\":\"%s\",\"os\":{\"os_image_hash\":\"%s\"},\"endpoints\":[{\"app\":\"%s\"}]}\\n' \"$TEST_COMPOSE_HASH\" \"$TEST_OS_IMAGE_HASH\" \"$TEST_ENDPOINT\";;\n\
                      *) exit 58;;\n\
                    esac;;\n\
                  deploy) printf '%s\\n' \"$@\" > \"$TEST_DEPLOY_ARGS\"; exit \"${TEST_DEPLOY_EXIT:-57}\";;\n\
                  *) exit 58;;\n\
                esac\n",
            ),
            (
                "docker",
                "#!/bin/sh\nprintf 'docker %s\\n' \"$*\" >> \"$TEST_CALLS\"\nexit 58\n",
            ),
            (
                "git",
                "#!/bin/sh\nprintf 'git %s\\n' \"$*\" >> \"$TEST_CALLS\"\nexit 58\n",
            ),
        ] {
            let executable = dir.path().join(name);
            std::fs::write(&executable, script).expect("write stub executable");
            std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755))
                .expect("make stub executable");
        }
        Mock::given(method("GET"))
            .and(path("/kms-roots"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/miners/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hotkey": "5HK", "status": "active", "products": [],
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/miners/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "worker_id": "worker-created"
            })))
            .mount(&server)
            .await;
        // Docker Hub refs bypass the anonymous manifest probe. No external
        // network or real image/CVM commands are needed to reach creation.
        let image = format!("docker.io/library/test@sha256:{}", "a".repeat(64));
        Mock::given(method("GET"))
            .and(path("/image-versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(image_versions(&image)))
            .mount(&server)
            .await;
        Self { dir, server, route }
    }

    fn command(&self, requested: Option<&str>, build: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gmcli"));
        match self.route {
            Route::Add | Route::RetrySecondary => command.args(["worker", "add"]),
            Route::Init => command.args(["init", "--yes"]),
            Route::Deploy | Route::RetryPrimary => command.arg("deploy"),
        };
        if let Some(id) = requested {
            command.args(["--kms-contract-id", id]);
        }
        if build && !matches!(self.route, Route::Init) {
            command.args(["--image-repo", "docker.io/library/test"]);
        }
        command
            .current_dir(self.dir.path())
            .env_clear()
            .env("PATH", self.dir.path())
            .env("GMCLI_CONFIG_DIR", self.dir.path())
            .env("TEST_CALLS", self.dir.path().join("calls"))
            .env("TEST_DEPLOY_ARGS", self.dir.path().join("deploy-args"))
            .env("HTTP_PROXY", self.server.uri())
            .env("http_proxy", self.server.uri())
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
        command
    }

    fn run(&self, requested: Option<&str>, build: bool) -> std::process::Output {
        self.command(requested, build)
            .output()
            .expect("run gmcli with isolated config and fake commands")
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("calls")).expect("read subprocess calls")
    }
}

#[tokio::test]
async fn isolated_phala_calls_keep_relative_credential_directories() {
    let fixture = Fixture::new(
        Route::Deploy,
        ResponseTemplate::new(200).set_body_json(allowed_roots()),
    )
    .await;
    let credentials = fixture.dir.path().join("credentials");
    std::fs::create_dir(&credentials).expect("create credential directory");
    std::fs::write(credentials.join("credentials.json"), "{}").expect("write session marker");

    let output = fixture
        .command(None, false)
        .env("PHALA_CLOUD_DIR", "credentials")
        .env("TEST_REQUIRE_CREDENTIALS", "1")
        .output()
        .expect("run deploy with a relative Phala credential directory");

    // The fake CLI checks credentials on every call and stops at creation.
    // Reaching deploy proves the version, login and name checks all used the
    // caller's credentials despite running outside its phala.toml directory.
    assert!(
        fixture.dir.path().join("deploy-args").exists(),
        "Phala lost the caller's credential directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn isolated_phala_calls_keep_relative_executable_search_paths() {
    // Both a relative component and an empty PATH component mean the
    // caller's directory; neither may be rebound to the isolated directory.
    for search_path in [".", ""] {
        let fixture = Fixture::new(
            Route::Deploy,
            ResponseTemplate::new(200).set_body_json(allowed_roots()),
        )
        .await;
        let output = fixture
            .command(None, false)
            .env("PATH", search_path)
            .output()
            .expect("run deploy with a relative executable search path");

        assert!(
            fixture.dir.path().join("deploy-args").exists(),
            "Phala was lost from PATH {search_path:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn kms_rejection_stops_real_creation_routes_before_image_build() {
    for route in ROUTES {
        // init has no KMS flag; its default selection must still fail closed.
        let overrides: &[Option<&str>] = if matches!(route, Route::Init) {
            &[None]
        } else {
            &[None, Some("unknown"), Some("expiring")]
        };
        for requested in overrides {
            let body = if requested.is_some() {
                allowed_roots()
            } else {
                json!({"roots": [root("other-allowed", false, None)]})
            };
            let fixture = Fixture::new(route, ResponseTemplate::new(200).set_body_json(body)).await;
            let output = fixture.run(*requested, true);
            assert!(!output.status.success(), "{route:?} accepted {requested:?}");
            assert_eq!(
                fixture.calls(),
                "",
                "{route:?}: rejected KMS data must stop before the Phala version check or key preflight"
            );
            let requests = fixture.server.received_requests().await.expect("requests");
            assert!(requests
                .iter()
                .all(|r| matches!(r.url.path(), "/kms-roots" | "/miners/me")));
            assert!(!fixture.dir.path().join("dist").exists());
        }
    }
}

#[tokio::test]
async fn missing_kms_endpoint_and_expiry_stop_real_creation_routes() {
    for route in ROUTES {
        for response in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(200).set_body_json(json!({"roots": [{
                "kms_contract_id": "registry-default", "is_default": true,
            }]})),
        ] {
            let fixture = Fixture::new(route, response).await;
            let output = fixture.run(None, true);
            assert!(
                !output.status.success(),
                "{route:?} must reject invalid KMS data"
            );
            assert_eq!(
                fixture.calls(),
                "",
                "{route:?}: rejected KMS data must stop before the Phala version check or key preflight"
            );
            let requests = fixture.server.received_requests().await.expect("requests");
            assert!(!requests.iter().any(|r| r.url.path() == "/image-versions"));
        }
    }
}

#[tokio::test]
async fn registry_selection_reaches_phala_on_every_creation_route() {
    for route in ROUTES {
        let overrides: &[Option<&str>] = if matches!(route, Route::Init) {
            &[None]
        } else {
            &[None, Some("other-allowed")]
        };
        for requested in overrides {
            let fixture = Fixture::new(
                route,
                ResponseTemplate::new(200).set_body_json(allowed_roots()),
            )
            .await;
            let output = fixture.run(*requested, false);
            let captured = std::fs::read_to_string(fixture.dir.path().join("deploy-args"));
            assert!(
                captured.is_ok(),
                "{route:?}: {captured:?}; {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let captured = captured.expect("Phala creation arguments");
            let args: Vec<_> = captured.lines().collect();
            assert_eq!(args.iter().filter(|&&arg| arg == "--kms").count(), 1);
            assert_eq!(
                args.iter()
                    .filter(|&&arg| arg == "--kms-contract-id")
                    .count(),
                1
            );
            assert!(args.windows(2).any(|pair| pair == ["--kms", "phala"]));
            assert!(args.contains(&"--ephemeral-data-disk"));
            assert!(
                args.windows(2)
                    .any(|pair| pair
                        == ["--kms-contract-id", requested.unwrap_or("registry-default")])
            );
            assert!(!args.contains(&"--cvm-id"));
            for flag in ["--compose", "--env", "--pre-launch-script"] {
                let value = args
                    .windows(2)
                    .find(|pair| pair[0] == flag)
                    .expect("staged file argument")[1];
                let path = std::path::Path::new(value);
                assert!(path.is_absolute() && path.is_file(), "{flag}: {value}");
            }
            assert!(!fixture
                .calls()
                .lines()
                .any(|call| call.starts_with("docker ")));
            let requests = fixture.server.received_requests().await.expect("requests");
            let kms = requests
                .iter()
                .position(|r| r.url.path() == "/kms-roots")
                .expect("KMS lookup");
            let image = requests
                .iter()
                .position(|r| r.url.path() == "/image-versions")
                .expect("image lookup");
            assert!(kms < image);
            assert!(!requests[kms].headers.contains_key("authorization"));
        }
    }
}

#[tokio::test]
async fn selected_root_hashes_allow_creation_and_registration() {
    let fixture = Fixture::new(
        Route::Deploy,
        ResponseTemplate::new(200).set_body_json(allowed_roots()),
    )
    .await;
    let image_ref = format!("docker.io/library/test@sha256:{}", "a".repeat(64));
    let selected_compose = compute_compose_hash(&image_ref, Network::Testnet, "ca-other-allowed")
        .expect("selected-root compose hash");
    let output = fixture
        .command(Some("other-allowed"), false)
        .env("TEST_DEPLOY_EXIT", "0")
        .env("TEST_COMPOSE_HASH", selected_compose.clone())
        .env("TEST_OS_IMAGE_HASH", PINNED_OS_IMAGE_HASH)
        .env("TEST_ENDPOINT", "http://app-8080.invalid")
        .output()
        .expect("run selected-root deploy");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.server.received_requests().await.expect("requests");
    let registration = requests
        .iter()
        .find(|request| request.url.path() == "/miners/register")
        .expect("verified CVM is registered");
    let body: Value = serde_json::from_slice(&registration.body).expect("registration body");
    assert_eq!(
        body["compose_hash"].as_str(),
        Some(selected_compose.as_str())
    );
    assert_eq!(body["os_image_hash"].as_str(), Some(PINNED_OS_IMAGE_HASH));
    assert!(body.get("provider_slots").is_none());
}

#[tokio::test]
async fn another_roots_approved_hashes_are_rejected_after_creation() {
    let fixture = Fixture::new(
        Route::Deploy,
        ResponseTemplate::new(200).set_body_json(allowed_roots()),
    )
    .await;
    let image_ref = format!("docker.io/library/test@sha256:{}", "a".repeat(64));
    let other_compose = compute_compose_hash(&image_ref, Network::Testnet, "ca-registry-default")
        .expect("other-root compose hash");
    let selected_compose = compute_compose_hash(&image_ref, Network::Testnet, "ca-other-allowed")
        .expect("selected-root compose hash");
    assert_ne!(other_compose, selected_compose);
    let versions = image_versions(&image_ref);
    assert_eq!(
        versions["versions"][0]["compose_hash"].as_str(),
        Some(other_compose.as_str())
    );
    let output = fixture
        .command(Some("other-allowed"), false)
        .env("TEST_DEPLOY_EXIT", "0")
        .env("TEST_COMPOSE_HASH", other_compose)
        .env("TEST_OS_IMAGE_HASH", PINNED_OS_IMAGE_HASH)
        .env("TEST_ENDPOINT", "http://app-8080.invalid")
        .output()
        .expect("run selected-root deploy with another root's measurements");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("HASH MISMATCH"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fixture.calls();
    assert!(calls
        .lines()
        .any(|call| call.split_whitespace().next() == Some("deploy")));
    assert!(calls.lines().any(|call| call.starts_with("cvms get ")));
    let requests = fixture.server.received_requests().await.expect("requests");
    assert!(requests
        .iter()
        .any(|request| request.url.path() == "/kms-roots"));
    assert!(!requests
        .iter()
        .any(|request| request.url.path() == "/miners/register"));
}
