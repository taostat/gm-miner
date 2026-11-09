//! `gmcli worker remove` end to end: the real binary against a mock registry
//! and a fake `phala` executable, so the CVM delete runs through the same
//! subprocess, argument and API-key wiring as production.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::{os::unix::fs::PermissionsExt as _, process::Command};

use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const HOTKEY: &str = "5HK";
const WORKER_ID: &str = "01JWORKER";
const APP_ID: &str = "app_abc123";
const PROVISIONAL_NAME: &str = "gm-miner-3";
const PROVISIONAL_APP_ID: &str = "app_prov456";

/// The fake `phala`: answers the `--version` presence probe, and `whoami`
/// as logged in only when `$TEST_PHALA_LOGIN=1`. Every `cvms` call is logged
/// as `<args> key=<scoped key>` and answered as `$TEST_PHALA_DELETE` says,
/// with the `--json` envelopes `phala` 1.1.19 prints.
const FAKE_PHALA: &str = "#!/bin/sh\n\
    case \"$1\" in\n\
      --version) printf '1.1.19\\n'; exit 0;;\n\
      whoami) [ \"$TEST_PHALA_LOGIN\" = 1 ]; exit $?;;\n\
    esac\n\
    printf '%s key=%s\\n' \"$*\" \"$PHALA_CLOUD_API_KEY\" >> \"$TEST_CALLS\"\n\
    case \"$TEST_PHALA_DELETE\" in\n\
      ok) printf '{\"success\":true,\"data\":{\"deleted\":true,\"cvm\":\"x\"}}\\n';;\n\
      gone) printf '{\"success\":false,\"error\":\"The requested CVM was not found\"}\\n'\n\
        exit 1;;\n\
      *) printf '{\"success\":false,\"error\":\"Insufficient permissions\"}\\n'; exit 1;;\n\
    esac\n";

/// How the mock registry answers the worker DELETE.
#[derive(Clone, Copy)]
enum Registry {
    Deletes,
    Refuses,
    Unused,
}

struct Fixture {
    dir: tempfile::TempDir,
    _server: MockServer,
}

fn worker(worker_id: &str, app_id: &str, app_name: &str) -> Value {
    json!({
        "worker_id": worker_id,
        "app_id": app_id,
        "app_name": app_name,
        "node_secret": "test-node-secret-1234",
    })
}

impl Fixture {
    async fn new(registry: Registry) -> Self {
        let dir = tempfile::tempdir().expect("isolated config and executables");
        let server = MockServer::start().await;
        let config = json!({
            "active_network": "testnet",
            "networks": {"testnet": {
                "api_url": server.uri(),
                "tokens": {"access_token": "test-token"},
                "workers": [
                    worker(WORKER_ID, APP_ID, "gm-miner-2"),
                    worker("", PROVISIONAL_APP_ID, PROVISIONAL_NAME),
                    worker("", "", "gm-miner-4"),
                ],
            }},
            "phala_api_key": "saved-key",
        });
        std::fs::write(dir.path().join("config.json"), config.to_string()).expect("write config");
        std::fs::write(dir.path().join("calls"), "").expect("initialize phala call log");
        let phala = dir.path().join("phala");
        std::fs::write(&phala, FAKE_PHALA).expect("write fake phala");
        std::fs::set_permissions(&phala, std::fs::Permissions::from_mode(0o755))
            .expect("make fake phala executable");

        Mock::given(method("GET"))
            .and(path("/miners/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hotkey": HOTKEY, "status": "active", "products": [],
            })))
            .mount(&server)
            .await;
        let (status, expected_calls) = match registry {
            Registry::Deletes => (204, 1..=1),
            Registry::Refuses => (500, 1..=1),
            Registry::Unused => (204, 0..=0),
        };
        Mock::given(method("DELETE"))
            .and(path(format!("/miners/{HOTKEY}/workers/{WORKER_ID}")))
            .respond_with(ResponseTemplate::new(status).set_body_string("registry says no"))
            .expect(expected_calls)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/miners/{HOTKEY}/workers/01JUNTRACKED")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Self {
            dir,
            _server: server,
        }
    }

    fn run(&self, args: &[&str], phala_delete: &str) -> std::process::Output {
        self.command(args, phala_delete)
            .output()
            .expect("run gmcli with isolated config and a fake phala")
    }

    fn command(&self, args: &[&str], phala_delete: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gmcli"));
        command
            .args(["worker", "remove"])
            .args(args)
            .current_dir(self.dir.path())
            .env_clear()
            .env("PATH", self.dir.path())
            .env("GMCLI_CONFIG_DIR", self.dir.path())
            .env("TEST_CALLS", self.dir.path().join("calls"))
            .env("TEST_PHALA_DELETE", phala_delete);
        command
    }

    fn without_phala_cli(&self) {
        std::fs::remove_file(self.dir.path().join("phala")).expect("remove fake phala");
    }

    fn without_saved_phala_key(&self) {
        let file = self.dir.path().join("config.json");
        let raw = std::fs::read_to_string(&file).expect("config");
        let mut config: Value = serde_json::from_str(&raw).expect("config is JSON");
        config
            .as_object_mut()
            .expect("config object")
            .remove("phala_api_key");
        std::fs::write(file, config.to_string()).expect("rewrite config");
    }

    fn phala_calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("calls")).expect("read phala calls")
    }

    fn tracked_app_ids(&self) -> Vec<String> {
        let raw = std::fs::read_to_string(self.dir.path().join("config.json")).expect("config");
        let config: Value = serde_json::from_str(&raw).expect("config is JSON");
        config["networks"]["testnet"]["workers"]
            .as_array()
            .expect("workers array")
            .iter()
            .map(|w| w["app_id"].as_str().expect("app_id").to_owned())
            .collect()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn removal_deletes_the_cvm_with_the_saved_key() {
    let fixture = Fixture::new(Registry::Deletes).await;
    let out = fixture.run(&[WORKER_ID], "ok");
    let stdout = text(&out.stdout);

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(
        fixture.phala_calls(),
        format!("cvms delete {APP_ID} --force --json key=saved-key\n")
    );
    assert!(
        stdout.contains(&format!("Deleted Phala CVM {APP_ID}.")),
        "{stdout}"
    );
    assert!(!fixture.tracked_app_ids().contains(&APP_ID.to_owned()));
}

#[tokio::test]
async fn the_phala_key_flag_overrides_the_saved_key() {
    let fixture = Fixture::new(Registry::Deletes).await;
    let out = fixture.run(&[WORKER_ID, "--phala-api-key", "flag-key"], "ok");

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(
        fixture.phala_calls(),
        format!("cvms delete {APP_ID} --force --json key=flag-key\n")
    );
}

#[tokio::test]
async fn keep_cvm_deregisters_without_touching_the_cvm() {
    let fixture = Fixture::new(Registry::Deletes).await;
    let out = fixture.run(&[WORKER_ID, "--keep-cvm"], "fail");
    let stdout = text(&out.stdout);

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(fixture.phala_calls(), "", "--keep-cvm must not run phala");
    assert!(
        stdout.contains(&format!("phala cvms delete {APP_ID}")),
        "{stdout}"
    );
    assert!(!fixture.tracked_app_ids().contains(&APP_ID.to_owned()));
}

#[tokio::test]
async fn a_failed_cvm_delete_after_deregistration_exits_non_zero_with_the_fallback() {
    let fixture = Fixture::new(Registry::Deletes).await;
    let out = fixture.run(&[WORKER_ID], "fail");
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);

    assert!(
        !out.status.success(),
        "a CVM left running must fail the run"
    );
    assert!(
        stdout.contains("deregistered from the registry")
            && stdout.contains("Dropped its local worker record."),
        "must say what succeeded: {stdout}"
    );
    assert!(
        stderr.contains(&format!("worker {WORKER_ID} is deregistered"))
            && stderr.contains(&format!("Phala CVM {APP_ID} was NOT deleted"))
            && stderr.contains("Insufficient permissions"),
        "must say what succeeded, what did not, and Phala's reason: {stderr}"
    );
    assert!(
        stderr.contains(&format!("phala cvms delete {APP_ID}")),
        "{stderr}"
    );
    assert!(
        !fixture.tracked_app_ids().contains(&APP_ID.to_owned()),
        "the worker is deregistered, so its local record is dropped"
    );
}

#[tokio::test]
async fn a_registry_failure_leaves_the_cvm_and_record_alone() {
    let fixture = Fixture::new(Registry::Refuses).await;
    let out = fixture.run(&[WORKER_ID], "ok");
    let stderr = text(&out.stderr);

    assert!(!out.status.success());
    assert!(stderr.contains("worker remove failed (500"), "{stderr}");
    assert_eq!(
        fixture.phala_calls(),
        "",
        "no CVM delete before deregistration"
    );
    assert!(fixture.tracked_app_ids().contains(&APP_ID.to_owned()));
}

#[tokio::test]
async fn an_untracked_app_id_exits_non_zero_with_the_generic_fallback() {
    let fixture = Fixture::new(Registry::Unused).await;
    let out = fixture.run(&["01JUNTRACKED"], "ok");
    let stderr = text(&out.stderr);

    assert!(!out.status.success(), "an unknown CVM must fail the run");
    assert!(
        stderr.contains("worker 01JUNTRACKED is deregistered")
            && stderr.contains("not tracked locally")
            && stderr.contains("phala cvms delete <app_id>"),
        "{stderr}"
    );
    assert_eq!(
        fixture.phala_calls(),
        "",
        "nothing to delete without an app_id"
    );
}

#[tokio::test]
async fn an_already_deleted_cvm_is_success() {
    let fixture = Fixture::new(Registry::Deletes).await;
    let out = fixture.run(&[WORKER_ID], "gone");
    let stdout = text(&out.stdout);

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(
        stdout.contains(&format!("Phala CVM {APP_ID} is already gone")),
        "{stdout}"
    );
}

#[tokio::test]
async fn a_provisional_record_deletes_its_cvm_without_a_registry_call() {
    let fixture = Fixture::new(Registry::Unused).await;
    let out = fixture.run(&[PROVISIONAL_NAME], "ok");
    let stdout = text(&out.stdout);

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(
        stdout.contains(&format!("record for '{PROVISIONAL_NAME}'")),
        "{stdout}"
    );
    assert_eq!(
        fixture.phala_calls(),
        format!("cvms delete {PROVISIONAL_APP_ID} --force --json key=saved-key\n")
    );
    assert!(!fixture
        .tracked_app_ids()
        .contains(&PROVISIONAL_APP_ID.to_owned()));
}

#[tokio::test]
async fn a_provisional_record_keeps_its_cvm_with_keep_cvm() {
    let fixture = Fixture::new(Registry::Unused).await;
    let out = fixture.run(&[PROVISIONAL_NAME, "--keep-cvm"], "fail");
    let stdout = text(&out.stdout);

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(fixture.phala_calls(), "");
    assert!(
        stdout.contains(&format!("phala cvms delete {PROVISIONAL_APP_ID}")),
        "{stdout}"
    );
    assert!(!fixture
        .tracked_app_ids()
        .contains(&PROVISIONAL_APP_ID.to_owned()));
}

#[tokio::test]
async fn a_provisional_record_without_an_app_id_names_the_cvm_to_delete() {
    let fixture = Fixture::new(Registry::Unused).await;
    let out = fixture.run(&["gm-miner-4"], "ok");
    let stderr = text(&out.stderr);

    assert!(
        !out.status.success(),
        "a possibly-launched CVM must fail the run"
    );
    assert!(
        stderr.contains("record for 'gm-miner-4' is dropped")
            && stderr.contains("phala cvms delete gm-miner-4"),
        "{stderr}"
    );
    assert_eq!(
        fixture.phala_calls(),
        "",
        "nothing to delete without an app_id"
    );
}

/// The preflight's refusal: nothing changed, the reason, and the way out.
fn assert_refused_before_anything_changed(fixture: &Fixture, out: &std::process::Output) {
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("Nothing was changed") && stderr.contains("--keep-cvm"),
        "{stderr}"
    );
    assert_eq!(fixture.phala_calls(), "", "no CVM delete may run");
    let tracked = fixture.tracked_app_ids();
    assert!(tracked.contains(&APP_ID.to_owned()), "record must be kept");
    assert!(
        tracked.contains(&PROVISIONAL_APP_ID.to_owned()),
        "record must be kept"
    );
}

#[tokio::test]
async fn a_missing_phala_cli_fails_before_deregistering() {
    let fixture = Fixture::new(Registry::Unused).await;
    fixture.without_phala_cli();
    for id in [WORKER_ID, PROVISIONAL_NAME] {
        let out = fixture.run(&[id], "ok");
        assert_refused_before_anything_changed(&fixture, &out);
        assert!(
            text(&out.stderr).contains("not found on PATH"),
            "{}",
            text(&out.stderr)
        );
    }
}

#[tokio::test]
async fn a_missing_phala_credential_fails_before_deregistering() {
    let fixture = Fixture::new(Registry::Unused).await;
    fixture.without_saved_phala_key();
    for id in [WORKER_ID, PROVISIONAL_NAME] {
        let out = fixture.run(&[id], "ok");
        assert_refused_before_anything_changed(&fixture, &out);
        assert!(
            text(&out.stderr).contains("no Phala credential found"),
            "{}",
            text(&out.stderr)
        );
    }
}

#[tokio::test]
async fn a_phala_cli_login_is_a_credential() {
    let fixture = Fixture::new(Registry::Deletes).await;
    fixture.without_saved_phala_key();
    let out = fixture
        .command(&[WORKER_ID], "ok")
        .env("TEST_PHALA_LOGIN", "1")
        .output()
        .expect("run gmcli");

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert_eq!(
        fixture.phala_calls(),
        format!("cvms delete {APP_ID} --force --json key=\n")
    );
}

#[tokio::test]
async fn keep_cvm_needs_neither_the_phala_cli_nor_a_key() {
    let fixture = Fixture::new(Registry::Deletes).await;
    fixture.without_phala_cli();
    fixture.without_saved_phala_key();
    let out = fixture.run(&[WORKER_ID, "--keep-cvm"], "ok");

    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(!fixture.tracked_app_ids().contains(&APP_ID.to_owned()));
}
