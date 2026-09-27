#![cfg(unix)]
#![expect(
    clippy::expect_used,
    reason = "integration tests intentionally fail hard on unexpected command output"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate must live under repo root")
        .to_owned()
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write mock executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("make mock executable runnable");
}

/// A service mock: records its start and its SIGTERM. With
/// `GM_TEST_<NAME>_EXIT` set it exits with that status once the other
/// services are up; otherwise it runs until terminated.
fn service(name: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
sleeper=""
trap 'touch "${{GM_TEST_MARKERS}}/{name}-term"; [[ -n "$sleeper" ]] && kill "$sleeper"; exit 0' TERM
touch "${{GM_TEST_MARKERS}}/{name}"
exit_var="GM_TEST_{upper}_EXIT"
if [[ -n "${{!exit_var:-}}" ]]; then
  # Exit only once every service is up, so the container stops each of them.
  for peer in gm-miner-attestd envoy; do
    for _ in $(seq 200); do
      [[ -e "${{GM_TEST_MARKERS}}/${{peer}}" ]] && break
      sleep 0.05
    done
  done
  exit "${{!exit_var}}"
fi
sleep 30 </dev/null >/dev/null 2>&1 &
sleeper=$!
wait
"#,
        upper = name.to_ascii_uppercase().replace('-', "_"),
    )
}

struct Runtime {
    markers: PathBuf,
    command: Command,
}

fn runtime(keys: &[(&str, &str)], exits: &[(&str, u8)]) -> Runtime {
    let root = tempfile::tempdir().expect("temp runtime").keep();
    let bin = root.join("bin");
    let markers = root.join("markers");
    fs::create_dir_all(&bin).expect("create mock bin");
    fs::create_dir_all(&markers).expect("create marker dir");
    executable(&bin.join("gm-miner-ratls"), "#!/usr/bin/env bash\nexit 0\n");
    for name in [
        "gm-miner-attestd",
        "gm-chutes-verify-proxy",
        "gm-kubetee-verify-proxy",
        "envoy",
    ] {
        executable(&bin.join(name), &service(name));
    }
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("image/start.sh"))
        .env_clear()
        .env("PATH", format!("{}:/bin:/usr/bin", bin.display()))
        .env("GM_TEST_MARKERS", &markers)
        .env("GM_ENVOY_TEMPLATE_DIR", repo_root().join("image/envoy"))
        .env("GM_RENDERED_CONFIG", root.join("envoy.yaml"))
        .env("GMCLI_BIN", env!("CARGO_BIN_EXE_gmcli"))
        .env("GM_NETWORK", "testnet")
        .envs(keys.iter().copied());
    for (name, status) in exits {
        command.env(
            format!(
                "GM_TEST_{}_EXIT",
                name.to_ascii_uppercase().replace('-', "_")
            ),
            status.to_string(),
        );
    }
    Runtime { markers, command }
}

fn run(runtime: &mut Runtime) -> Output {
    runtime.command.output().expect("run start.sh")
}

fn wait_for(markers: &Path, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !markers.join(name).exists() {
        assert!(Instant::now() < deadline, "{name} never started");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn terminate(child: Child) -> Output {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(status.success());
    child.wait_with_output().expect("collect start.sh output")
}

/// Each key-gated verification proxy: its key, its binary and the name
/// start.sh gives it when it exits.
const PROXIES: [(&str, &str, &str); 2] = [
    ("CHUTES_API_KEY", "gm-chutes-verify-proxy", "Chutes"),
    ("KUBETEE_API_KEY", "gm-kubetee-verify-proxy", "KubeTEE"),
];

#[test]
fn a_key_starts_its_verification_proxy_under_supervision() {
    for (key, proxy, _) in PROXIES {
        let mut runtime = runtime(&[(key, "provider-key")], &[("envoy", 17)]);
        let output = run(&mut runtime);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(17), "{stderr}");
        assert!(runtime.markers.join(proxy).exists(), "{proxy} not started");
        assert!(
            runtime.markers.join(format!("{proxy}-term")).exists(),
            "{proxy} was not stopped with the container"
        );
    }
}

#[test]
fn without_its_key_no_proxy_is_started() {
    let mut runtime = runtime(&[("OPENAI_API_KEY", "openai-key")], &[("envoy", 17)]);
    let output = run(&mut runtime);
    assert_eq!(output.status.code(), Some(17));
    assert!(runtime.markers.join("envoy").exists());
    for (_, proxy, _) in PROXIES {
        assert!(!runtime.markers.join(proxy).exists(), "{proxy} started");
    }
}

#[test]
fn a_proxy_exit_brings_down_the_container_and_names_it() {
    for (key, proxy, label) in PROXIES {
        let mut runtime = runtime(&[(key, "provider-key")], &[(proxy, 23)]);
        let output = run(&mut runtime);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(23), "{stderr}");
        assert!(
            stderr.contains(&format!("{label} verification proxy exited (status 23)")),
            "{stderr}"
        );
        assert!(runtime.markers.join("envoy-term").exists());
        assert!(runtime.markers.join("gm-miner-attestd-term").exists());
    }
}

#[test]
fn sigterm_stops_every_proxy_with_every_other_service() {
    let mut runtime = runtime(
        &[
            ("CHUTES_API_KEY", "chutes-key"),
            ("KUBETEE_API_KEY", "kubetee-key"),
        ],
        &[],
    );
    let child = runtime
        .command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start start.sh");
    let services = [
        "gm-chutes-verify-proxy",
        "gm-kubetee-verify-proxy",
        "envoy",
        "gm-miner-attestd",
    ];
    // A mock records its start only once its TERM trap is installed.
    for service in services {
        wait_for(&runtime.markers, service);
    }
    let output = terminate(child);
    assert_eq!(output.status.code(), Some(1));
    for service in services {
        assert!(
            runtime.markers.join(format!("{service}-term")).exists(),
            "{service} was not stopped"
        );
    }
}
