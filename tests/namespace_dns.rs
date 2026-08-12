use std::{
        path::PathBuf,
        process::{Command, ExitStatus},
};

fn run_namespace_collector_test(root: &PathBuf) -> std::io::Result<ExitStatus> {
        let script = root.join("scripts/namespace_lab.sh");

        if unsafe { libc::geteuid() == 0 } {
                Command::new(script)
                        .arg("collector-test")
                        .current_dir(root)
                        .status()
        } else {
                Command::new("sudo")
                        .arg(script)
                        .arg("collector-test")
                        .current_dir(root)
                        .status()
        }
}

/// End-to-end namespace test for DNS UDP/TCP forwarding and Flow attribution.
///
/// Run explicitly because it requires root, a prepared namespace topology,
/// TC eBPF support, nftables, and conntrack:
///
///     sudo make namespace-up
///     make namespace-dns-test
#[test]
#[ignore = "requires root and the prepared Linux namespace topology"]
fn namespace_dns_forwarding_and_flow_attribution() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let status = run_namespace_collector_test(&root)
                .expect("failed to launch namespace collector integration test");

        assert!(
                status.success(),
                "namespace collector integration test failed with {status}"
        );
}
