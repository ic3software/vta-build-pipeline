//! Smoke test for the embedded mediator fixture.
//!
//! Spawns a `TestMediator` against the in-memory backend, hits
//! `/healthchecker`, and shuts down cleanly. If this test passes, the
//! `[patch.crates-io]` redirect graph + the path dep on
//! `affinidi-messaging-test-mediator` are wired correctly and the rest
//! of the e2e suite can build on top of it.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;

mod common;

#[tokio::test]
async fn mediator_spawns_and_serves_healthchecker() {
    common::init_tracing();

    let mediator = TestMediator::spawn().await.expect("spawn test mediator");

    assert_eq!(mediator.endpoint().scheme(), "http");
    assert!(mediator.did().starts_with("did:peer:2."));
    assert!(mediator.bound_addr().port() > 0);

    let url = format!("{}healthchecker", mediator.endpoint());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("healthchecker request");
    assert!(
        resp.status().is_success(),
        "healthchecker returned: {}",
        resp.status()
    );

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}
