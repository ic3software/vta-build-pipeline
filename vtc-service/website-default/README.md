# vtc-service default community website

In-tree default landing page served when the operator has not set
`website.root_dir` in the daemon config.

This is a tiny fallback so a fresh `cargo run` produces a working
`GET /` response instead of a 503. The page fetches
`/v1/community/profile` + `/health` and renders them; until the
profile is populated, the placeholder copy in `index.html` is
shown.

Baked at compile time by `include_dir!` (see
`src/website/default_site.rs`). Served by the `/` catch-all
sub-router **only** when:

- The `website` cargo feature is on.
- `website.root_dir` is unset.

Once the operator sets `website.root_dir`, the filesystem-backed
handler from `src/website/serve.rs` takes over and this default
becomes unreachable.

Operators wanting a richer "out of the box" landing page replace
the files in this directory (or, more commonly, configure
`website.root_dir` and populate that directory with their own
content).
