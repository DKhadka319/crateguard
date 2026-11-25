from crateguard import cargo_toml

TOML = '''[package]
name = "demo"
version = "0.1.0"

[dependencies]
# web server
tokio = { version = "1.0", features = ["full"] }
openssl = "0.10.30"
serde_xml_rs = "0.6"
made-up-crate = "0.1"

[dependencies.zip]
version = "0.5"
default-features = false

[dev-dependencies]
pretty_assertions = "1"
local = { path = "../local" }
'''


def test_dependencies():
    deps = cargo_toml.dependencies(TOML)
    assert ("tokio", "1.0") in deps and ("zip", "0.5") in deps and ("pretty_assertions", "1") in deps
    assert all(n != "local" for n, _ in deps)  # path dependencies are skipped


def test_extract_ai_reply():
    reply = "Sure!\n```toml\nserde = \"1\"\nrand = \"0.8\"\n```\nHope this helps."
    assert cargo_toml.dependencies(cargo_toml.extract(reply)) == [("serde", "1"), ("rand", "0.8")]


def test_rewrite_keeps_layout():
    fixes = {"openssl": {"crate": "openssl", "req": "0.10.75"},
             "tokio": {"crate": "tokio", "req": "1.48.0"},
             "serde_xml_rs": {"crate": "serde-xml-rs", "req": "0.8.1"},
             "made-up-crate": {"crate": None, "req": None},
             "zip": {"crate": "zip", "req": "6.0.0"}}
    new = cargo_toml.rewrite(TOML, fixes)
    assert 'openssl = "0.10.75"' in new
    assert 'tokio = { version = "1.48.0", features = ["full"] }' in new
    assert 'serde-xml-rs = "0.8.1"' in new
    assert "# crateguard: removed" in new and "\nmade-up-crate" not in new
    assert '[dependencies.zip]\nversion = "6.0.0"\ndefault-features = false' in new
    assert "# web server" in new and 'pretty_assertions = "1"' in new
    assert ("made-up-crate", "0.1") not in cargo_toml.dependencies(new)
