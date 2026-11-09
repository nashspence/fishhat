from scripts.check_public import check_text

CHECK_PURPOSE = {
    "purpose": "repository-policy",
    "authority": ["scripts/check_public.py"],
    "scope": "public-content guard",
    "relationship": "no-product-claim",
    "reason": "Public Markdown, path, identity and secret-pattern policy, not product behavior.",
    "claims": [],
}


def test_git_identity_headers_are_allowed_only_as_commit_metadata():
    metadata = "committer GitHub <noreply@" + "github.com> 1720000000 +0000"
    assert check_text("commit", metadata, git_commit=True) == []
    assert check_text("source", metadata)
    assert check_text("commit", "\n\n" + metadata, git_commit=True)
    assert check_text("commit", "message: noreply@" + "github.com", git_commit=True)


def test_private_identifier_checks_still_cover_git_identity_headers():
    metadata = "author Someone <person@" + "private-domain.internal> 1720000000 +0000"
    assert check_text("commit", metadata, ["private-domain.internal"], git_commit=True)
    assert check_text("commit", "https://" + "private-domain.internal/path", git_commit=True)


def test_dependabot_public_signoff_is_allowed_only_in_commit_messages():
    signoff = "Signed-off-by: dependabot[bot] <support@" + "github.com>"
    assert check_text("commit", "\n\n" + signoff, git_commit=True) == []
    assert check_text("source", signoff)


def test_onboarding_documents_preserve_other_path_and_content_checks(tmp_path, monkeypatch):
    import scripts.check_public as scanner

    names = ["README.md"]
    monkeypatch.setattr(scanner, "ROOT", tmp_path)
    monkeypatch.setattr(scanner, "git", lambda *args: b"\0".join(name.encode() for name in names))
    readme = tmp_path / "README.md"
    readme.write_text("Working overview\n")
    assert scanner.run() == 0
    readme.write_text("https://" + "private-domain.internal/path\n")
    assert scanner.run() == 1
    readme.write_text("Working overview\n")
    (tmp_path / "AGENTS.md").write_text("Developer guide\n")
    names[:] = ["README.md", "AGENTS.md"]
    assert scanner.run() == 0
    for name in (
        "notes.md",
        "packages/example/README.md",
        "docs/README.md",
        "packages/example/AGENTS.md",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Additional documentation\n")
        names[:] = ["README.md", name]
        assert scanner.run() == 1


def test_markdown_links_receive_destination_checks():
    assert check_text("README.md", "[reference](https://" + "private-domain.internal/path)")
    assert check_text(
        "source.py", "https://" + "cloud-images.ubuntu.com.private-domain.internal/path"
    )
    for url in (
        "https://cloud-images.ubuntu.com/",
        "https://docs.ansible.com/projects/ansible/latest/getting_started/basic_concepts.html",
        "https://pyinfra.com/",
        "https://kamal-deploy.org/",
        "https://komo.do/docs/intro",
        "https://coolify.io/docs/core/how-coolify-works",
        "https://doc.yunohost.org/en/admin/what_is_yunohost/",
    ):
        assert check_text("README.md", f"[reference]({url})\u2060") == []
