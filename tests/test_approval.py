"""Out-of-band approval flow: pending -> human approve -> allowed once."""
import json
import os
import time

import guardrail_cli as cli
import pytest


def hit(gg, tool="Bash", **inp):
    if tool == "Bash":
        inp = {"command": "rm %s/.ssh/id_x" % gg.home}
    return gg.run(tool, inp)


def approve(gg, rid, answer="yes", now=None):
    out = []
    rc = cli.approve(rid, state_dir=gg.state, require_tty=False,
                     input_fn=lambda *_: answer, out=out.append, now=now)
    return rc, "\n".join(out)


def test_block_creates_pending_request_with_id_and_instructions(gg):
    r = hit(gg)
    assert r.kind == "approve"
    rid = r.approval_id
    assert "guardrail_cli.py approve %s" % rid in r.stderr
    assert "Do not" in r.stderr
    pending = os.path.join(gg.state, "pending", rid + ".json")
    data = json.load(open(pending, encoding="utf-8"))
    assert data["tool"] == "Bash"
    assert ".ssh/id_x" in data["summary"]
    assert data["reason"]
    assert data["ttl_seconds"] == 600


def test_ttl_comes_from_config(gg):
    gg.write_config(approval={"ttl_seconds": 7})
    rid = hit(gg).approval_id
    data = json.load(open(os.path.join(gg.state, "pending", rid + ".json"), encoding="utf-8"))
    assert data["ttl_seconds"] == 7


def test_same_action_same_id_different_action_different_id(gg):
    a = hit(gg).approval_id
    assert hit(gg).approval_id == a
    other = gg.bash("rm %s/.ssh/id_y" % gg.home).approval_id
    assert other != a


def test_approve_shows_request_and_allows_exactly_once(gg):
    rid = hit(gg).approval_id
    rc, shown = approve(gg, rid)
    assert rc == 0
    assert ".ssh/id_x" in shown and "Bash" in shown
    first = hit(gg)
    assert first.kind == "allow"
    second = hit(gg)
    assert second.kind == "approve"
    assert second.approval_id == rid


def test_approval_does_not_cover_a_different_action(gg):
    rid = hit(gg).approval_id
    approve(gg, rid)
    assert gg.bash("rm %s/.ssh/id_other" % gg.home).kind == "approve"
    assert hit(gg).kind == "allow"


def test_answer_other_than_yes_does_not_approve(gg):
    rid = hit(gg).approval_id
    rc, _ = approve(gg, rid, answer="y")
    assert rc != 0
    assert hit(gg).kind == "approve"


def test_approve_refuses_without_a_tty(gg):
    rid = hit(gg).approval_id
    rc = cli.approve(rid, state_dir=gg.state, require_tty=True,
                     input_fn=lambda *_: "yes", out=lambda s: None,
                     isatty_fn=lambda: False)
    assert rc != 0
    assert hit(gg).kind == "approve"


def test_unknown_id_is_rejected(gg):
    rc, _ = approve(gg, "deadbeef")
    assert rc != 0


def test_invalid_id_format_is_rejected(gg):
    rc, _ = approve(gg, "../../etc/passwd")
    assert rc != 0


def test_expired_token_is_rejected(gg):
    rid = hit(gg).approval_id
    rc, _ = approve(gg, rid, now=lambda: time.time() - 100000)
    assert rc == 0
    assert hit(gg).kind == "approve"


def test_forged_token_without_key_is_rejected(gg):
    rid = hit(gg).approval_id
    pending = json.load(open(os.path.join(gg.state, "pending", rid + ".json"), encoding="utf-8"))
    os.makedirs(os.path.join(gg.state, "approved"), exist_ok=True)
    forged = {"id": rid, "action_hash": pending["action_hash"],
              "expires": time.time() + 600, "mac": "0" * 64}
    with open(os.path.join(gg.state, "approved", rid + ".json"), "w", encoding="utf-8") as f:
        json.dump(forged, f)
    assert hit(gg).kind == "approve"


def test_tampered_token_is_rejected(gg):
    rid = hit(gg).approval_id
    approve(gg, rid)
    path = os.path.join(gg.state, "approved", rid + ".json")
    tok = json.load(open(path, encoding="utf-8"))
    tok["expires"] = time.time() + 10 ** 7
    json.dump(tok, open(path, "w", encoding="utf-8"))
    assert hit(gg).kind == "approve"


def test_file_tool_approval_binds_content(gg):
    path = os.path.join(gg.allowed, ".env")
    r = gg.run("Write", {"file_path": path, "content": "A=1"})
    assert r.kind == "approve"
    approve(gg, r.approval_id)
    assert gg.run("Write", {"file_path": path, "content": "A=2"}).kind == "approve"
    assert gg.run("Write", {"file_path": path, "content": "A=1"}).kind == "allow"
    assert gg.run("Write", {"file_path": path, "content": "A=1"}).kind == "approve"


def test_deny_tier_cannot_be_approved(gg):
    r = gg.bash("rm %s/a.py" % gg.protected)
    assert r.kind == "deny"
    assert r.approval_id is None
    assert not os.path.isdir(os.path.join(gg.state, "pending")) or not os.listdir(
        os.path.join(gg.state, "pending"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_state_dir_and_files_are_private(gg):
    rid = hit(gg).approval_id
    approve(gg, rid)
    assert os.stat(gg.state).st_mode & 0o777 == 0o700
    key = os.path.join(gg.state, "hmac.key")
    assert os.stat(key).st_mode & 0o777 == 0o600
    assert os.stat(os.path.join(gg.state, "pending", rid + ".json")).st_mode & 0o777 == 0o600
