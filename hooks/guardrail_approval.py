"""Out-of-band approval state: pending requests and HMAC-signed tokens.

Layout under the state dir:
    hmac.key            random signing key (0600)
    pending/<id>.json   what the hook blocked, written by the hook
    approved/<id>.json  signed one-time token, written by guardrail_cli.py

The id is the first 16 hex characters (64 bits) of the action hash, so the
same action always maps to the same id and a crafted second action cannot
realistically collide with it.
"""
import hashlib
import hmac
import json
import os
import re
import time

ID_RE = re.compile(r"^[0-9a-f]{16}$")


def action_hash(tool, normalized):
    return hashlib.sha256((tool + "\0" + normalized).encode("utf-8", "surrogatepass")).hexdigest()


def bash_action(command, cwd=""):
    # The same relative command has a different target in a different directory,
    # so an approval must not carry over between them.
    return action_hash("Bash", cwd + "\0" + command.strip())


def file_action(tool, resolved_path, content):
    digest = hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()
    return action_hash(tool, resolved_path + "\0" + digest)


def action_id(ahash):
    return ahash[:16]


def _chmod(path, mode):
    try:
        os.chmod(path, mode)
    except OSError:
        pass  # not supported on every platform/filesystem


def ensure_state_dir(state):
    for d in (state, os.path.join(state, "pending"), os.path.join(state, "approved")):
        os.makedirs(d, mode=0o700, exist_ok=True)
        _chmod(d, 0o700)


def write_private(path, text):
    tmp = "%s.%d.tmp" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    _chmod(path, 0o600)


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_key(state):
    ensure_state_dir(state)
    path = os.path.join(state, "hmac.key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(os.urandom(32).hex())
        _chmod(path, 0o600)
    except FileExistsError:
        pass
    with open(path, "rb") as f:
        return f.read().strip()


def _mac(key, rid, ahash, expires):
    msg = ("%s|%s|%d" % (rid, ahash, expires)).encode("ascii")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def pending_path(state, rid):
    return os.path.join(state, "pending", rid + ".json")


def approved_path(state, rid):
    return os.path.join(state, "approved", rid + ".json")


def write_pending(state, ahash, tool, summary, reason, ttl):
    ensure_state_dir(state)
    rid = action_id(ahash)
    rec = {"id": rid, "tool": tool, "summary": summary, "reason": reason,
           "action_hash": ahash, "ttl_seconds": ttl, "created": int(time.time())}
    write_private(pending_path(state, rid), json.dumps(rec))
    return rid


def read_pending(state, rid):
    return _read_json(pending_path(state, rid))


def issue_token(state, rid, now=None):
    """Called by the human-run CLI after confirmation."""
    rec = read_pending(state, rid)
    key = load_key(state)
    expires = int((now or time.time)() + rec["ttl_seconds"])
    token = {"id": rid, "action_hash": rec["action_hash"], "expires": expires,
             "mac": _mac(key, rid, rec["action_hash"], expires)}
    write_private(approved_path(state, rid), json.dumps(token))
    return token


def consume_token(state, ahash, now=None):
    """Return True and delete the token if a valid unexpired one exists."""
    rid = action_id(ahash)
    path = approved_path(state, rid)
    if not os.path.isfile(path):
        return False
    try:
        tok = _read_json(path)
        expires = tok["expires"]
        if (not isinstance(expires, int) or isinstance(expires, bool)
                or tok["id"] != rid or tok["action_hash"] != ahash):
            return False
        key = load_key(state)
        if not hmac.compare_digest(str(tok["mac"]), _mac(key, rid, ahash, expires)):
            return False
    except (OSError, ValueError, KeyError, TypeError):
        return False
    try:
        os.remove(path)  # consumed whether or not it is still fresh
    except OSError:
        return False
    return expires > (now or time.time)()


def list_entries(state, now=None):
    """Return [(id, status, record)] for pending and approved requests."""
    now = (now or time.time)()
    out = []
    pdir = os.path.join(state, "pending")
    if not os.path.isdir(pdir):
        return out
    for name in sorted(os.listdir(pdir)):
        rid = name[:-5]
        if not name.endswith(".json") or not ID_RE.match(rid):
            continue
        try:
            rec = _read_json(os.path.join(pdir, name))
        except (OSError, ValueError):
            continue
        status = "pending"
        try:
            tok = _read_json(approved_path(state, rid))
            if int(tok["expires"]) > now:
                status = "approved (expires in %ds)" % (int(tok["expires"]) - now)
            else:
                status = "pending (previous approval expired)"
        except (OSError, ValueError, KeyError, TypeError):
            pass
        out.append((rid, status, rec))
    return out
