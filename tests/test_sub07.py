from wiki_spike.claims import DeterministicMockExtractor
from wiki_spike.controlplane import ControlPlane
from wiki_spike.generation import GenerationBuilder
from wiki_spike.gitrepo import GitRepo
from wiki_spike.mirror import RemoteMirror
from wiki_spike.publish import PublishService
from wiki_spike.search import SearchService
from wiki_spike.signing import Keyring

A = "Alpha | supports | feature X | positive | v=2026\n"
B = "Beta | supports | feature Y | positive | v=2026\n"


def _stack(tmp_path):
    repo = GitRepo.init_bare(tmp_path / "repo.git")
    kr = Keyring(); kr.generate("k1")
    builder = GenerationBuilder(repo, kr, "k1")
    cp = ControlPlane(tmp_path / "control.sqlite")
    return repo, builder, cp, PublishService(builder, cp)


def _ex(text):
    return DeterministicMockExtractor().extract(text, "src", "rep")


def test_lease_exclusivity_returns_token(tmp_path):
    _, _, cp, _ = _stack(tmp_path)
    now = 1000
    t1 = cp.acquire_lease("pub-A", now, ttl=30)
    assert t1 is not None
    assert cp.acquire_lease("pub-B", now, ttl=30) is None  # A holds it
    cp.release_lease("pub-A")
    t2 = cp.acquire_lease("pub-B", now, ttl=30)
    assert t2 is not None and t2 > t1  # fencing token advances on takeover


def test_lease_expires(tmp_path):
    _, _, cp, _ = _stack(tmp_path)
    assert cp.acquire_lease("pub-A", now=1000, ttl=30) is not None
    assert cp.acquire_lease("pub-B", now=1031, ttl=30) is not None


def test_mirror_pushes_and_is_idempotent(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    res = pub.publish(_ex(A).claims, "snapA")
    mirror = RemoteMirror(repo, tmp_path / "remote.git")
    assert mirror.process_outbox(cp) == 1
    assert mirror.remote_has(res.candidate_commit_oid)
    assert mirror.process_outbox(cp) == 0  # idempotent
    res2 = pub.publish(_ex(B).claims, "snapB")
    assert mirror.process_outbox(cp) == 1
    assert mirror.remote_has(res2.candidate_commit_oid)


def test_search_filters_retracted_when_stale(tmp_path):
    # Explicit REVOKE + lagging search pointer -> retracted claim is filtered out.
    repo, builder, cp, pub = _stack(tmp_path)
    search = SearchService(cp, max_generation_lag=5)
    ex = _ex(A)
    r1 = pub.publish(ex.claims, "snapA")            # G1 indexes Alpha
    alpha_id = ex.claims[0].identity.claim_id
    r2 = pub.publish([], "snapB", revokes=[alpha_id])  # G2 retracts Alpha
    cp.set_search_pointer(r1.generation_id)          # search lags at G1
    resp = search.query("Alpha")
    assert resp.stale is True
    assert resp.hits == []                            # retracted in current G2


def test_search_returns_live_claim(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    search = SearchService(cp)
    pub.publish(_ex(A).claims, "snapA")
    resp = search.query("Alpha")
    assert not resp.stale and len(resp.hits) == 1


def test_search_disabled_when_lag_exceeds_max(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    search = SearchService(cp, max_generation_lag=0)
    r1 = pub.publish(_ex(A).claims, "snapA")
    r2 = pub.publish(_ex(B).claims, "snapB")
    cp.set_search_pointer(r1.generation_id)
    assert search.query("Beta").disabled is True
