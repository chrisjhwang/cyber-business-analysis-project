"""The rescore loop against a real database."""
import pytest
from sqlalchemy import func, select

from app.models import RiskScore
from app.scoring.engine import rescore
from tests.factories import HEARTBLEED_VECTOR, add_asset, add_vuln


def score_count(db):
    return db.scalar(select(func.count()).select_from(RiskScore))


def test_scores_only_applicable_pairs(db):
    payment = add_asset(db, "payment API", technologies=["apache:log4j"])
    add_asset(db, "auth", technologies=["microsoft:windows_server"])
    add_vuln(db, "CVE-2021-44228")                                  # log4j: payment only
    add_vuln(db, "CVE-2014-0160", vector=HEARTBLEED_VECTOR, kev=False, ransomware=False,
             affected=["openssl:openssl"])                          # applies to neither
    add_vuln(db, "CVE-2099-0001", vector=None, score=None)          # no CVSS yet

    result = rescore(db)
    db.commit()

    assert result.scores_written == 1
    assert result.unscorable == 1
    score = db.scalars(select(RiskScore)).one()
    assert score.asset_id == payment.id
    assert score.matched_technology == "apache:log4j"
    # Same hand-computed answer as tests/test_scoring.py, now through the DB.
    assert score.ale == pytest.approx(2_635_200)


def test_rescore_is_idempotent(db):
    add_asset(db)
    add_vuln(db, "CVE-2021-44228")
    rescore(db)
    rescore(db)
    db.commit()
    assert score_count(db) == 1


def test_rescore_removes_scores_that_no_longer_apply(db):
    asset = add_asset(db)
    add_vuln(db, "CVE-2021-44228")
    rescore(db)
    db.commit()
    assert score_count(db) == 1

    asset.technologies = []  # the asset no longer runs log4j
    db.commit()
    result = rescore(db)
    db.commit()

    assert result.stale_removed == 1
    assert score_count(db) == 0
