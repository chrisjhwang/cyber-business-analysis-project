"""SQLAlchemy ORM models -- the schema, expressed as Python classes.

One row in `vulnerabilities` is written by TWO different sources at different
times: the CISA KEV feed and the NVD CVE API. Each column below is therefore
tagged with which source owns it. That ownership is not decoration -- when the
ingesters upsert, each one may only overwrite the columns it owns, or re-running
KEV would blank out the CVSS data NVD wrote (and vice versa).
"""
from datetime import date, datetime

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Vulnerability(Base):
    """A single CVE. Natural primary key -- the CVE ID is already unique and
    stable worldwide, so there is no reason to invent a surrogate integer id."""

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)

    # --- owned by the NVD ingester -------------------------------------
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    cvss_severity: Mapped[str | None] = mapped_column(Text)
    # "3.1", "3.0", "4.0" or "2.0". Old KEV entries often only have a v2 vector,
    # and the scoring engine parses each version differently.
    cvss_version: Mapped[str | None] = mapped_column(Text)
    published_date: Mapped[date | None] = mapped_column(Date)
    nvd_last_modified: Mapped[datetime | None] = mapped_column(DateTime)
    # "vendor:product" pairs pulled from NVD's CPE match list, e.g. "apache:log4j".
    # This is what lets scoring decide whether a CVE touches a given asset.
    affected_products: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # --- owned by the KEV ingester -------------------------------------
    # kev_flag is not-null with a default because a CVE that has never been
    # seen in the KEV feed is definitively "not known-exploited", not "unknown".
    kev_flag: Mapped[bool] = mapped_column(
        default=False, server_default="false", nullable=False
    )
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    # Feed reports "Known" / "Unknown" -- stored as a bool where Unknown=False,
    # because for scoring purposes unproven is treated the same as absent.
    known_ransomware_use: Mapped[bool] = mapped_column(
        default=False, server_default="false", nullable=False
    )
    vendor_project: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    short_description: Mapped[str | None] = mapped_column(Text)
    # CISA's remediation instruction, e.g. "Apply updates per vendor instructions."
    required_action: Mapped[str | None] = mapped_column(Text)

    # --- written by whichever ingester touched the row last -------------
    # Both feeds supply CWEs and both can supply several, so this is an array
    # rather than the single cwe_id column the original data model sketched.
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    last_updated: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    risk_scores: Mapped[list["RiskScore"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id} cvss={self.cvss_score} kev={self.kev_flag}>"


class Asset(Base):
    """A thing worth money that a CVE could damage. Hand-curated (5-10 rows),
    not ingested -- these are inputs to the model, not observed facts."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Unique so the seed script can upsert on it and stay re-runnable.
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    # 1 (low) .. 3 (high). Drives the secondary-loss multiplier in FAIR-lite.
    sensitivity_tier: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Software this asset runs, as "vendor:product" in NVD CPE naming. A CVE is
    # only scored against an asset whose stack it affects -- see
    # app/scoring/applicability.py. Empty means nothing is scored against it.
    technologies: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default=text("'{}'")
    )

    risk_scores: Mapped[list["RiskScore"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "sensitivity_tier BETWEEN 1 AND 3", name="ck_assets_sensitivity_tier"
        ),
    )

    def __repr__(self) -> str:
        return f"<Asset {self.id} {self.name!r} tier={self.sensitivity_tier}>"


class RiskScore(Base):
    """Derived output: what one CVE is worth, in dollars, against one asset.

    Nothing here is ingested -- every row is computed by the scoring engine from
    a (vulnerability, asset) pair, and recomputed whenever either side changes.
    """

    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), nullable=False
    )

    # Which of the asset's technologies made this CVE apply, e.g. "apache:log4j".
    matched_technology: Mapped[str] = mapped_column(Text, nullable=False)

    # The intermediate values are stored, not just the ALE, so any number in
    # the report can be traced back to its inputs. See app/scoring/fair_lite.py.
    tef: Mapped[float] = mapped_column(Float, nullable=False)  # threat event frequency
    exploit_probability: Mapped[float] = mapped_column(Float, nullable=False)
    lef: Mapped[float] = mapped_column(Float, nullable=False)  # loss event frequency
    primary_loss: Mapped[float] = mapped_column(Float, nullable=False)
    secondary_loss: Mapped[float] = mapped_column(Float, nullable=False)
    lm: Mapped[float] = mapped_column(Float, nullable=False)   # primary + secondary
    ale: Mapped[float] = mapped_column(Float, nullable=False, index=True)  # lef * lm
    computed_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="risk_scores")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="risk_scores")

    __table_args__ = (
        # One score per (asset, CVE). Makes rescoring an upsert instead of an
        # append, so /rescore can run repeatedly without piling up history.
        UniqueConstraint("asset_id", "cve_id", name="uq_risk_scores_asset_cve"),
    )

    def __repr__(self) -> str:
        return f"<RiskScore asset={self.asset_id} {self.cve_id} ale={self.ale:,.0f}>"
