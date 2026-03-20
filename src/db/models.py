"""SQLAlchemy 2.0 ORM models for the UN meeting database.

Tables
------
countries        – UN Member States (canonical names + ISO codes)
speakers         – People who spoke; country_id is nullable
documents        – One row per PDF / meeting
document_items   – One row per agenda item or named section in a meeting
stage_directions – Procedural italic text; linked to a document_item
speeches         – One row per speech segment; linked to a document_item
resolutions      – Draft / adopted resolutions
votes            – One voting event per resolution per document_item
country_votes    – Per-country vote position (for recorded votes)
amendments       – (optional) proposed amendments
"""

from __future__ import annotations

from datetime import date
from typing import Optional

from sqlalchemy import (
    Boolean,
    Date,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Countries
# ---------------------------------------------------------------------------


class Country(Base):
    __tablename__ = "countries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(300), unique=True, nullable=False)
    short_name: Mapped[Optional[str]] = mapped_column(String(100))
    iso2: Mapped[Optional[str]] = mapped_column(String(2), unique=True)
    iso3: Mapped[Optional[str]] = mapped_column(String(3), unique=True)
    un_member_since: Mapped[Optional[date]] = mapped_column(Date)

    speakers: Mapped[list["Speaker"]] = relationship(back_populates="country")
    country_votes: Mapped[list["CountryVote"]] = relationship(back_populates="country")


# ---------------------------------------------------------------------------
# Speakers
# ---------------------------------------------------------------------------


class Speaker(Base):
    __tablename__ = "speakers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    country_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("countries.id"), nullable=True
    )
    organization: Mapped[Optional[str]] = mapped_column(String(400), nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String(100))
    title: Mapped[Optional[str]] = mapped_column(String(20))

    country: Mapped[Optional[Country]] = relationship(back_populates="speakers")
    speeches: Mapped[list["Speech"]] = relationship(back_populates="speaker")

    __table_args__ = (
        UniqueConstraint("name", "country_id", "organization", name="uq_speaker"),
    )


# ---------------------------------------------------------------------------
# Documents (one per meeting PDF)
# ---------------------------------------------------------------------------


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    symbol: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    body: Mapped[str] = mapped_column(String(2), nullable=False)
    meeting_number: Mapped[int] = mapped_column(Integer, nullable=False)
    session: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    date: Mapped[Optional[date]] = mapped_column(Date)
    location: Mapped[Optional[str]] = mapped_column(String(50))
    pdf_path: Mapped[Optional[str]] = mapped_column(String(500))

    items: Mapped[list["DocumentItem"]] = relationship(back_populates="document")
    speeches: Mapped[list["Speech"]] = relationship(back_populates="document")
    stage_directions: Mapped[list["StageDirection"]] = relationship(
        back_populates="document"
    )
    votes: Mapped[list["Vote"]] = relationship(back_populates="document")


# ---------------------------------------------------------------------------
# Document items (agenda items or other named sections)
# ---------------------------------------------------------------------------


class DocumentItem(Base):
    """One agenda item or other named section within a meeting.

    ``position`` is the zero-based order of this item in the meeting.
    Speeches, stage directions, and votes within the item share a common
    ``position_in_item`` counter for document reconstruction.
    """

    __tablename__ = "document_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("documents.id"), nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    item_type: Mapped[str] = mapped_column(
        Enum("agenda_item", "other_item", name="item_type_enum"), nullable=False
    )
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    agenda_number: Mapped[Optional[int]] = mapped_column(Integer)
    sub_item: Mapped[Optional[str]] = mapped_column(String(10))
    continued: Mapped[bool] = mapped_column(Boolean, default=False)

    document: Mapped[Document] = relationship(back_populates="items")
    speeches: Mapped[list["Speech"]] = relationship(back_populates="item")
    stage_directions: Mapped[list["StageDirection"]] = relationship(
        back_populates="item"
    )
    votes: Mapped[list["Vote"]] = relationship(back_populates="item")

    __table_args__ = (
        UniqueConstraint("document_id", "position", name="uq_item_position"),
    )


# ---------------------------------------------------------------------------
# Stage directions
# ---------------------------------------------------------------------------


class StageDirection(Base):
    __tablename__ = "stage_directions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("documents.id"), nullable=False
    )
    item_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("document_items.id"), nullable=True
    )
    text: Mapped[str] = mapped_column(Text, nullable=False)
    direction_type: Mapped[str] = mapped_column(
        Enum(
            "adoption",
            "decision",
            "suspension",
            "resumption",
            "adjournment",
            "silence",
            "language_note",
            "other",
            name="direction_type_enum",
        ),
        nullable=False,
        default="other",
    )
    position_in_document: Mapped[int] = mapped_column(Integer, nullable=False)
    position_in_item: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    document: Mapped[Document] = relationship(back_populates="stage_directions")
    item: Mapped[Optional[DocumentItem]] = relationship(
        back_populates="stage_directions"
    )


# ---------------------------------------------------------------------------
# Speeches
# ---------------------------------------------------------------------------


class Speech(Base):
    __tablename__ = "speeches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("documents.id"), nullable=False
    )
    item_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("document_items.id"), nullable=True
    )
    speaker_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("speakers.id"), nullable=False
    )
    language: Mapped[Optional[str]] = mapped_column(String(50))
    on_behalf_of: Mapped[Optional[str]] = mapped_column(String(300))
    text: Mapped[str] = mapped_column(Text, nullable=False)
    position_in_document: Mapped[int] = mapped_column(Integer, nullable=False)
    position_in_item: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    document: Mapped[Document] = relationship(back_populates="speeches")
    item: Mapped[Optional[DocumentItem]] = relationship(back_populates="speeches")
    speaker: Mapped[Speaker] = relationship(back_populates="speeches")


# ---------------------------------------------------------------------------
# Resolutions
# ---------------------------------------------------------------------------


class Resolution(Base):
    __tablename__ = "resolutions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    draft_symbol: Mapped[str] = mapped_column(String(50), nullable=False)
    adopted_symbol: Mapped[Optional[str]] = mapped_column(String(50))
    title: Mapped[Optional[str]] = mapped_column(Text)
    body: Mapped[str] = mapped_column(String(2), nullable=False)
    session: Mapped[Optional[int]] = mapped_column(Integer)
    category: Mapped[Optional[str]] = mapped_column(String(200))

    votes: Mapped[list["Vote"]] = relationship(back_populates="resolution")


# ---------------------------------------------------------------------------
# Votes
# ---------------------------------------------------------------------------


class Vote(Base):
    __tablename__ = "votes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("documents.id"), nullable=False
    )
    item_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("document_items.id"), nullable=True
    )
    resolution_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("resolutions.id"), nullable=False
    )
    vote_type: Mapped[str] = mapped_column(
        Enum("consensus", "recorded", name="vote_type_enum"), nullable=False
    )
    vote_scope: Mapped[str] = mapped_column(
        Enum(
            "whole_resolution",
            "paragraph",
            "amendment",
            name="vote_scope_enum",
        ),
        nullable=False,
        default="whole_resolution",
    )
    paragraph_number: Mapped[Optional[int]] = mapped_column(Integer)
    yes_count: Mapped[Optional[int]] = mapped_column(Integer)
    no_count: Mapped[Optional[int]] = mapped_column(Integer)
    abstain_count: Mapped[Optional[int]] = mapped_column(Integer)
    position_in_item: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    document: Mapped[Document] = relationship(back_populates="votes")
    item: Mapped[Optional[DocumentItem]] = relationship(back_populates="votes")
    resolution: Mapped[Resolution] = relationship(back_populates="votes")
    country_votes: Mapped[list["CountryVote"]] = relationship(back_populates="vote")


# ---------------------------------------------------------------------------
# Country votes
# ---------------------------------------------------------------------------


class CountryVote(Base):
    __tablename__ = "country_votes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vote_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("votes.id"), nullable=False
    )
    country_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("countries.id"), nullable=False
    )
    vote_position: Mapped[str] = mapped_column(
        Enum("yes", "no", "abstain", "absent", name="vote_position_enum"),
        nullable=False,
    )

    vote: Mapped[Vote] = relationship(back_populates="country_votes")
    country: Mapped[Country] = relationship(back_populates="country_votes")

    __table_args__ = (
        UniqueConstraint("vote_id", "country_id", name="uq_country_vote"),
    )


# ---------------------------------------------------------------------------
# Amendments (optional)
# ---------------------------------------------------------------------------


class Amendment(Base):
    __tablename__ = "amendments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resolution_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("resolutions.id"), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(Text)
    proposed_by_country_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("countries.id"), nullable=True
    )
    oral_correction: Mapped[bool] = mapped_column(Boolean, default=False)
