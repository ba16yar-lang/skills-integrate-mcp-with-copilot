from datetime import datetime
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.auth import get_current_session, require_csrf
from src.database import get_db, utcnow_naive
from src.models import MasterCV, MasterCVRevision, UserSession


class ContactDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=320)
    phone: str = Field(default="", max_length=40)
    location: str = Field(default="", max_length=160)
    website: str = Field(default="", max_length=300)
    linkedin: str = Field(default="", max_length=300)


class EmploymentEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_title: str = Field(min_length=1, max_length=160)
    employer: str = Field(min_length=1, max_length=160)
    location: str = Field(default="", max_length=160)
    start_date: str = Field(default="", max_length=32)
    end_date: str = Field(default="", max_length=32)
    description: str = Field(default="", max_length=4000)
    achievements: list[str] = Field(default_factory=list, max_length=30)


class EducationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    institution: str = Field(min_length=1, max_length=200)
    qualification: str = Field(default="", max_length=160)
    subject: str = Field(default="", max_length=160)
    start_date: str = Field(default="", max_length=32)
    end_date: str = Field(default="", max_length=32)
    details: str = Field(default="", max_length=3000)


class CertificationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    issuer: str = Field(default="", max_length=160)
    date: str = Field(default="", max_length=32)


class ProjectEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=3000)
    url: str = Field(default="", max_length=300)


class MasterCVContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contact: ContactDetails = Field(default_factory=ContactDetails)
    professional_summary: str = Field(default="", max_length=5000)
    employment: list[EmploymentEntry] = Field(default_factory=list, max_length=50)
    education: list[EducationEntry] = Field(default_factory=list, max_length=50)
    certifications: list[CertificationEntry] = Field(default_factory=list, max_length=50)
    skills: list[str] = Field(default_factory=list, max_length=100)
    projects: list[ProjectEntry] = Field(default_factory=list, max_length=50)


class MasterCVUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=0)
    content: MasterCVContent


class MasterCVResponse(BaseModel):
    id: str | None
    version: int
    updated_at: datetime | None
    content: MasterCVContent


class MasterCVRevisionResponse(BaseModel):
    version: int
    created_at: datetime
    content: MasterCVContent


router = APIRouter(prefix="/master-cv", tags=["master CV"])
EMPTY_CONTENT = MasterCVContent()


@router.get("/me", response_model=MasterCVResponse)
def get_master_cv(
    session: Annotated[UserSession, Depends(get_current_session)],
    db: Session = Depends(get_db),
) -> MasterCVResponse:
    record = db.scalar(select(MasterCV).where(MasterCV.user_id == session.user_id))
    if not record:
        return MasterCVResponse(id=None, version=0, updated_at=None, content=EMPTY_CONTENT)
    return MasterCVResponse(
        id=record.id,
        version=record.version,
        updated_at=record.updated_at,
        content=MasterCVContent.model_validate(record.content),
    )


@router.get("/revisions/me", response_model=list[MasterCVRevisionResponse])
def get_master_cv_revisions(
    session: Annotated[UserSession, Depends(get_current_session)],
    db: Session = Depends(get_db),
) -> list[MasterCVRevisionResponse]:
    record = db.scalar(select(MasterCV).where(MasterCV.user_id == session.user_id))
    if not record:
        return []
    revisions = db.scalars(
        select(MasterCVRevision)
        .where(MasterCVRevision.master_cv_id == record.id)
        .order_by(MasterCVRevision.version.desc())
    ).all()
    return [
        MasterCVRevisionResponse(
            version=item.version,
            created_at=item.created_at,
            content=MasterCVContent.model_validate(item.content),
        )
        for item in revisions
    ]


@router.put("/me", response_model=MasterCVResponse)
def save_master_cv(
    payload: MasterCVUpdate,
    session: Annotated[UserSession, Depends(require_csrf)],
    db: Session = Depends(get_db),
) -> MasterCVResponse:
    record = db.scalar(select(MasterCV).where(MasterCV.user_id == session.user_id))
    current_version = record.version if record else 0
    if payload.expected_version != current_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Master CV version conflict; current version is {current_version}",
        )

    content = payload.content.model_dump(mode="json")
    if record:
        result = db.execute(
            update(MasterCV)
            .where(MasterCV.id == record.id, MasterCV.version == payload.expected_version)
            .values(
                content=content,
                version=MasterCV.version + 1,
                updated_at=utcnow_naive(),
            )
        )
        if result.rowcount != 1:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Master CV was updated by another request",
            )
    else:
        record = MasterCV(
            id=str(uuid4()),
            user_id=session.user_id,
            content=content,
            version=1,
            updated_at=utcnow_naive(),
        )
        db.add(record)
    try:
        db.flush()
        db.add(
            MasterCVRevision(
                master_cv_id=record.id,
                version=record.version,
                content=content,
                created_at=utcnow_naive(),
            )
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Master CV was created by another request",
        ) from exc
    db.refresh(record)
    return MasterCVResponse(
        id=record.id,
        version=record.version,
        updated_at=record.updated_at,
        content=payload.content,
    )


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_master_cv(
    session: Annotated[UserSession, Depends(require_csrf)],
    db: Session = Depends(get_db),
) -> Response:
    record = db.scalar(select(MasterCV).where(MasterCV.user_id == session.user_id))
    if record:
        db.delete(record)
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
