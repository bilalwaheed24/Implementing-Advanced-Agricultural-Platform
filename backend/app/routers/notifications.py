"""User notification centre (FR-X4)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..core.deps import CurrentUser, DbSession, PagingDep, rate_limit
from ..core.errors import NotFound
from ..core.security import utcnow
from ..models import Notification
from ..repositories import paginate
from ..schemas import NotificationOut, Page

router = APIRouter(prefix="/notifications", tags=["Notifications"],
                   dependencies=[Depends(rate_limit)])


@router.get("", response_model=Page[NotificationOut], summary="List my notifications")
def list_notifications(db: DbSession, paging: PagingDep, principal: CurrentUser,
                       unread_only: bool = Query(default=False)) -> Page[NotificationOut]:
    query = select(Notification).where(Notification.user_id == principal.id).order_by(
        Notification.created_at.desc())
    if unread_only:
        query = query.where(Notification.read_at.is_(None))
    rows, total = paginate(db, query, paging.page, paging.page_size)
    return Page[NotificationOut](items=[NotificationOut.model_validate(r) for r in rows],
                                 total=total, page=paging.page, page_size=paging.page_size)


@router.post("/{notification_id}/read", response_model=NotificationOut, summary="Mark as read")
def mark_read(notification_id: str, db: DbSession, principal: CurrentUser) -> NotificationOut:
    notification = db.execute(select(Notification).where(
        Notification.id == notification_id,
        Notification.user_id == principal.id)).scalar_one_or_none()
    if notification is None:
        raise NotFound("Notification not found")
    notification.read_at = utcnow()
    db.commit()
    return NotificationOut.model_validate(notification)


@router.post("/read-all", summary="Mark every notification as read")
def mark_all_read(db: DbSession, principal: CurrentUser) -> dict:
    rows = list(db.execute(select(Notification).where(
        Notification.user_id == principal.id, Notification.read_at.is_(None))).scalars())
    now = utcnow()
    for notification in rows:
        notification.read_at = now
    db.commit()
    return {"marked_read": len(rows)}


@router.get("/unread-count", summary="Unread notification count")
def unread_count(db: DbSession, principal: CurrentUser) -> dict:
    from sqlalchemy import func

    count = db.execute(select(func.count()).select_from(Notification).where(
        Notification.user_id == principal.id, Notification.read_at.is_(None))).scalar_one()
    return {"unread": int(count)}
