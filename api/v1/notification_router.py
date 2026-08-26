"""
Auth N&Z - In-App Notifications Router (api/v1/notification_router.py)
----------------------------------------------------------------------
Endpoints for retrieving user notification feeds, unread badge counters,
and marking individual or all notifications as read.
"""

from typing import Any, Dict
import logging
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update as sql_update

from api.dependencies import get_current_user
from database import get_session_factory
from workspace_models import Notification

logger = logging.getLogger("auth_nz.notification_router")

router = APIRouter(tags=["In-App Notifications"])


@router.get("/notifications")
async def get_user_notifications(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve in-app notifications and unread count for current authenticated user."""
    user_id = current_user["user_id"]
    try:
        user_uuid = uuid.UUID(str(user_id).strip())
    except Exception:
        return {"status": "SUCCESS", "unread_count": 0, "notifications": []}

    session_factory = get_session_factory()
    async with session_factory() as session:
        unread_res = await session.execute(
            select(func.count(Notification.id)).where(
                Notification.user_id == user_uuid, Notification.is_read == False
            )
        )
        unread_count = unread_res.scalar_one() or 0

        stmt = (
            select(Notification)
            .where(Notification.user_id == user_uuid)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows_res = await session.execute(stmt)
        rows = rows_res.scalars().all()

        notifications = [
            {
                "id": str(n.id),
                "user_id": str(n.user_id),
                "workspace_id": str(n.workspace_id) if n.workspace_id else None,
                "task_id": str(n.task_id) if n.task_id else None,
                "type": n.type,
                "title": n.title,
                "message": n.message,
                "link": n.link,
                "is_read": 1 if n.is_read else 0,
                "created_at": n.created_at.isoformat() if n.created_at else "",
            }
            for n in rows
        ]

    return {
        "status": "SUCCESS",
        "unread_count": unread_count,
        "notifications": notifications,
    }


@router.post("/notifications/{notification_id}/read")
async def mark_notification_as_read(
    notification_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Mark a specific notification as read."""
    user_id = current_user["user_id"]
    try:
        user_uuid = uuid.UUID(str(user_id).strip())
        notif_uuid = uuid.UUID(str(notification_id).strip())
    except Exception:
        raise HTTPException(status_code=404, detail="Notification not found.")

    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = (
            sql_update(Notification)
            .where(Notification.id == notif_uuid, Notification.user_id == user_uuid)
            .values(is_read=True)
        )
        res = await session.execute(stmt)
        await session.commit()
        if (res.rowcount or 0) == 0:
            raise HTTPException(status_code=404, detail="Notification not found.")

    return {"status": "SUCCESS", "id": notification_id, "is_read": 1}


@router.post("/notifications/read-all")
async def mark_all_notifications_as_read(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Mark all notifications for the authenticated user as read."""
    user_id = current_user["user_id"]
    try:
        user_uuid = uuid.UUID(str(user_id).strip())
    except Exception:
        return {"status": "SUCCESS", "message": "All notifications marked as read."}

    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = (
            sql_update(Notification)
            .where(Notification.user_id == user_uuid, Notification.is_read == False)
            .values(is_read=True)
        )
        await session.execute(stmt)
        await session.commit()

    return {"status": "SUCCESS", "message": "All notifications marked as read."}
