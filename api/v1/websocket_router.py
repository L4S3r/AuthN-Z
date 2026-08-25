"""
Auth N&Z - Real-Time WebSocket Router & Event Gateway (api/v1/websocket_router.py)
----------------------------------------------------------------------------------
Manages real-time WebSocket connection lifecycle, workspace broadcast channels,
user notification subscriptions, and Redis pub/sub message synchronization.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional, Set
import urllib.parse
import uuid

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from models import Notification
from database import get_session_factory
from api.dependencies import (
    sess_store,
    token_svc,
    user_repo,
    ws_repo,
    perm_eval,
)

logger = logging.getLogger("auth_nz.websocket")

router = APIRouter(tags=["Realtime WebSockets"])


class ConnectionManager:
    """Manages active WebSocket connections grouped by workspace and user channels."""

    def __init__(self, redis_client: Optional[Any] = None):
        self.active_workspace_connections: Dict[str, Set[WebSocket]] = {}
        self.active_user_connections: Dict[str, Set[WebSocket]] = {}
        self.redis_client = redis_client

    async def connect(self, websocket: WebSocket, workspace_id: str, user_id: str):
        await websocket.accept()
        if workspace_id not in self.active_workspace_connections:
            self.active_workspace_connections[workspace_id] = set()
        self.active_workspace_connections[workspace_id].add(websocket)

        if user_id not in self.active_user_connections:
            self.active_user_connections[user_id] = set()
        self.active_user_connections[user_id].add(websocket)

    def disconnect(self, websocket: WebSocket, workspace_id: str, user_id: str):
        if workspace_id in self.active_workspace_connections:
            self.active_workspace_connections[workspace_id].discard(websocket)
            if not self.active_workspace_connections[workspace_id]:
                self.active_workspace_connections.pop(workspace_id, None)

        if user_id in self.active_user_connections:
            self.active_user_connections[user_id].discard(websocket)
            if not self.active_user_connections[user_id]:
                self.active_user_connections.pop(user_id, None)

    async def broadcast_to_workspace(self, workspace_id: str, message: Dict[str, Any]):
        """Broadcast a real-time event to all connected workspace participants."""
        sockets = list(self.active_workspace_connections.get(workspace_id, set()))
        dead_sockets = []
        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception:
                dead_sockets.append(ws)

        for ws in dead_sockets:
            if workspace_id in self.active_workspace_connections:
                self.active_workspace_connections[workspace_id].discard(ws)

        if self.redis_client is not None:
            try:
                channel = f"ws:workspace:{workspace_id}"
                self.redis_client.publish(channel, json.dumps(message))
            except Exception as exc:
                logger.warning("Failed to publish WebSocket message to Redis channel: %s", exc)

    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        """Send a real-time event directly to a specific user across their connected devices."""
        sockets = list(self.active_user_connections.get(user_id, set()))
        dead_sockets = []
        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception:
                dead_sockets.append(ws)

        for ws in dead_sockets:
            if user_id in self.active_user_connections:
                self.active_user_connections[user_id].discard(ws)

        if self.redis_client is not None:
            try:
                channel = f"ws:user:{user_id}"
                self.redis_client.publish(channel, json.dumps(message))
            except Exception as exc:
                logger.warning("Failed to publish user notification to Redis channel: %s", exc)


# Singleton connection manager
ws_manager = ConnectionManager(redis_client=getattr(sess_store, "r", None))


async def create_and_push_notification(
    user_id: str,
    notif_type: str,
    title: str,
    message: str,
    link: Optional[str] = None,
    workspace_id: Optional[str] = None,
    task_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist notification in PostgreSQL and broadcast in real-time over WebSocket with deep-link metadata."""
    notif_uuid = uuid.uuid4()
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()

    resolved_task_uuid = None
    if task_id:
        try:
            resolved_task_uuid = uuid.UUID(str(task_id).strip())
        except Exception:
            pass
    elif link and "task=" in link:
        try:
            parsed = urllib.parse.urlparse(link)
            qs = urllib.parse.parse_qs(parsed.query)
            if "task" in qs and qs["task"]:
                resolved_task_uuid = uuid.UUID(qs["task"][0].strip())
        except Exception:
            pass

    user_uuid = None
    try:
        user_uuid = uuid.UUID(str(user_id).strip())
    except Exception:
        pass

    ws_uuid = None
    if workspace_id:
        try:
            ws_uuid = uuid.UUID(str(workspace_id).strip())
        except Exception:
            pass

    record = {
        "id": str(notif_uuid),
        "user_id": str(user_id),
        "workspace_id": str(workspace_id) if workspace_id else None,
        "task_id": str(resolved_task_uuid) if resolved_task_uuid else None,
        "type": notif_type,
        "title": title,
        "message": message,
        "link": link,
        "is_read": 0,
        "created_at": now_str,
    }

    if user_uuid:
        try:
            session_factory = get_session_factory()
            async with session_factory() as session:
                notif_obj = Notification(
                    id=notif_uuid,
                    user_id=user_uuid,
                    workspace_id=ws_uuid,
                    task_id=resolved_task_uuid,
                    type=notif_type,
                    title=title,
                    message=message,
                    link=link,
                    is_read=False,
                    created_at=now_dt,
                )
                session.add(notif_obj)
                await session.commit()
        except Exception as exc:
            logger.error("Failed to insert in-app notification to PostgreSQL: %s", exc)

    # Push to active WebSocket clients for this user
    await ws_manager.send_to_user(
        user_id,
        {
            "event": "notification.received",
            "notification": record,
            "timestamp": now_str,
        },
    )
    return record


@router.websocket("/ws/workspaces/{workspace_id}")
async def workspace_websocket_endpoint(
    websocket: WebSocket,
    workspace_id: str,
    token: Optional[str] = Query(None),
):
    """
    Authenticated real-time WebSocket channel for task board synchronization and in-app notifications.
    Authenticates via 'access_token' cookie, Authorization header, or '?token=<jwt>' query parameter.
    """
    raw_token = token
    if not raw_token or raw_token == "cookie_session":
        raw_token = websocket.cookies.get("access_token")

    if not raw_token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_token = auth_header.split(" ", 1)[1]

    if not raw_token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication token required")
        return

    clean_token = str(raw_token).strip().strip('"').strip("'")
    try:
        payload = token_svc.decode_and_verify(clean_token)
    except Exception as exc:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=f"Invalid token: {str(exc)}")
        return

    user_id = payload.get("sub")
    user = await user_repo.get_by_id(user_id)
    if not user or not user.get("is_active", 1):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User inactive or not found")
        return

    # Verify workspace membership clearance if not superadmin
    is_superadmin = await perm_eval.has_role(user_id, "superadmin")
    if not is_superadmin and workspace_id != "ws_default":
        member = await ws_repo.get_member(workspace_id, user_id=user_id, email=user.get("email"))
        if not member:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Not a member of this workspace")
            return

    await ws_manager.connect(websocket, workspace_id, user_id)
    try:
        await websocket.send_json({
            "event": "connected",
            "workspace_id": workspace_id,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        while True:
            try:
                data = await websocket.receive_text()
            except (WebSocketDisconnect, RuntimeError):
                break
            except Exception:
                break

            if not data or data == "close":
                break
            elif data == "ping":
                try:
                    await websocket.send_text("pong")
                except Exception:
                    break
            else:
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
                    elif msg.get("type") == "close":
                        break
                except Exception:
                    pass
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as exc:
        logger.debug("WebSocket exception: %s", exc)
    finally:
        ws_manager.disconnect(websocket, workspace_id, user_id)
