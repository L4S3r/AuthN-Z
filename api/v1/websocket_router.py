"""
Auth N&Z - Real-Time WebSocket Router & Event Gateway (api/v1/websocket_router.py)
----------------------------------------------------------------------------------
Manages real-time WebSocket connection lifecycle, workspace broadcast channels,
user notification subscriptions, and Redis pub/sub message synchronization.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional, Set
import urllib.parse
import uuid

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from workspace_models import Notification
from database import get_session_factory
from config import settings
from api.dependencies import (
    sess_store,
    token_svc,
    user_repo,
    ws_repo,
    perm_eval,
)

logger = logging.getLogger("auth_nz.websocket")

router = APIRouter(tags=["Realtime WebSockets"])

# Unique process/node ID generated at startup to prevent pub/sub loopback echoes
NODE_ID = str(uuid.uuid4())


class ConnectionManager:
    """Manages active WebSocket connections grouped by workspace and user channels."""

    def __init__(self, redis_client: Optional[Any] = None, node_id: Optional[str] = None):
        self.active_workspace_connections: Dict[str, Set[WebSocket]] = {}
        self.active_user_connections: Dict[str, Set[WebSocket]] = {}
        self.redis_client = redis_client
        self.node_id = node_id or NODE_ID

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
        """Broadcast a real-time event to all connected workspace participants on this node and publish to Redis."""
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
                envelope = {**message, "_origin_node_id": self.node_id}
                self.redis_client.publish(channel, json.dumps(envelope))
            except Exception as exc:
                logger.warning("Failed to publish WebSocket message to Redis channel: %s", exc)

    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        """Send a real-time event directly to a specific user across their connected devices on this node and publish to Redis."""
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
                envelope = {**message, "_origin_node_id": self.node_id}
                self.redis_client.publish(channel, json.dumps(envelope))
            except Exception as exc:
                logger.warning("Failed to publish user notification to Redis channel: %s", exc)


# Singleton connection manager
ws_manager = ConnectionManager(redis_client=getattr(sess_store, "r", None), node_id=NODE_ID)

_pubsub_task: Optional[asyncio.Task] = None
_pubsub_client: Optional[Any] = None


async def redis_ws_pubsub_listener(manager: ConnectionManager, redis_url: Optional[str] = None):
    """Background listener consuming multi-pod WebSocket messages from Redis and forwarding to local sockets."""
    global _pubsub_client
    if aioredis is None:
        logger.info("redis.asyncio not installed; distributed WebSocket sync listener disabled.")
        return

    target_url = redis_url or settings.get_redis_url()

    while True:
        try:
            _pubsub_client = aioredis.from_url(
                target_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            pubsub = _pubsub_client.pubsub()
            await pubsub.psubscribe("ws:workspace:*", "ws:user:*")
            logger.info("Distributed WebSocket Redis Pub/Sub listener active (Node ID: %s)", manager.node_id)

            async for msg in pubsub.listen():
                if not msg or msg.get("type") != "pmessage":
                    continue

                channel = str(msg.get("channel", ""))
                raw_data = msg.get("data")
                if not raw_data or not isinstance(raw_data, str):
                    continue

                try:
                    payload = json.loads(raw_data)
                except Exception:
                    continue

                # Skip rebroadcasting if this node published the message (loopback suppression)
                if payload.get("_origin_node_id") == manager.node_id:
                    continue

                # Strip internal routing metadata before pushing to frontend WebSocket clients
                clean_payload = {k: v for k, v in payload.items() if k != "_origin_node_id"}

                if channel.startswith("ws:workspace:"):
                    ws_id = channel.split("ws:workspace:", 1)[1]
                    sockets = list(manager.active_workspace_connections.get(ws_id, set()))
                    for ws in sockets:
                        try:
                            await ws.send_json(clean_payload)
                        except Exception:
                            pass
                elif channel.startswith("ws:user:"):
                    uid = channel.split("ws:user:", 1)[1]
                    sockets = list(manager.active_user_connections.get(uid, set()))
                    for ws in sockets:
                        try:
                            await ws.send_json(clean_payload)
                        except Exception:
                            pass

        except asyncio.CancelledError:
            logger.info("Redis Pub/Sub listener cancelled for graceful shutdown.")
            break
        except Exception as exc:
            logger.warning("Redis Pub/Sub listener connection lost (%s). Retrying in 5s...", exc)
            await asyncio.sleep(5)
        finally:
            if _pubsub_client:
                try:
                    await _pubsub_client.aclose()
                except Exception:
                    pass


def start_redis_pubsub_listener(manager: Optional[ConnectionManager] = None) -> Optional[asyncio.Task]:
    """Start the background Redis pub/sub listener task inside the running event loop."""
    global _pubsub_task
    mgr = manager or ws_manager
    if _pubsub_task is None or _pubsub_task.done():
        try:
            loop = asyncio.get_running_loop()
            _pubsub_task = loop.create_task(redis_ws_pubsub_listener(mgr))
            return _pubsub_task
        except RuntimeError:
            logger.warning("No running event loop to start Redis Pub/Sub listener.")
    return _pubsub_task


async def stop_redis_pubsub_listener() -> None:
    """Stop the background Redis pub/sub listener task cleanly."""
    global _pubsub_task, _pubsub_client
    if _pubsub_task and not _pubsub_task.done():
        _pubsub_task.cancel()
        try:
            await _pubsub_task
        except (asyncio.CancelledError, Exception):
            pass
        _pubsub_task = None
    if _pubsub_client:
        try:
            await _pubsub_client.aclose()
        except Exception:
            pass
        _pubsub_client = None


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
