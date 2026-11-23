from __future__ import annotations

import json
import uuid
from typing import Dict, Union

from fastapi.websockets import WebSocket, WebSocketDisconnect

MessageType = Union[str, bytes, dict]


class ConnectionManager:
    """Simple in-memory WebSocket connection manager."""

    def __init__(self) -> None:
        self.active: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active[connection_id] = websocket
        return connection_id

    async def disconnect(self, connection_id: str) -> None:
        websocket = self.active.pop(connection_id, None)
        if websocket is None:
            return
        try:
            await websocket.close()
        except WebSocketDisconnect:
            pass
        except Exception:
            pass

    async def send(self, connection_id: str, data: MessageType) -> None:
        websocket = self.active.get(connection_id)
        if websocket is None:
            return
        serialized = self._serialize(data)
        try:
            if isinstance(serialized, bytes):
                await websocket.send_bytes(serialized)
            else:
                await websocket.send_text(serialized)
        except WebSocketDisconnect:
            self.active.pop(connection_id, None)
        except Exception:
            self.active.pop(connection_id, None)

    async def broadcast(self, data: MessageType) -> None:
        connection_ids = list(self.active.keys())
        for connection_id in connection_ids:
            await self.send(connection_id, data)

    def _serialize(self, data: MessageType) -> Union[str, bytes]:
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data
        return json.dumps(data)


__all__ = ["ConnectionManager"]
