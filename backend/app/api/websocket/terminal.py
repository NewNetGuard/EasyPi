"""
Terminal WebSocket Handler

Provides real PTY (pseudo-terminal) access to the Raspberry Pi via WebSocket.
Supports full terminal features: colors, cursor movement, interactive commands.
Includes JWT authentication, admin role verification, and command audit logging.
"""

import asyncio
import os
import select
import struct
import signal
import logging
import json
import re
import locale
from functools import lru_cache
from app.utils.time import utc_now
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState
from typing import Optional

# Unix-specific imports (not available on Windows)
try:
    import fcntl
    import termios
    HAS_PTY = True
except ImportError:
    HAS_PTY = False

from app.core.terminal_security import terminal_security, check_dangerous_command
from app.core.rate_limit import get_client_ip
from app.db.session import async_session_maker
from app.models.terminal import TerminalSession, TerminalCommand
from app.services.operation_event_service import OperationEventService

logger = logging.getLogger(__name__)

router = APIRouter()
operation_event_service = OperationEventService()

MAX_TERMINAL_INPUT_CHARS = 65_536
MAX_TERMINAL_COMMAND_BUFFER_CHARS = 8_192
MAX_TERMINAL_WS_MESSAGE_CHARS = 131_072
MIN_TERMINAL_COLS = 20
MAX_TERMINAL_COLS = 500
MIN_TERMINAL_ROWS = 5
MAX_TERMINAL_ROWS = 200
TERMINAL_WS_PROTOCOL_PREFIX = "easypi-terminal."
TERMINAL_PROCESS_TERM_GRACE_SECONDS = 0.5
TERMINAL_PROCESS_KILL_WAIT_SECONDS = 0.5
TERMINAL_AUTH_REVALIDATE_INTERVAL_SECONDS = 5.0


def _record_terminal_runtime_event(*, status_value: str, message: str, started_at: str) -> None:
    """Persist bounded handshake/PTY outcomes for later read-only diagnosis."""

    try:
        operation_event_service.record_event(
            action_id="terminal.websocket",
            status=status_value,
            title="Terminal live session",
            subtitle="Terminal - WebSocket/PTY runtime",
            route="/terminal",
            message=str(message or "Terminal runtime event")[:500],
            started_at=started_at,
            updated_at=utc_now().isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record terminal runtime event: %s", exc)


def _get_ws_client_ip(websocket: WebSocket) -> str:
    # WebSocket exposes the same client/headers attributes used by the HTTP helper.
    # Forwarding headers are accepted only from the configured trusted proxy.
    return get_client_ip(websocket)  # type: ignore[arg-type]


def _is_locale_available(name: str) -> bool:
    try:
        current = locale.setlocale(locale.LC_ALL)
    except locale.Error:
        current = "C"

    try:
        locale.setlocale(locale.LC_ALL, name)
        return True
    except locale.Error:
        return False
    finally:
        try:
            locale.setlocale(locale.LC_ALL, current)
        except locale.Error:
            locale.setlocale(locale.LC_ALL, "C")


@lru_cache(maxsize=1)
def _pick_terminal_locale() -> str:
    preferred = [
        "C.UTF-8",
        "C.utf8",
        "en_US.UTF-8",
        "en_US.utf8",
    ]
    for loc in preferred:
        if _is_locale_available(loc):
            return loc

    return "C"


class PTYTerminal:
    """Manages a PTY (pseudo-terminal) session with command logging"""
    
    def __init__(
        self,
        websocket: WebSocket,
        user_id: Optional[int],
        username: str,
        session_id: Optional[int],
    ):
        self.websocket = websocket
        self.master_fd: Optional[int] = None
        self.pid: Optional[int] = None
        self.process: Optional[asyncio.subprocess.Process] = None
        self.running = False
        self.user_id = user_id
        self.username = username
        self.session_id = session_id
        self.command_buffer = ""  # Buffer to detect commands

    def _input_echo_enabled(self) -> bool:
        """Fail closed for auditing when the PTY hides input or cannot be inspected."""
        if not HAS_PTY or self.master_fd is None:
            return False
        try:
            attributes = termios.tcgetattr(self.master_fd)
            return bool(attributes[3] & termios.ECHO)
        except (OSError, termios.error):
            return False
        
    async def log_command(self, command: str):
        """Record command metadata without persisting arguments or secrets."""
        if self.session_id is None:
            return

        is_dangerous, matched_pattern = check_dangerous_command(command)
        stripped = command.strip()
        match = re.match(r"^(?:sudo[ \t]+)?([A-Za-z0-9_./-]+)", stripped)
        command_name = match.group(1).rsplit("/", 1)[-1] if match else "unknown"
        audit_summary = f"{command_name} [length={len(stripped)}]"
        if is_dangerous:
            audit_summary += f" [dangerous={matched_pattern}]"

        try:
            async with async_session_maker() as db:
                terminal_command = TerminalCommand(
                    session_id=self.session_id,
                    command=audit_summary,
                    executed_at=utc_now()
                )
                db.add(terminal_command)
                await db.commit()
                logger.info(
                    "User %s executed terminal command %s",
                    self.username,
                    audit_summary,
                )
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    async def start(self, shell: str = "/bin/bash", cols: int = 80, rows: int = 24):
        """Start PTY with shell using script command for proper PTY"""
        if not HAS_PTY:
            raise RuntimeError("PTY not supported on this platform (Windows). Terminal features require Unix-like OS.")

        master_fd: int | None = None
        slave_fd: int | None = None
        try:
            # Create pipe for communication
            master_fd, slave_fd = os.openpty()
            
            # Get user's home directory
            home_dir = os.path.expanduser("~")

            # Ensure a valid locale in the PTY to avoid bash setlocale warnings.
            env = os.environ.copy()
            # Force C locale to avoid warnings on systems without UTF-8 locales
            env["LANG"] = "C"
            env["LC_ALL"] = "C"
            env.setdefault("TERM", "xterm-256color")
            env.setdefault("COLORTERM", "truecolor")
            
            # Start bash in PTY with home directory as working directory
            self.process = await asyncio.create_subprocess_exec(
                shell,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=home_dir,  # Start in home directory
                env=env,
                preexec_fn=os.setsid,
            )
            
            self.pid = self.process.pid
            self.master_fd = master_fd
            master_fd = None
            self.running = True
            
            # Close slave fd in parent
            os.close(slave_fd)
            slave_fd = None
            
            # Set terminal size
            self.resize(cols, rows)
            
            # Set non-blocking mode
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            logger.info(f"PTY started: pid={self.pid}, fd={self.master_fd}, cwd={home_dir}")
                
        except Exception as e:
            for descriptor in (slave_fd, master_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            await self.stop()
            logger.error("Failed to start PTY: %s", type(e).__name__)
            raise
    
    def resize(self, cols: int, rows: int):
        """Resize terminal window"""
        if self.master_fd is None:
            return
        
        try:
            # TIOCSWINSZ = Terminal I/O Control Set Window Size
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            logger.debug(f"Terminal resized: {cols}x{rows}")
        except Exception as e:
            logger.error(f"Failed to resize terminal: {e}")
    
    async def read_from_pty(self):
        """Read output from PTY and send to WebSocket"""
        loop = asyncio.get_event_loop()
        
        while self.running:
            try:
                # Use select to check if data is available
                readable, _, _ = await loop.run_in_executor(
                    None,
                    select.select,
                    [self.master_fd], [], [], 0.1
                )
                
                if self.master_fd in readable:
                    # Read from PTY
                    data = os.read(self.master_fd, 4096)
                    
                    if data:
                        chunk = data.decode("utf-8", errors="replace")
                        try:
                            await self.websocket.send_json({"type": "output", "data": chunk})
                        except Exception as send_error:
                            logger.error(f"Failed to push PTY output: {send_error}")
                            break
                    else:
                        # PTY closed
                        logger.info("PTY closed (EOF)")
                        break
                        
            except OSError as e:
                if e.errno == 5:  # EIO - process exited
                    logger.info("PTY process exited")
                    break
                logger.error(f"PTY read error: {e}")
                break
            except Exception as e:
                logger.error(f"Error reading from PTY: {e}")
                break
    
    async def write_to_pty(self, data: str):
        """Write input from WebSocket to PTY and detect commands"""
        if (
            self.master_fd is None
            or not self.running
            or not isinstance(data, str)
            or not data
        ):
            return
        if len(data) > MAX_TERMINAL_INPUT_CHARS:
            logger.warning("Rejected oversized terminal input for user %s", self.username)
            return
        
        try:
            # Read ECHO before writing. A password prompt may restore ECHO as
            # soon as it receives Enter, which would be too late to classify
            # this input safely after os.write().
            audit_input = self._input_echo_enabled()
            encoded = data.encode('utf-8')
            os.write(self.master_fd, encoded)

            if not audit_input:
                self.command_buffer = ""
                return
            
            # Detect command execution (when Enter is pressed)
            text = data
            self.command_buffer = (
                self.command_buffer + text
            )[-MAX_TERMINAL_COMMAND_BUFFER_CHARS:]
            
            # If Enter key pressed, log the command
            if '\r' in text or '\n' in text:
                # Clean ANSI escape codes and extra whitespace
                command = re.sub(r'\x1b\[[0-9;]*[mGKHf]', '', self.command_buffer)
                command = command.strip()
                
                # Log non-empty commands
                if command and not command.isspace():
                    await self.log_command(command)
                
                # Reset buffer
                self.command_buffer = ""
                
        except Exception as e:
            logger.error(f"Error writing to PTY: {e}")
    
    def _process_group_exists(self) -> bool:
        if not self.pid:
            return False
        try:
            os.killpg(self.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            logger.error("Lost permission to inspect PTY process group %s", self.pid)
            return True

    async def _wait_for_process_group_exit(self, timeout: float) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        while self._process_group_exists() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)
        return not self._process_group_exists()

    async def stop(self):
        """Stop PTY session"""
        self.running = False

        process_group = self.pid
        if process_group:
            try:
                os.killpg(process_group, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.error("Error terminating PTY process group: %s", type(exc).__name__)

        # The shell may already be reaped while a child in its process group is
        # still alive. Wait on the group itself, then force the complete group
        # down instead of treating the shell's exit as successful cleanup.
        if process_group and not await self._wait_for_process_group_exit(
            TERMINAL_PROCESS_TERM_GRACE_SECONDS
        ):
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.error("Error killing PTY process group: %s", type(exc).__name__)
            await self._wait_for_process_group_exit(TERMINAL_PROCESS_KILL_WAIT_SECONDS)

        if self.process and self.process.returncode is None:
            try:
                await asyncio.wait_for(self.process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                logger.error("PTY process did not exit after process-group termination")
            except Exception as exc:
                logger.error("Error waiting for PTY process: %s", type(exc).__name__)

        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
                logger.info(f"PTY fd {self.master_fd} closed")
            except OSError:
                pass
            finally:
                self.master_fd = None
        self.pid = None
        self.process = None


def _authorized_terminal_user(db, user_id: int, session_jti: str):
    """Return the active admin only while its originating login session is valid."""
    from app.models.session import UserSession
    from app.models.user import User
    from sqlalchemy import select

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user or not user.is_active or user.role != "admin" or not session_jti:
        return None

    login_session = db.execute(
        select(UserSession).where(
            UserSession.token_jti == session_jti,
            UserSession.user_id == user_id,
            UserSession.is_active.is_(True),
        )
    ).scalar_one_or_none()
    if (
        not login_session
        or login_session.revoked_at is not None
        or login_session.expires_at < utc_now()
    ):
        return None
    return user


@router.websocket("/ws/terminal")
async def terminal_websocket_handler(
    websocket: WebSocket,
):
    """
    WebSocket endpoint handler for terminal access.
    
    SECURITY: Requires admin-only terminal token. Connection is rejected if:
    - No token provided
    - Token is invalid/expired
    - User role is not 'admin'
    - Client IP is not allowed
    """
    from app.db.session import get_db
    client_ip = _get_ws_client_ip(websocket)
    user_agent = websocket.headers.get("user-agent", "")
    user_id: Optional[int] = None
    username: str = "unknown"
    session_key: Optional[str] = None
    started_at = utc_now().isoformat()
    requested_protocols = [
        value.strip()
        for value in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if value.strip()
    ]
    terminal_protocols = [
        value for value in requested_protocols if value.startswith(TERMINAL_WS_PROTOCOL_PREFIX)
    ]
    selected_protocol = terminal_protocols[0] if len(terminal_protocols) == 1 else None
    ws_token = (
        selected_protocol.removeprefix(TERMINAL_WS_PROTOCOL_PREFIX)
        if selected_protocol
        else None
    )

    if not user_agent:
        logger.warning("Terminal WS connection rejected - missing User-Agent from %s", client_ip)
        terminal_security.record_failed_attempt(client_ip)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    allowed, reason = terminal_security.is_ip_allowed(client_ip)
    if not allowed:
        logger.warning("Terminal WS connection rejected - IP %s: %s", client_ip, reason)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if not ws_token:
        logger.warning(
            "Terminal WS connection rejected - no token provided from %s",
            websocket.client,
        )
        terminal_security.record_failed_attempt(client_ip)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    token_data, reason = terminal_security.verify_and_consume_token(
        ws_token,
        client_ip,
        user_agent,
    )
    if not token_data:
        logger.warning("Terminal WS connection rejected - %s from %s", reason, client_ip)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id = token_data.user_id
    username = token_data.username
    session_key = token_data.session_fingerprint

    db_context = get_db()
    try:
        db = next(db_context)
        user = _authorized_terminal_user(db, user_id, token_data.session_jti)
    except Exception as exc:
        logger.error("Failed to get user for terminal token: %s", type(exc).__name__)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    finally:
        db_context.close()

    if not user:
        logger.warning(
            "Terminal WS connection rejected - user %s (%s) not authorized",
            username,
            user_id,
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    can_create, reason = terminal_security.try_register_session(user_id, session_key)
    if not can_create:
        logger.warning("Terminal WS connection rejected - %s", reason)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Now safe to accept connection - user is authenticated admin
    try:
        await websocket.accept(subprotocol=selected_protocol)
        logger.info(
            "Terminal WS connection accepted for admin user %s (%s) from %s",
            username,
            user_id,
            websocket.client,
        )
    except Exception as e:
        logger.error(f"Failed to accept WebSocket connection: {e}")
        terminal_security.unregister_session(user_id, session_key)
        _record_terminal_runtime_event(
            status_value="failed",
            message=f"WebSocket accept failed: {type(e).__name__}",
            started_at=started_at,
        )
        return
    
    # Create terminal session in database
    session_id: Optional[int] = None
    if user_id is not None:
        try:
            async with async_session_maker() as db:
                terminal_session = TerminalSession(
                    user_id=user_id,
                    username=username,
                    started_at=utc_now(),
                    ip_address=client_ip if client_ip != "unknown" else None,
                )
                db.add(terminal_session)
                await db.commit()
                await db.refresh(terminal_session)
                session_id = terminal_session.id
                logger.info("Terminal session %s started for %s", session_id, username)
        except Exception as e:
            logger.error("Failed to create terminal session record: %s", e)

    terminal = PTYTerminal(websocket, user_id, username, session_id)
    graceful_shutdown = True
    read_task: Optional[asyncio.Task] = None
    revalidate_task: Optional[asyncio.Task] = None
    
    try:
        # Check if PTY is supported
        if not HAS_PTY:
            logger.warning("PTY not supported on Windows - terminal features unavailable")
            _record_terminal_runtime_event(
                status_value="failed",
                message="PTY is not supported on this platform.",
                started_at=started_at,
            )
            await websocket.send_json({
                "type": "error",
                "message": "Terminal not supported on Windows. Please use Linux/Unix system for PTY features."
            })
            await websocket.close()
            return
        
        # Start PTY with bash
        logger.info(f"Starting PTY for user {username}")
        await terminal.start(shell="/bin/bash", cols=80, rows=24)
        logger.info(f"PTY started successfully for user {username}")
        _record_terminal_runtime_event(
            status_value="success",
            message="Authenticated Terminal WebSocket and PTY started successfully.",
            started_at=started_at,
        )
        
        # Create tasks for reading and writing
        read_task = asyncio.create_task(terminal.read_from_pty())

        # Tear the root shell down if the admin is deactivated / demoted mid-session.
        from app.api.websocket.ws_auth import revalidate_session_periodically
        revalidate_task = asyncio.create_task(
            revalidate_session_periodically(
                websocket,
                user_id=user_id,
                session_jti=token_data.session_jti,
                require_admin=True,
                interval_sec=TERMINAL_AUTH_REVALIDATE_INTERVAL_SECONDS,
            )
        )

        # Handle incoming messages
        while terminal.running:
            try:
                message_text = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                if len(message_text) > MAX_TERMINAL_WS_MESSAGE_CHARS:
                    graceful_shutdown = False
                    await websocket.close(code=status.WS_1009_MESSAGE_TOO_BIG)
                    break
                try:
                    data = json.loads(message_text)
                except json.JSONDecodeError:
                    logger.warning(
                        "Ignoring malformed terminal message (%s characters)",
                        len(message_text),
                    )
                    continue

                if not isinstance(data, dict):
                    logger.warning("Ignoring non-object terminal message")
                    continue

                msg_type = data.get("type")
                if msg_type == "input":
                    await terminal.write_to_pty(data.get("data", ""))
                elif msg_type == "resize":
                    try:
                        cols = max(
                            MIN_TERMINAL_COLS,
                            min(MAX_TERMINAL_COLS, int(data.get("cols", 80))),
                        )
                        rows = max(
                            MIN_TERMINAL_ROWS,
                            min(MAX_TERMINAL_ROWS, int(data.get("rows", 24))),
                        )
                    except (TypeError, ValueError):
                        logger.warning("Ignoring invalid terminal resize message")
                        continue
                    terminal.resize(cols, rows)
            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                graceful_shutdown = False
                logger.info(f"Terminal WebSocket disconnected: {username}")
                break
            except Exception as receive_error:
                graceful_shutdown = False
                logger.error(f"Terminal websocket receive error: {receive_error}")
                break
        
        # Wait for read task to complete
        read_task.cancel()
        revalidate_task.cancel()
        await asyncio.gather(read_task, revalidate_task, return_exceptions=True)
    except Exception as e:
        graceful_shutdown = False
        logger.error(f"Terminal error for user {username}: {e}")
        logger.exception("Full terminal exception:")
        _record_terminal_runtime_event(
            status_value="failed",
            message=f"Terminal WebSocket/PTY failed: {type(e).__name__}",
            started_at=started_at,
        )
        try:
            await websocket.send_json({"type": "error", "message": "INTERNAL_ERROR"})
        except Exception:
            pass
    finally:
        for task in (read_task, revalidate_task):
            if task is not None and not task.done():
                task.cancel()
        pending_tasks = [
            task for task in (read_task, revalidate_task) if task is not None
        ]
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

        await terminal.stop()

        if user_id is not None and session_key:
            terminal_security.unregister_session(user_id, session_key)
        
        # Update session end time
        if session_id is not None:
            try:
                async with async_session_maker() as db:
                    session = await db.get(TerminalSession, session_id)
                    if session:
                        session.ended_at = utc_now()
                        await db.commit()
                        logger.info(f"Terminal session {session_id} ended for user {username}")
            except Exception as e:
                logger.error(f"Failed to update terminal session: {e}")
        
        try:
            if graceful_shutdown and websocket.application_state == WebSocketState.CONNECTED:
                await websocket.send_json({"type": "closed"})
        except Exception:
            graceful_shutdown = False
        
        try:
            if websocket.application_state != WebSocketState.DISCONNECTED:
                await websocket.close()
        except Exception:
            pass
