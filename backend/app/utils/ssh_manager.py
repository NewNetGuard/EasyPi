"""
SSH Manager for Cloud VPN

Handles SSH connections to remote VPS servers for WireGuard installation and management.
"""

import paramiko
import io
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class SSHManager:
    """Manage SSH connections to VPS servers"""
    
    def __init__(self, host: str, port: int, username: str, 
                 password: Optional[str] = None, ssh_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssh_key = ssh_key
        self.client: Optional[paramiko.SSHClient] = None
        
    def connect(self) -> None:
        """Establish SSH connection to VPS"""
        try:
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
            
            if self.ssh_key:
                # Use SSH key for authentication
                key_file = io.StringIO(self.ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
                
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=pkey,
                    timeout=30,
                    look_for_keys=False,
                    allow_agent=False
                )
            else:
                # Use password authentication
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=30,
                    look_for_keys=False,
                    allow_agent=False
                )
            
            logger.info(f"SSH connection established to {self.host}")
            
        except paramiko.AuthenticationException:
            raise Exception("Authentication failed. Check credentials.")
        except paramiko.SSHException as e:
            raise Exception(f"SSH connection error: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to connect to VPS: {str(e)}")
    
    def execute_command(self, command: str, timeout: int = 300) -> Tuple[int, str, str]:
        """
        Execute command on remote server
        
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self.client:
            raise Exception("SSH client not connected")
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            
            stdout_text = stdout.read().decode('utf-8')
            stderr_text = stderr.read().decode('utf-8')
            
            command_name = command.lstrip().split(None, 1)[0] if command.strip() else "unknown"
            logger.debug(
                "Remote command completed: name=%s exit_code=%s stdout_bytes=%s",
                command_name.rsplit("/", 1)[-1],
                exit_code,
                len(stdout_text.encode("utf-8", errors="ignore")),
            )
            
            return exit_code, stdout_text, stderr_text
            
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            raise Exception(f"Failed to execute command: {str(e)}")
    
    def upload_file(
        self,
        local_content: str,
        remote_path: str,
        mode: int = 0o600,
    ) -> None:
        """Upload file content to a remote path with a private mode."""
        if not self.client:
            raise Exception("SSH client not connected")
        if mode not in {0o600, 0o700}:
            raise ValueError("Remote upload mode must be 0600 or 0700")
        
        try:
            sftp = self.client.open_sftp()
            
            # Write content to remote file
            with sftp.file(remote_path, 'w') as remote_file:
                remote_file.write(local_content)
            
            sftp.chmod(remote_path, mode)
            
            sftp.close()
            logger.info(f"File uploaded to {remote_path}")
            
        except Exception as e:
            logger.error(f"File upload failed: {str(e)}")
            raise Exception(f"Failed to upload file: {str(e)}")
    
    def download_file(self, remote_path: str) -> str:
        """Download file from remote server"""
        if not self.client:
            raise Exception("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            
            with sftp.file(remote_path, 'r') as remote_file:
                content = remote_file.read().decode('utf-8')
            
            sftp.close()
            logger.info(f"File downloaded from {remote_path}")
            
            return content
            
        except Exception as e:
            logger.error(f"File download failed: {str(e)}")
            raise Exception(f"Failed to download file: {str(e)}")
    
    def download_binary(self, remote_path: str) -> bytes:
        """Download binary file (like PNG) from remote server"""
        if not self.client:
            raise Exception("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            
            with sftp.file(remote_path, 'rb') as remote_file:
                content = remote_file.read()
            
            sftp.close()
            logger.info(f"Binary file downloaded from {remote_path}")
            
            return content
            
        except Exception as e:
            logger.error(f"Binary file download failed: {str(e)}")
            raise Exception(f"Failed to download binary file: {str(e)}")
    
    def file_exists(self, remote_path: str) -> bool:
        """Check if file exists on remote server"""
        if not self.client:
            raise Exception("SSH client not connected")
        
        try:
            sftp = self.client.open_sftp()
            try:
                sftp.stat(remote_path)
                sftp.close()
                return True
            except FileNotFoundError:
                sftp.close()
                return False
        except Exception as e:
            logger.error(f"File check failed: {str(e)}")
            return False
    
    def close(self) -> None:
        """Close SSH connection"""
        if self.client:
            self.client.close()
            logger.info(f"SSH connection closed to {self.host}")
            self.client = None
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
