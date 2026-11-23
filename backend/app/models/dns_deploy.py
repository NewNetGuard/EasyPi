"""
DNS Deploy model for storing remote VPS deployments
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON
from app.utils.time import utc_now
from .base import Base


class DNSDeploy(Base):
    """DNS server deployment configuration and results"""
    __tablename__ = "dns_deploys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    
    # VPS information
    vps_ip = Column(String(45), nullable=False)  # IPv4 or IPv6
    ssh_user = Column(String(100), nullable=False, default="root")
    ssh_port = Column(Integer, nullable=False, default=22)
    domain = Column(String(255), nullable=True)
    
    # Deployment results
    dns_ipv4 = Column(String(45), nullable=True)
    dns_ipv6 = Column(String(45), nullable=True)
    admin_url = Column(String(512), nullable=True)
    doh_url = Column(String(512), nullable=True)
    dot_address = Column(String(255), nullable=True)
    wireguard_installed = Column(Boolean, nullable=False, default=False)
    
    # Status
    status = Column(String(50), nullable=False, default="deployed")  # deployed, failed, removed
    deployment_date = Column(DateTime, nullable=False, default=utc_now)
    last_check = Column(DateTime, nullable=True)
    is_online = Column(Boolean, nullable=True)
    
    # Additional data
    warnings = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    deployment_log = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<DNSDeploy(id={self.id}, vps_ip={self.vps_ip}, status={self.status})>"
