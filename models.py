from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')  # admin, user
    name = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.Float, nullable=True)  # 使用时间戳存储
    last_login = db.Column(db.Float, nullable=True)  # 使用时间戳存储

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    ip_address = db.Column(db.String(15), index=True, unique=True)
    device_type = db.Column(db.String(32))  # router, switch, server, etc.
    status = db.Column(db.String(16), default='unknown')  # online, offline, warning, error
    snmp_community = db.Column(db.String(64), nullable=True)
    snmp_port = db.Column(db.Integer, default=161)
    location = db.Column(db.String(128), nullable=True)
    description = db.Column(db.Text, nullable=True)
    last_seen = db.Column(db.Float, nullable=True)  # timestamp
    os_type = db.Column(db.String(32), nullable=True)  # linux, ios, windows等
    os_version = db.Column(db.String(64), nullable=True)  # 操作系统版本

    network_data = db.relationship('NetworkData', backref='device', lazy='dynamic')
    alerts = db.relationship('Alert', backref='device', lazy='dynamic')

    def __repr__(self):
        return f'<Device {self.name} ({self.ip_address})>'

class NetworkData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    timestamp = db.Column(db.Float, index=True)  # 使用时间戳便于数据处理
    cpu_usage = db.Column(db.Float, default=0)  # 百分比
    memory_usage = db.Column(db.Float, default=0)  # 百分比
    bandwidth_usage = db.Column(db.Float, default=0)  # Mbps
    packet_loss = db.Column(db.Float, default=0)  # 百分比
    latency = db.Column(db.Float, default=0)  # 毫秒
    
    # 可以根据需要添加更多监控指标
    interface_status = db.Column(db.Text, nullable=True)  # JSON格式存储接口状态
    system_uptime = db.Column(db.Float, nullable=True)  # 系统运行时间（秒）
    error_count = db.Column(db.Integer, default=0)  # 错误计数
    
    def __repr__(self):
        return f'<NetworkData for Device {self.device_id} at {self.timestamp}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    timestamp = db.Column(db.Float, index=True)
    alert_type = db.Column(db.String(32))  # cpu_high, memory_high, offline, etc.
    message = db.Column(db.Text)
    severity = db.Column(db.String(16))  # info, warning, error, critical
    resolved = db.Column(db.Boolean, default=False)
    resolved_time = db.Column(db.Float, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Alert {self.id}: {self.alert_type} for Device {self.device_id}>'
