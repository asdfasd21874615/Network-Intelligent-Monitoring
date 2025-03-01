"""
初始化数据库脚本
用于创建数据库表结构和初始化管理员用户
"""

import os
import sys
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

# 添加项目根目录到sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, Device, NetworkData, Alert

def datetime_to_timestamp(dt):
    """将datetime对象转换为时间戳"""
    return dt.timestamp()

def init_database():
    """初始化数据库"""
    with app.app_context():
        # 创建所有表
        db.create_all()
        
        # 检查是否已有管理员用户
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # 创建默认管理员用户
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role='admin',
                name='系统管理员',
                created_at=datetime_to_timestamp(datetime.now())
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            
            # 创建一些示例设备
            sample_devices = [
                Device(
                    name='核心交换机',
                    ip_address='192.168.1.1',
                    device_type='switch',
                    location='数据中心A区',
                    snmp_community='public',
                    status='up',
                    os_type='ios',
                    os_version='15.2',
                    last_seen=datetime_to_timestamp(datetime.now())
                ),
                Device(
                    name='边界路由器',
                    ip_address='192.168.1.2',
                    device_type='router',
                    location='数据中心A区',
                    snmp_community='public',
                    status='up',
                    os_type='ios',
                    os_version='16.1',
                    last_seen=datetime_to_timestamp(datetime.now())
                ),
                Device(
                    name='办公区交换机',
                    ip_address='192.168.2.1',
                    device_type='switch',
                    location='办公区B区',
                    snmp_community='public',
                    status='up',
                    os_type='ios',
                    os_version='15.1',
                    last_seen=datetime_to_timestamp(datetime.now())
                ),
                Device(
                    name='Web服务器',
                    ip_address='192.168.1.10',
                    device_type='server',
                    location='数据中心A区',
                    snmp_community='public',
                    status='up',
                    os_type='linux',
                    os_version='Ubuntu 22.04',
                    last_seen=datetime_to_timestamp(datetime.now())
                ),
                Device(
                    name='数据库服务器',
                    ip_address='192.168.1.11',
                    device_type='server',
                    location='数据中心A区',
                    snmp_community='public',
                    status='up',
                    os_type='linux',
                    os_version='CentOS 8',
                    last_seen=datetime_to_timestamp(datetime.now())
                ),
            ]
            
            for device in sample_devices:
                db.session.add(device)
            
            # 添加一些示例告警
            sample_alerts = [
                Alert(
                    device_id=1,
                    alert_type='high_cpu',
                    message='CPU使用率超过90%',
                    severity='warning',
                    timestamp=datetime_to_timestamp(datetime.now()),
                    resolved=False
                ),
                Alert(
                    device_id=2,
                    alert_type='high_memory',
                    message='内存使用率超过85%',
                    severity='warning',
                    timestamp=datetime_to_timestamp(datetime.now()),
                    resolved=False
                ),
                Alert(
                    device_id=3,
                    alert_type='device_unreachable',
                    message='设备无法ping通',
                    severity='critical',
                    timestamp=datetime_to_timestamp(datetime.now()),
                    resolved=False
                ),
            ]
            
            for alert in sample_alerts:
                db.session.add(alert)
            
            # 添加一些示例数据
            now = datetime.now()
            for device_id in range(1, 6):
                # 添加CPU使用率数据
                for i in range(12):
                    hour_offset = i
                    timestamp_dt = now.replace(hour=now.hour-hour_offset) if now.hour >= hour_offset else now.replace(hour=24-(hour_offset-now.hour), day=now.day-1)
                    cpu_data = NetworkData(
                        device_id=device_id,
                        cpu_usage=float(30 + i * 5),
                        timestamp=datetime_to_timestamp(timestamp_dt)
                    )
                    db.session.add(cpu_data)
                
                # 添加内存使用率数据
                for i in range(12):
                    hour_offset = i
                    timestamp_dt = now.replace(hour=now.hour-hour_offset) if now.hour >= hour_offset else now.replace(hour=24-(hour_offset-now.hour), day=now.day-1)
                    memory_data = NetworkData(
                        device_id=device_id,
                        memory_usage=float(40 + i * 3),
                        timestamp=datetime_to_timestamp(timestamp_dt)
                    )
                    db.session.add(memory_data)
                
                # 添加带宽使用率数据
                for i in range(12):
                    hour_offset = i
                    timestamp_dt = now.replace(hour=now.hour-hour_offset) if now.hour >= hour_offset else now.replace(hour=24-(hour_offset-now.hour), day=now.day-1)
                    bandwidth_data = NetworkData(
                        device_id=device_id,
                        bandwidth_usage=float(100 + i * 20),
                        timestamp=datetime_to_timestamp(timestamp_dt)
                    )
                    db.session.add(bandwidth_data)
            
            db.session.commit()
            print('数据库初始化完成!')
            print('创建了管理员用户: admin/admin123')
        else:
            print('数据库已存在，未进行初始化。')

if __name__ == '__main__':
    init_database()
