import logging
import time
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class AlertManager:
    """
    告警管理器，用于监控指标并生成告警
    """
    
    def __init__(self, config=None):
        """
        初始化告警管理器
        
        Args:
            config: 配置字典，用于设置告警阈值
        """
        logger.info("初始化告警管理器")
        self.config = config or {}
        
        # 默认告警阈值
        self.default_thresholds = {
            'cpu_usage': 80,        # CPU使用率超过80%告警
            'memory_usage': 80,     # 内存使用率超过80%告警
            'bandwidth_usage': 90,  # 带宽使用率超过90%告警
            'packet_loss': 5,       # 丢包率超过5%告警
            'latency': 100          # 延迟超过100ms告警
        }
        
        # 告警历史记录
        self.alert_history = {}
        
        # 告警冷却时间（秒）
        self.alert_cooldown = 300  # 5分钟内相同告警不重复发送
    
    def check_alerts(self, device, data):
        """
        检查设备数据是否触发告警
        
        Args:
            device: 设备对象
            data: 监控数据字典
            
        Returns:
            list: 告警列表
        """
        alerts = []
        
        # 获取设备ID
        device_id = getattr(device, 'id', None)
        if device_id is None:
            device_id = device.get('id', str(hash(str(device))))
        
        # 获取设备名称
        device_name = getattr(device, 'name', None)
        if device_name is None:
            device_name = device.get('name', device.get('ip_address', 'Unknown Device'))
        
        # 获取设备IP地址
        ip_address = getattr(device, 'ip_address', None)
        if ip_address is None:
            ip_address = device.get('ip_address', 'unknown')
        
        # 检查设备可达性（如果数据中包含is_reachable字段）
        if 'is_reachable' in data and not data['is_reachable']:
            alert = self._create_alert(
                device_id=device_id,
                device_name=device_name,
                ip_address=ip_address,
                alert_type='device_unreachable',
                message=f"设备 {device_name} ({ip_address}) 无法连通",
                severity='critical',
                data={'is_reachable': False}
            )
            alerts.append(alert)
            return alerts  # 如果设备不可达，返回不可达告警并停止检查其他指标
        
        # 检查CPU使用率
        if 'cpu_usage' in data:
            threshold = self.config.get('ALERT_CPU_THRESHOLD', self.default_thresholds['cpu_usage'])
            if data['cpu_usage'] > threshold:
                alert = self._create_alert(
                    device_id=device_id,
                    device_name=device_name,
                    ip_address=ip_address,
                    alert_type='high_cpu',
                    message=f"设备 {device_name} ({ip_address}) CPU使用率过高: {data['cpu_usage']:.1f}% > {threshold}%",
                    severity='warning' if data['cpu_usage'] < threshold + 10 else 'error',
                    data={'cpu_usage': data['cpu_usage'], 'threshold': threshold}
                )
                alerts.append(alert)
        
        # 检查内存使用率
        if 'memory_usage' in data:
            threshold = self.config.get('ALERT_MEMORY_THRESHOLD', self.default_thresholds['memory_usage'])
            if data['memory_usage'] > threshold:
                alert = self._create_alert(
                    device_id=device_id,
                    device_name=device_name,
                    ip_address=ip_address,
                    alert_type='high_memory',
                    message=f"设备 {device_name} ({ip_address}) 内存使用率过高: {data['memory_usage']:.1f}% > {threshold}%",
                    severity='warning' if data['memory_usage'] < threshold + 10 else 'error',
                    data={'memory_usage': data['memory_usage'], 'threshold': threshold}
                )
                alerts.append(alert)
        
        # 检查带宽使用率
        if 'bandwidth_usage' in data:
            threshold = self.config.get('ALERT_BANDWIDTH_THRESHOLD', self.default_thresholds['bandwidth_usage'])
            if data['bandwidth_usage'] > threshold:
                alert = self._create_alert(
                    device_id=device_id,
                    device_name=device_name,
                    ip_address=ip_address,
                    alert_type='high_bandwidth',
                    message=f"设备 {device_name} ({ip_address}) 带宽使用率过高: {data['bandwidth_usage']:.1f}% > {threshold}%",
                    severity='warning' if data['bandwidth_usage'] < threshold + 5 else 'error',
                    data={'bandwidth_usage': data['bandwidth_usage'], 'threshold': threshold}
                )
                alerts.append(alert)
        
        # 检查丢包率
        if 'packet_loss' in data:
            threshold = self.config.get('ALERT_PACKET_LOSS_THRESHOLD', self.default_thresholds['packet_loss'])
            if data['packet_loss'] > threshold:
                alert = self._create_alert(
                    device_id=device_id,
                    device_name=device_name,
                    ip_address=ip_address,
                    alert_type='high_packet_loss',
                    message=f"设备 {device_name} ({ip_address}) 丢包率过高: {data['packet_loss']:.1f}% > {threshold}%",
                    severity='warning' if data['packet_loss'] < threshold * 2 else 'error',
                    data={'packet_loss': data['packet_loss'], 'threshold': threshold}
                )
                alerts.append(alert)
        
        # 检查延迟
        if 'latency' in data:
            threshold = self.config.get('ALERT_LATENCY_THRESHOLD', self.default_thresholds['latency'])
            if data['latency'] > threshold:
                alert = self._create_alert(
                    device_id=device_id,
                    device_name=device_name,
                    ip_address=ip_address,
                    alert_type='high_latency',
                    message=f"设备 {device_name} ({ip_address}) 延迟过高: {data['latency']:.1f}ms > {threshold}ms",
                    severity='warning' if data['latency'] < threshold * 2 else 'error',
                    data={'latency': data['latency'], 'threshold': threshold}
                )
                alerts.append(alert)
        
        return alerts
    
    def _create_alert(self, device_id, device_name, ip_address, alert_type, message, severity, data=None):
        """
        创建告警对象
        
        Args:
            device_id: 设备ID
            device_name: 设备名称
            ip_address: 设备IP地址
            alert_type: 告警类型
            message: 告警消息
            severity: 告警严重性（info, warning, error, critical）
            data: 告警相关数据
            
        Returns:
            dict: 告警对象
        """
        # 生成告警键，用于去重
        alert_key = f"{device_id}_{alert_type}"
        
        # 检查是否在冷却期内
        current_time = time.time()
        if alert_key in self.alert_history:
            last_alert_time = self.alert_history[alert_key]
            if current_time - last_alert_time < self.alert_cooldown:
                # 告警在冷却期内，跳过
                return None
        
        # 更新告警历史
        self.alert_history[alert_key] = current_time
        
        # 创建告警对象
        alert = {
            'device_id': device_id,
            'device_name': device_name,
            'ip_address': ip_address,
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': current_time,
            'data': data or {}
        }
        
        # 记录告警日志
        log_level = {
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL
        }.get(severity, logging.WARNING)
        
        logger.log(log_level, f"告警: {message}")
        
        return alert
    
    def get_active_alerts(self, device_id=None):
        """
        获取活跃告警列表
        
        Args:
            device_id: 可选的设备ID过滤
            
        Returns:
            list: 活跃告警列表
        """
        # 实际应用中应从数据库中查询活跃告警
        # 这里简单返回一个空列表
        return []
