import logging
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict
from models import db, Device, NetworkData, Alert
from utils.alert_manager import AlertManager

class NetworkAnalyzer:
    """网络数据分析与智能建议模块"""
    
    def __init__(self, alert_manager=None):
        self.logger = logging.getLogger(__name__)
        self.alert_manager = alert_manager or AlertManager()
        
    def analyze_network_health(self):
        """分析整体网络健康状态并返回概要信息"""
        try:
            # 获取设备状态统计
            devices = Device.query.all()
            total_devices = len(devices)
            
            if total_devices == 0:
                return {
                    "status": "unknown",
                    "score": 0,
                    "device_status": {"total": 0},
                    "recommendations": ["请添加设备以开始监控网络"]
                }
            
            status_counts = defaultdict(int)
            for device in devices:
                status_counts[device.status] += 1
            
            # 计算健康评分 (0-100)
            health_score = 100
            if status_counts.get('error', 0) > 0:
                health_score -= min(40, status_counts['error'] * 10)
            if status_counts.get('warning', 0) > 0:
                health_score -= min(30, status_counts['warning'] * 5)
            if status_counts.get('offline', 0) > 0:
                health_score -= min(20, status_counts['offline'] * 3)
            
            # 确定整体状态
            overall_status = "healthy"
            if health_score < 60:
                overall_status = "critical"
            elif health_score < 80:
                overall_status = "warning"
            
            # 生成建议
            recommendations = self._generate_recommendations(devices, status_counts, health_score)
            
            return {
                "status": overall_status,
                "score": health_score,
                "device_status": {
                    "total": total_devices,
                    "online": status_counts.get('online', 0),
                    "offline": status_counts.get('offline', 0),
                    "warning": status_counts.get('warning', 0),
                    "error": status_counts.get('error', 0),
                },
                "recommendations": recommendations
            }
        except Exception as e:
            self.logger.error(f"分析网络健康状态时出错: {str(e)}")
            return {
                "status": "unknown",
                "score": 0,
                "device_status": {},
                "recommendations": ["分析过程中发生错误，请检查系统日志"]
            }
    
    def analyze_device_performance(self, device_id, time_range='day'):
        """分析特定设备的性能并提供建议"""
        try:
            device = Device.query.get(device_id)
            if not device:
                return {"error": "设备不存在"}
            
            # 确定时间范围
            now = datetime.now()
            if time_range == 'hour':
                start_time = now - timedelta(hours=1)
            elif time_range == 'day':
                start_time = now - timedelta(days=1)
            elif time_range == 'week':
                start_time = now - timedelta(weeks=1)
            elif time_range == 'month':
                start_time = now - timedelta(days=30)
            else:
                start_time = now - timedelta(days=1)  # 默认为一天
            
            # 获取设备数据
            data = NetworkData.query.filter(
                NetworkData.device_id == device_id,
                NetworkData.timestamp >= start_time.timestamp()
            ).all()
            
            if not data:
                return {
                    "device_name": device.name,
                    "status": device.status,
                    "analysis": "没有足够的数据进行分析",
                    "recommendations": ["开始收集数据以获取性能分析"]
                }
            
            # 分析数据
            cpu_values = [d.cpu_usage for d in data if d.cpu_usage is not None]
            memory_values = [d.memory_usage for d in data if d.memory_usage is not None]
            latency_values = [d.latency for d in data if d.latency is not None]
            
            analysis = {
                "device_name": device.name,
                "status": device.status,
                "data_points": len(data),
                "time_range": time_range,
                "cpu": self._analyze_metric(cpu_values, "CPU使用率", 80, 90),
                "memory": self._analyze_metric(memory_values, "内存使用率", 80, 90),
                "latency": self._analyze_metric(latency_values, "网络延迟", 100, 200, reverse=True)
            }
            
            # 生成设备特定建议
            recommendations = []
            
            if analysis["cpu"]["status"] == "critical":
                recommendations.append(f"CPU使用率过高（平均{analysis['cpu']['avg']}%），建议检查负载并考虑升级")
            elif analysis["cpu"]["status"] == "warning":
                recommendations.append(f"CPU使用率较高（平均{analysis['cpu']['avg']}%），建议监控负载趋势")
                
            if analysis["memory"]["status"] == "critical":
                recommendations.append(f"内存使用率过高（平均{analysis['memory']['avg']}%），建议增加内存或优化应用")
            elif analysis["memory"]["status"] == "warning":
                recommendations.append(f"内存使用率较高（平均{analysis['memory']['avg']}%），建议关注内存使用趋势")
                
            if analysis["latency"]["status"] == "critical":
                recommendations.append(f"网络延迟过高（平均{analysis['latency']['avg']}ms），建议检查网络连接和路由")
            elif analysis["latency"]["status"] == "warning":
                recommendations.append(f"网络延迟较高（平均{analysis['latency']['avg']}ms），建议监控网络性能")
                
            if device.ssh_enabled and not device.ssh_last_connected:
                recommendations.append("SSH已启用但无法连接，请检查SSH配置和凭据")
                
            # 添加设备类型特定建议
            if device.device_type == 'router':
                recommendations.append("定期检查路由表和ACL配置，确保路由效率和安全性")
            elif device.device_type == 'switch':
                recommendations.append("建议定期检查端口状态和VLAN配置，确保网络分段合理")
            elif device.device_type == 'firewall':
                recommendations.append("定期审查防火墙规则，移除过时规则，确保安全策略最新")
                
            # 如果没有特定建议，添加一般性建议
            if not recommendations:
                recommendations.append("设备性能正常，继续保持现有配置")
                
            analysis["recommendations"] = recommendations
            return analysis
            
        except Exception as e:
            self.logger.error(f"分析设备性能时出错 (ID: {device_id}): {str(e)}")
            return {"error": f"分析过程中发生错误: {str(e)}"}
    
    def get_optimization_suggestions(self):
        """获取网络优化建议"""
        try:
            # 查找所有设备
            devices = Device.query.all()
            if not devices:
                return ["尚未添加任何设备，请添加设备以获取优化建议"]
            
            # 获取最近的告警
            recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()
            
            # 分析设备和告警数据，生成优化建议
            suggestions = []
            
            # 基于设备类型和状态的建议
            device_types = defaultdict(list)
            for device in devices:
                device_types[device.device_type].append(device)
            
            # 检查是否有离线设备
            offline_devices = [d for d in devices if d.status == 'offline']
            if offline_devices:
                suggestions.append(f"发现{len(offline_devices)}台离线设备，建议检查网络连接或设备状态")
            
            # 检查告警模式
            if recent_alerts:
                alert_devices = defaultdict(int)
                alert_types = defaultdict(int)
                
                for alert in recent_alerts:
                    alert_devices[alert.device_id] += 1
                    alert_types[alert.alert_type] += 1
                
                # 查找告警最多的设备
                if alert_devices:
                    max_alerts_device_id = max(alert_devices, key=alert_devices.get)
                    max_alerts_device = Device.query.get(max_alerts_device_id)
                    if max_alerts_device and alert_devices[max_alerts_device_id] > 3:
                        suggestions.append(f"设备 '{max_alerts_device.name}' 产生了大量告警，建议优先检查")
                
                # 分析常见告警类型
                if alert_types:
                    most_common_alert = max(alert_types, key=alert_types.get)
                    if most_common_alert == 'high_cpu':
                        suggestions.append("多个设备报告CPU使用率高，建议检查网络负载或升级硬件")
                    elif most_common_alert == 'high_memory':
                        suggestions.append("多个设备报告内存使用率高，建议检查内存泄漏或增加内存容量")
                    elif most_common_alert == 'high_latency':
                        suggestions.append("网络延迟较高，建议检查网络拥塞点或优化路由")
            
            # 基于设备类型的通用建议
            if 'router' in device_types and len(device_types['router']) > 1:
                suggestions.append("检测到多个路由器，建议审查路由策略确保最佳路径选择")
                
            if 'switch' in device_types and len(device_types['switch']) > 3:
                suggestions.append("交换机数量较多，建议检查网络拓扑并考虑简化网络结构")
                
            if 'firewall' in device_types:
                suggestions.append("建议定期审查防火墙规则，移除冗余规则以提高性能")
            
            # 如果建议太少，添加一些通用建议
            if len(suggestions) < 3:
                suggestions.append("定期备份网络设备配置，确保出现问题时能快速恢复")
                suggestions.append("实施网络分段策略，隔离不同安全级别的系统")
                suggestions.append("建立基线性能指标，便于识别异常性能变化")
            
            return suggestions
            
        except Exception as e:
            self.logger.error(f"生成网络优化建议时出错: {str(e)}")
            return ["生成优化建议时发生错误，请检查系统日志"]
    
    def _analyze_metric(self, values, metric_name, warning_threshold, critical_threshold, reverse=False):
        """分析特定指标，确定状态和趋势"""
        if not values:
            return {
                "status": "unknown",
                "avg": None,
                "max": None,
                "min": None,
                "trend": "unknown"
            }
        
        avg_value = sum(values) / len(values)
        max_value = max(values)
        min_value = min(values)
        
        # 确定状态
        if reverse:
            # 对于延迟等指标，值越低越好
            status = "healthy"
            if avg_value > critical_threshold:
                status = "critical"
            elif avg_value > warning_threshold:
                status = "warning"
        else:
            # 对于CPU、内存等指标，值越高越差
            status = "healthy"
            if avg_value > critical_threshold:
                status = "critical"
            elif avg_value > warning_threshold:
                status = "warning"
        
        # 简单趋势分析（仅适用于有足够数据点的情况）
        trend = "stable"
        if len(values) >= 5:
            # 比较后半部分和前半部分的平均值
            mid_point = len(values) // 2
            avg_first_half = sum(values[:mid_point]) / mid_point
            avg_second_half = sum(values[mid_point:]) / (len(values) - mid_point)
            
            difference_pct = (avg_second_half - avg_first_half) / avg_first_half * 100 if avg_first_half > 0 else 0
            
            if abs(difference_pct) < 5:
                trend = "stable"
            elif difference_pct > 0:
                trend = "increasing"
            else:
                trend = "decreasing"
        
        return {
            "status": status,
            "avg": round(avg_value, 2),
            "max": round(max_value, 2),
            "min": round(min_value, 2),
            "trend": trend
        }
    
    def _generate_recommendations(self, devices, status_counts, health_score):
        """根据网络状态生成通用建议"""
        recommendations = []
        
        # 基于健康评分的建议
        if health_score < 60:
            recommendations.append("网络健康状况堪忧，建议立即检查处于警告和错误状态的设备")
        elif health_score < 80:
            recommendations.append("网络健康状况一般，建议关注处于警告状态的设备，防止问题扩大")
        else:
            recommendations.append("网络整体健康状况良好，建议保持当前配置和监控")
        
        # 基于设备状态的建议
        if status_counts.get('error', 0) > 0:
            recommendations.append(f"有{status_counts['error']}台设备处于错误状态，建议优先处理")
            
        if status_counts.get('offline', 0) > 0:
            recommendations.append(f"有{status_counts['offline']}台设备离线，建议检查连接状态和网络可达性")
            
        if status_counts.get('warning', 0) > 0:
            recommendations.append(f"有{status_counts['warning']}台设备处于警告状态，建议在问题扩大前处理")
        
        # 根据设备类型分布的建议
        device_types = defaultdict(int)
        for device in devices:
            device_types[device.device_type] += 1
        
        # 查找SSH配置不当的设备
        ssh_issues = 0
        for device in devices:
            if device.ssh_enabled and not device.ssh_last_connected:
                ssh_issues += 1
        
        if ssh_issues > 0:
            recommendations.append(f"有{ssh_issues}台设备启用了SSH但无法连接，请检查SSH配置")
            
        # 通用最佳实践建议
        if len(recommendations) < 3:
            recommendations.append("定期检查网络设备固件是否需要更新，及时应用安全补丁")
            recommendations.append("实施网络监控基线，便于及时发现性能异常")
        
        return recommendations

    def _generate_device_recommendations(self, device, data):
        """为单个设备生成优化建议"""
        recommendations = []
        
        # 根据设备数据生成建议
        if data.get('cpu_util', 0) > 80:
            recommendations.append(f"设备CPU使用率较高 ({data.get('cpu_util')}%)，建议检查进程负载或考虑升级硬件")
        
        if data.get('memory_util', 0) > 80:
            recommendations.append(f"设备内存使用率较高 ({data.get('memory_util')}%)，建议优化内存使用或增加内存容量")
            
        if data.get('latency', 0) > 100:
            recommendations.append(f"设备网络延迟较高 ({data.get('latency')}ms)，建议检查网络链路或优化流量")
            
        # 如果没有具体建议，提供一般性建议
        if not recommendations:
            if device.status == 'online':
                recommendations.append("设备运行正常，建议定期更新固件并进行安全检查")
            elif device.status == 'offline':
                recommendations.append("设备当前离线，请检查物理连接和设备电源")
            elif device.status == 'warning':
                recommendations.append("设备处于警告状态，请查看详细警报信息")
            elif device.status == 'error':
                recommendations.append("设备处于错误状态，需要立即关注")
                
        return recommendations
        
    def diagnose_network_issue(self, device_id, issue_description):
        """
        诊断特定设备的网络问题并提供解决方案
        
        Args:
            device_id: 设备ID
            issue_description: 问题描述
            
        Returns:
            dict: 包含诊断结果和建议的字典
        """
        try:
            device = Device.query.get(device_id)
            if not device:
                return {
                    "success": False,
                    "message": "未找到设备",
                    "diagnosis": None,
                    "recommendations": []
                }
                
            # 获取最近的设备数据
            recent_data = NetworkData.query.filter_by(device_id=device_id).order_by(NetworkData.timestamp.desc()).first()
            
            # 获取最近的告警
            recent_alerts = Alert.query.filter_by(device_id=device_id, resolved=False).all()
            
            # 根据问题描述和设备数据进行诊断
            diagnosis = self._analyze_issue(device, recent_data, recent_alerts, issue_description)
            
            # 生成解决方案建议
            recommendations = self._generate_solution_recommendations(device, diagnosis, recent_data)
            
            return {
                "success": True,
                "device_name": device.name,
                "device_type": device.device_type,
                "device_status": device.status,
                "diagnosis": diagnosis,
                "recommendations": recommendations
            }
            
        except Exception as e:
            self.logger.error(f"诊断网络问题时出错: {str(e)}")
            return {
                "success": False,
                "message": f"诊断过程中出错: {str(e)}",
                "diagnosis": None,
                "recommendations": ["请检查设备连接并稍后重试"]
            }
            
    def _analyze_issue(self, device, recent_data, alerts, issue_description):
        """分析设备问题并生成诊断结果"""
        issue_keywords = {
            "慢": ["带宽不足", "网络拥塞", "路由延迟", "服务质量问题"],
            "断开": ["物理连接问题", "认证失败", "IP地址冲突", "DHCP问题"],
            "延迟": ["网络拥塞", "路由器配置不当", "带宽限制", "DNS解析延迟"],
            "丢包": ["网络拥塞", "硬件故障", "路由配置错误", "MTU设置不当"],
            "不稳定": ["信号干扰", "硬件故障", "路由器过热", "固件问题"],
            "连接失败": ["认证错误", "安全策略阻止", "IP地址冲突", "物理连接问题"],
            "上传": ["上行带宽限制", "QoS配置", "ISP限流", "硬件性能不足"],
            "下载": ["下行带宽限制", "DNS问题", "服务器负载过高", "网络拥塞"],
            "CPU": ["应用程序负载过高", "系统进程异常", "硬件资源不足", "病毒或恶意软件"],
            "内存": ["内存泄漏", "应用程序内存占用过高", "缓存配置不当", "硬件资源不足"],
            "崩溃": ["软件错误", "硬件故障", "兼容性问题", "过热"],
            "重启": ["电源问题", "硬件故障", "固件错误", "内存溢出"]
        }
        
        # 根据问题描述和关键词匹配可能的问题
        possible_issues = []
        for keyword, issues in issue_keywords.items():
            if keyword in issue_description:
                possible_issues.extend(issues)
                
        if not possible_issues:
            possible_issues = ["未能匹配特定问题模式，需要进一步分析"]
        
        # 分析设备状态和数据
        status_analysis = ""
        if device.status == "error":
            status_analysis = "设备当前处于错误状态，"
        elif device.status == "warning":
            status_analysis = "设备当前处于警告状态，"
        elif device.status == "offline":
            status_analysis = "设备当前离线，"
        else:
            status_analysis = "设备当前在线，"
            
        # 分析设备数据
        data_analysis = ""
        if recent_data:
            if getattr(recent_data, 'cpu_util', 0) > 80:
                data_analysis += f"CPU使用率高 ({recent_data.cpu_util}%)，"
            if getattr(recent_data, 'memory_util', 0) > 80:
                data_analysis += f"内存使用率高 ({recent_data.memory_util}%)，"
            if getattr(recent_data, 'latency', 0) > 100:
                data_analysis += f"网络延迟高 ({recent_data.latency}ms)，"
            if getattr(recent_data, 'packet_loss', 0) > 2:
                data_analysis += f"存在明显丢包 ({recent_data.packet_loss}%)，"
                
        # 分析告警
        alerts_analysis = ""
        if alerts:
            alerts_analysis = f"存在{len(alerts)}个未解决的告警，"
            
        # 组合诊断结果
        final_diagnosis = f"{status_analysis}{data_analysis}{alerts_analysis}可能的问题包括: {', '.join(possible_issues[:3])}"
        return final_diagnosis
        
    def _generate_solution_recommendations(self, device, diagnosis, recent_data):
        """根据诊断生成解决方案建议"""
        recommendations = []
        
        # 根据诊断中的关键词生成建议
        if "带宽不足" in diagnosis or "网络拥塞" in diagnosis:
            recommendations.append("检查网络带宽使用情况，考虑实施QoS策略优先处理关键业务流量")
            recommendations.append("监控网络流量模式，识别并限制非必要的高带宽应用")
            
        if "物理连接问题" in diagnosis:
            recommendations.append("检查网络设备的物理连接，确保线缆完好且正确连接")
            recommendations.append("测试替换网络线缆和接口，排除硬件故障")
            
        if "路由" in diagnosis:
            recommendations.append("检查路由表配置，确保路由条目正确")
            recommendations.append("测试从不同位置到目标的网络路径，识别可能的路由问题")
            
        if "DNS" in diagnosis:
            recommendations.append("检查DNS服务器配置，考虑使用更快的DNS解析服务")
            recommendations.append("实施本地DNS缓存，减少解析延迟")
            
        if "认证" in diagnosis or "安全" in diagnosis:
            recommendations.append("检查网络认证配置和凭据")
            recommendations.append("审核防火墙规则，确保不会阻止合法流量")
            
        if "CPU" in diagnosis:
            recommendations.append("识别并优化占用CPU资源的进程")
            recommendations.append("考虑升级设备硬件或分散负载")
            
        if "内存" in diagnosis:
            recommendations.append("识别并解决可能的内存泄漏问题")
            recommendations.append("优化内存密集型应用或增加设备内存容量")
            
        if "丢包" in diagnosis:
            recommendations.append("检查网络拥塞点和网络接口状态")
            recommendations.append("验证MTU设置是否正确，考虑进行路径MTU发现")
            
        if "固件" in diagnosis:
            recommendations.append("检查并更新设备固件到最新版本")
            recommendations.append("确保固件版本与其他网络设备兼容")
            
        # 如果没有生成特定建议，提供通用建议
        if not recommendations:
            recommendations = [
                "检查设备的物理连接和电源状态",
                "验证网络配置是否符合预期",
                "监控设备性能指标，查看是否存在异常",
                "检查设备日志以获取详细错误信息",
                "考虑重启设备以解决临时性问题"
            ]
            
        return recommendations
