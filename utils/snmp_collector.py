from pysnmp.hlapi import *
import time
import logging

logger = logging.getLogger(__name__)

class SNMPCollector:
    """
    SNMP数据收集器，用于通过SNMP协议从网络设备收集监控数据
    """

    def __init__(self):
        logger.info("初始化SNMP数据收集器")

    def collect(self, ip_address, community, port=161):
        """
        从指定IP地址的设备收集SNMP数据
        
        Args:
            ip_address: 设备IP地址
            community: SNMP社区字符串
            port: SNMP端口，默认161
            
        Returns:
            dict: 收集到的数据字典
        """
        try:
            logger.info(f"从 {ip_address} 收集SNMP数据")
            data = {}
            
            # 收集CPU使用率 - OID for CPU utilization
            cpu_usage = self._get_snmp_value(ip_address, community, '1.3.6.1.4.1.9.9.109.1.1.1.1.5.1', port)
            if cpu_usage is not None:
                data['cpu_usage'] = float(cpu_usage)
            
            # 收集内存使用率 - OID for memory utilization
            memory_used = self._get_snmp_value(ip_address, community, '1.3.6.1.4.1.9.9.48.1.1.1.5.1', port)
            memory_free = self._get_snmp_value(ip_address, community, '1.3.6.1.4.1.9.9.48.1.1.1.6.1', port)
            
            if memory_used is not None and memory_free is not None:
                memory_used = float(memory_used)
                memory_free = float(memory_free)
                total_memory = memory_used + memory_free
                if total_memory > 0:
                    data['memory_usage'] = (memory_used / total_memory) * 100
            
            # 收集接口带宽使用率
            # 获取接口列表
            interfaces = self._get_interfaces(ip_address, community, port)
            
            total_in_octets = 0
            total_out_octets = 0
            max_bandwidth = 0
            
            # 计算总带宽使用
            for if_index in interfaces:
                # 获取接口入流量
                in_octets = self._get_snmp_value(ip_address, community, f'1.3.6.1.2.1.2.2.1.10.{if_index}', port)
                # 获取接口出流量
                out_octets = self._get_snmp_value(ip_address, community, f'1.3.6.1.2.1.2.2.1.16.{if_index}', port)
                # 获取接口速度
                speed = self._get_snmp_value(ip_address, community, f'1.3.6.1.2.1.2.2.1.5.{if_index}', port)
                
                if in_octets is not None and out_octets is not None and speed is not None:
                    total_in_octets += float(in_octets)
                    total_out_octets += float(out_octets)
                    max_bandwidth += float(speed)
            
            # 计算总带宽使用率
            if max_bandwidth > 0:
                # 计算总带宽使用率（入流量 + 出流量）/ 最大带宽
                bandwidth_usage = ((total_in_octets + total_out_octets) / max_bandwidth) * 100
                data['bandwidth_usage'] = bandwidth_usage
            
            # 模拟packet_loss和latency数据（实际应使用ping或其他方法测量）
            data['packet_loss'] = self._simulate_packet_loss(ip_address)
            data['latency'] = self._simulate_latency(ip_address)
            
            logger.info(f"从 {ip_address} 收集到数据: {data}")
            return data
            
        except Exception as e:
            logger.error(f"从 {ip_address} 收集SNMP数据出错: {str(e)}")
            # 返回带有默认值的字典，避免数据缺失
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'bandwidth_usage': 0,
                'packet_loss': 0,
                'latency': 0
            }
    
    def _get_snmp_value(self, ip_address, community, oid, port=161):
        """
        获取单个SNMP OID的值
        
        Args:
            ip_address: 设备IP地址
            community: SNMP社区字符串
            oid: 要查询的OID
            port: SNMP端口，默认161
            
        Returns:
            str: SNMP值，如果无法获取则返回None
        """
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(SnmpEngine(),
                       CommunityData(community),
                       UdpTransportTarget((ip_address, port)),
                       ContextData(),
                       ObjectType(ObjectIdentity(oid)))
            )
            
            if error_indication:
                logger.error(f"SNMP错误: {error_indication}")
                return None
            elif error_status:
                logger.error(f"SNMP错误状态: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}")
                return None
            else:
                # 返回值
                for var_bind in var_binds:
                    return var_bind[1].prettyPrint()
            
            return None
        except Exception as e:
            logger.error(f"获取SNMP值出错: {str(e)}")
            return None
    
    def _get_interfaces(self, ip_address, community, port=161):
        """
        获取设备的接口列表
        
        Args:
            ip_address: 设备IP地址
            community: SNMP社区字符串
            port: SNMP端口，默认161
            
        Returns:
            list: 接口索引列表
        """
        interfaces = []
        
        try:
            # 遍历接口表
            for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip_address, port)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.1')),  # ifIndex
                lexicographicMode=False
            ):
                if error_indication:
                    logger.error(f"SNMP错误: {error_indication}")
                    break
                elif error_status:
                    logger.error(f"SNMP错误状态: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}")
                    break
                else:
                    for var_bind in var_binds:
                        interfaces.append(var_bind[1].prettyPrint())
            
            return interfaces
        except Exception as e:
            logger.error(f"获取接口列表出错: {str(e)}")
            return []
    
    def _simulate_packet_loss(self, ip_address):
        """
        模拟获取丢包率（在实际应用中应使用ping或其他方法测量）
        
        Args:
            ip_address: 设备IP地址
            
        Returns:
            float: 模拟的丢包率
        """
        # 在实际应用中，应该使用ping命令或其他方法来测量丢包率
        # 这里仅作为示例，返回一个随机值
        import random
        return random.uniform(0, 10)
    
    def _simulate_latency(self, ip_address):
        """
        模拟获取延迟（在实际应用中应使用ping或其他方法测量）
        
        Args:
            ip_address: 设备IP地址
            
        Returns:
            float: 模拟的延迟（毫秒）
        """
        # 在实际应用中，应该使用ping命令或其他方法来测量延迟
        # 这里仅作为示例，返回一个随机值
        import random
        return random.uniform(1, 200)
