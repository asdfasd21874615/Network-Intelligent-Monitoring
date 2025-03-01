import socket
import subprocess
import platform
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import json
import requests

logger = logging.getLogger(__name__)

class ActiveAgent:
    """
    主动代理收集器，用于主动探测网络设备状态
    """
    
    def __init__(self):
        logger.info("初始化主动代理收集器")
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    def collect(self, ip_address):
        """
        从指定IP地址的设备收集数据
        
        Args:
            ip_address: 设备IP地址
            
        Returns:
            dict: 收集到的数据字典
        """
        try:
            logger.info(f"从 {ip_address} 收集主动探测数据")
            data = {}
            
            # 检查设备连通性
            is_reachable = self.ping(ip_address)
            
            if not is_reachable:
                logger.warning(f"设备 {ip_address} 无法连通")
                return {
                    'is_reachable': False,
                    'packet_loss': 100,
                    'latency': 99999,
                    'cpu_usage': 0,
                    'memory_usage': 0,
                    'bandwidth_usage': 0
                }
            
            # 设备可连通
            data['is_reachable'] = True
            
            # 测试常见端口
            open_ports = self.scan_ports(ip_address)
            data['open_ports'] = open_ports
            
            # 测量网络性能
            packet_loss, latency = self.measure_network_performance(ip_address)
            data['packet_loss'] = packet_loss
            data['latency'] = latency
            
            # 查询HTTP服务（如果有）
            if 80 in open_ports or 443 in open_ports:
                protocol = 'https' if 443 in open_ports else 'http'
                http_status = self.check_http_service(ip_address, protocol)
                data['http_status'] = http_status
            
            # 模拟一些系统性能指标（实际应通过远程代理或其他方式获取）
            data['cpu_usage'] = self._simulate_cpu_usage()
            data['memory_usage'] = self._simulate_memory_usage()
            data['bandwidth_usage'] = self._simulate_bandwidth_usage()
            
            logger.info(f"从 {ip_address} 收集到的主动探测数据: {data}")
            return data
            
        except Exception as e:
            logger.error(f"从 {ip_address} 收集主动探测数据出错: {str(e)}")
            # 返回带有默认值的字典，避免数据缺失
            return {
                'is_reachable': False,
                'packet_loss': 100,
                'latency': 99999,
                'cpu_usage': 0,
                'memory_usage': 0,
                'bandwidth_usage': 0
            }
    
    def ping(self, ip_address, count=4):
        """
        检查设备是否可达（使用ping）
        
        Args:
            ip_address: 设备IP地址
            count: ping次数
            
        Returns:
            bool: 设备是否可达
        """
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, str(count), ip_address]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ping {ip_address} 出错: {str(e)}")
            return False
    
    def scan_ports(self, ip_address, ports=None):
        """
        扫描常见端口是否开放
        
        Args:
            ip_address: 设备IP地址
            ports: 要扫描的端口列表，默认为常见端口
            
        Returns:
            list: 开放的端口列表
        """
        if ports is None:
            # 默认扫描常见端口
            ports = [21, 22, 23, 25, 53, 80, 123, 443, 161, 162, 389, 636, 3306, 5432, 8080]
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    return port
                return None
            except Exception:
                return None
            finally:
                sock.close()
        
        # 并行检查多个端口
        futures = [self.executor.submit(check_port, port) for port in ports]
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)
        
        return open_ports
    
    def measure_network_performance(self, ip_address, count=10):
        """
        测量网络性能（丢包率和延迟）
        
        Args:
            ip_address: 设备IP地址
            count: ping次数
            
        Returns:
            tuple: (丢包率, 延迟)
        """
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, str(count), ip_address]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout
            
            # 解析ping输出，提取丢包率和延迟
            if platform.system().lower() == 'windows':
                # Windows解析
                try:
                    # 尝试解析丢包率
                    packet_loss_line = [line for line in output.split('\n') if 'loss' in line][0]
                    packet_loss = int(''.join(c for c in packet_loss_line.split('%')[0][-3:] if c.isdigit()))
                    
                    # 尝试解析延迟
                    latency_line = [line for line in output.split('\n') if 'Average' in line][0]
                    latency = int(''.join(c for c in latency_line.split('=')[1] if c.isdigit()))
                except (IndexError, ValueError):
                    return 100, 99999
            else:
                # Linux/Unix解析
                try:
                    # 尝试解析丢包率
                    packet_loss_line = [line for line in output.split('\n') if 'packet loss' in line][0]
                    packet_loss = float(packet_loss_line.split('%')[0].split(' ')[-1])
                    
                    # 尝试解析延迟
                    latency_line = [line for line in output.split('\n') if 'rtt min/avg/max' in line][0]
                    latency = float(latency_line.split('/')[4].split('/')[0])
                except (IndexError, ValueError):
                    return 100, 99999
            
            return packet_loss, latency
            
        except Exception as e:
            logger.error(f"测量网络性能出错: {str(e)}")
            return 100, 99999
    
    def check_http_service(self, ip_address, protocol='http'):
        """
        检查HTTP服务状态
        
        Args:
            ip_address: 设备IP地址
            protocol: 协议（http或https）
            
        Returns:
            dict: HTTP服务状态信息
        """
        try:
            url = f"{protocol}://{ip_address}"
            response = requests.get(url, timeout=5, verify=False)
            
            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds() * 1000,  # 毫秒
                'content_type': response.headers.get('Content-Type', 'unknown')
            }
        except requests.exceptions.RequestException:
            return {
                'status_code': -1,
                'response_time': 99999,
                'content_type': 'unknown'
            }
    
    def _simulate_cpu_usage(self):
        """
        模拟获取CPU使用率
        
        Returns:
            float: 模拟的CPU使用率
        """
        import random
        return random.uniform(10, 90)
    
    def _simulate_memory_usage(self):
        """
        模拟获取内存使用率
        
        Returns:
            float: 模拟的内存使用率
        """
        import random
        return random.uniform(20, 80)
    
    def _simulate_bandwidth_usage(self):
        """
        模拟获取带宽使用率
        
        Returns:
            float: 模拟的带宽使用率
        """
        import random
        return random.uniform(5, 60)
