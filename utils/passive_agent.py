import socket
import threading
import time
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class PassiveAgent:
    """
    被动代理收集器，用于接收来自网络设备的被动数据
    """
    
    def __init__(self, port=5140):
        """
        初始化被动代理收集器
        
        Args:
            port: 监听端口，默认5140（Syslog常用端口之一）
        """
        logger.info(f"初始化被动代理收集器，监听端口: {port}")
        self.port = port
        self.running = False
        self.data_store = {}  # 存储接收到的数据，按设备IP地址索引
        self.data_lock = threading.Lock()  # 数据锁，用于线程安全
        
        # 启动监听线程
        self.start_listening()
    
    def start_listening(self):
        """
        启动监听线程，接收来自网络设备的数据
        """
        if self.running:
            return
        
        self.running = True
        logger.info("启动被动代理监听线程")
        
        # 创建UDP套接字用于接收Syslog数据
        self.syslog_listener = threading.Thread(target=self._syslog_listener)
        self.syslog_listener.daemon = True
        self.syslog_listener.start()
        
        # 创建TCP套接字用于接收SNMP Trap数据
        self.snmp_trap_listener = threading.Thread(target=self._snmp_trap_listener)
        self.snmp_trap_listener.daemon = True
        self.snmp_trap_listener.start()
        
        # 创建HTTP监听器用于接收设备推送的数据
        self.http_listener = threading.Thread(target=self._http_listener)
        self.http_listener.daemon = True
        self.http_listener.start()
    
    def stop_listening(self):
        """
        停止所有监听线程
        """
        self.running = False
        logger.info("停止被动代理监听线程")
    
    def get_data(self, ip_address):
        """
        获取指定IP地址的设备数据
        
        Args:
            ip_address: 设备IP地址
            
        Returns:
            dict: 设备数据，如果没有数据则返回空字典
        """
        with self.data_lock:
            # 获取数据并清理过期数据（超过5分钟的数据视为过期）
            current_time = time.time()
            data = self.data_store.get(ip_address, {}).copy()
            
            # 检查数据是否过期
            if data and 'timestamp' in data:
                if current_time - data['timestamp'] > 300:  # 5分钟 = 300秒
                    # 数据过期，返回空字典
                    return {}
            
            return data
    
    def _syslog_listener(self):
        """
        Syslog UDP监听器，用于接收设备发送的Syslog消息
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', self.port))
            sock.settimeout(1)
            
            logger.info(f"Syslog监听器启动，在端口 {self.port} 上等待数据")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip_address = addr[0]
                    
                    # 处理接收到的数据
                    self._process_syslog_data(ip_address, data)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Syslog监听器处理数据出错: {str(e)}")
            
            sock.close()
            
        except Exception as e:
            logger.error(f"Syslog监听器出错: {str(e)}")
    
    def _snmp_trap_listener(self):
        """
        SNMP Trap TCP监听器，用于接收设备发送的SNMP Trap消息
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('0.0.0.0', self.port + 1))  # 在下一个端口监听SNMP Trap
            sock.listen(5)
            sock.settimeout(1)
            
            logger.info(f"SNMP Trap监听器启动，在端口 {self.port + 1} 上等待数据")
            
            while self.running:
                try:
                    conn, addr = sock.accept()
                    ip_address = addr[0]
                    
                    # 处理连接
                    data = conn.recv(4096)
                    if data:
                        # 处理接收到的数据
                        self._process_snmp_trap_data(ip_address, data)
                    
                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"SNMP Trap监听器处理数据出错: {str(e)}")
            
            sock.close()
            
        except Exception as e:
            logger.error(f"SNMP Trap监听器出错: {str(e)}")
    
    def _http_listener(self):
        """
        HTTP监听器，用于接收设备通过HTTP POST方法推送的数据
        """
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import threading
            
            class DataHandler(BaseHTTPRequestHandler):
                def do_POST(self):
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    client_ip = self.client_address[0]
                    
                    # 处理接收到的数据
                    self.server.passive_agent._process_http_data(client_ip, post_data)
                    
                    # 返回成功响应
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')
                
                def log_message(self, format, *args):
                    # 重写日志方法，避免输出过多HTTP日志
                    pass
            
            # 创建HTTP服务器
            server = HTTPServer(('0.0.0.0', self.port + 2), DataHandler)
            server.passive_agent = self
            server.timeout = 1
            
            logger.info(f"HTTP监听器启动，在端口 {self.port + 2} 上等待数据")
            
            while self.running:
                server.handle_request()
            
            server.server_close()
            
        except Exception as e:
            logger.error(f"HTTP监听器出错: {str(e)}")
    
    def _process_syslog_data(self, ip_address, data):
        """
        处理Syslog数据
        
        Args:
            ip_address: 发送数据的设备IP地址
            data: 接收到的原始数据
        """
        try:
            # 解码数据
            message = data.decode('utf-8', errors='ignore')
            logger.debug(f"从 {ip_address} 接收到Syslog消息: {message}")
            
            # 简单解析Syslog消息（实际应用中应使用更复杂的解析）
            cpu_usage = self._extract_metric(message, 'CPU')
            memory_usage = self._extract_metric(message, 'Memory')
            bandwidth_usage = self._extract_metric(message, 'Bandwidth')
            
            # 更新数据存储
            with self.data_lock:
                if ip_address not in self.data_store:
                    self.data_store[ip_address] = {}
                
                # 更新数据
                if cpu_usage is not None:
                    self.data_store[ip_address]['cpu_usage'] = cpu_usage
                if memory_usage is not None:
                    self.data_store[ip_address]['memory_usage'] = memory_usage
                if bandwidth_usage is not None:
                    self.data_store[ip_address]['bandwidth_usage'] = bandwidth_usage
                
                # 更新时间戳
                self.data_store[ip_address]['timestamp'] = time.time()
                self.data_store[ip_address]['last_update_source'] = 'syslog'
            
        except Exception as e:
            logger.error(f"处理Syslog数据出错: {str(e)}")
    
    def _process_snmp_trap_data(self, ip_address, data):
        """
        处理SNMP Trap数据
        
        Args:
            ip_address: 发送数据的设备IP地址
            data: 接收到的原始数据
        """
        try:
            # SNMP Trap数据处理比较复杂，这里仅做简单模拟
            logger.debug(f"从 {ip_address} 接收到SNMP Trap数据，长度: {len(data)}")
            
            # 实际应用中应使用pysnmp等库解析SNMP Trap数据
            # 这里简单模拟一下
            import random
            cpu_usage = random.uniform(10, 90)
            memory_usage = random.uniform(20, 80)
            
            # 更新数据存储
            with self.data_lock:
                if ip_address not in self.data_store:
                    self.data_store[ip_address] = {}
                
                # 更新数据
                self.data_store[ip_address]['cpu_usage'] = cpu_usage
                self.data_store[ip_address]['memory_usage'] = memory_usage
                
                # 更新时间戳
                self.data_store[ip_address]['timestamp'] = time.time()
                self.data_store[ip_address]['last_update_source'] = 'snmp_trap'
            
        except Exception as e:
            logger.error(f"处理SNMP Trap数据出错: {str(e)}")
    
    def _process_http_data(self, ip_address, data):
        """
        处理HTTP推送的数据
        
        Args:
            ip_address: 发送数据的设备IP地址
            data: 接收到的原始数据
        """
        try:
            # 尝试解析JSON数据
            json_data = json.loads(data.decode('utf-8', errors='ignore'))
            logger.debug(f"从 {ip_address} 接收到HTTP数据: {json_data}")
            
            # 提取指标数据
            cpu_usage = json_data.get('cpu_usage')
            memory_usage = json_data.get('memory_usage')
            bandwidth_usage = json_data.get('bandwidth_usage')
            packet_loss = json_data.get('packet_loss')
            latency = json_data.get('latency')
            
            # 更新数据存储
            with self.data_lock:
                if ip_address not in self.data_store:
                    self.data_store[ip_address] = {}
                
                # 更新数据
                if cpu_usage is not None:
                    self.data_store[ip_address]['cpu_usage'] = float(cpu_usage)
                if memory_usage is not None:
                    self.data_store[ip_address]['memory_usage'] = float(memory_usage)
                if bandwidth_usage is not None:
                    self.data_store[ip_address]['bandwidth_usage'] = float(bandwidth_usage)
                if packet_loss is not None:
                    self.data_store[ip_address]['packet_loss'] = float(packet_loss)
                if latency is not None:
                    self.data_store[ip_address]['latency'] = float(latency)
                
                # 更新时间戳
                self.data_store[ip_address]['timestamp'] = time.time()
                self.data_store[ip_address]['last_update_source'] = 'http'
            
        except json.JSONDecodeError:
            logger.error(f"解析来自 {ip_address} 的HTTP数据时JSON解码错误")
        except Exception as e:
            logger.error(f"处理HTTP数据出错: {str(e)}")
    
    def _extract_metric(self, message, metric_name):
        """
        从Syslog消息中提取指标值（简单实现）
        
        Args:
            message: Syslog消息
            metric_name: 指标名称
            
        Returns:
            float: 提取出的指标值，如果未找到则返回None
        """
        try:
            # 简单的指标提取（格式假设为 "MetricName: Value%"）
            import re
            pattern = rf'{metric_name}:\s*(\d+\.?\d*)%?'
            match = re.search(pattern, message)
            if match:
                return float(match.group(1))
            return None
        except Exception:
            return None
