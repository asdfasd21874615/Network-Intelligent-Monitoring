import paramiko
import logging
import time
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

class SSHConnector:
    """
    SSH连接器，用于通过SSH登录到网络设备并执行命令
    """
    
    def __init__(self, host: str, username: str, port: int = 22):
        """
        初始化SSH连接器
        
        Args:
            host: 主机IP地址
            username: SSH用户名
            port: SSH端口，默认为22
        """
        self.host = host
        self.username = username
        self.port = port
        self.client = None
        self.connected = False
        
    def connect(self, password: Optional[str] = None, key_file: Optional[str] = None, 
                timeout: int = 10) -> bool:
        """
        连接到设备
        
        Args:
            password: SSH密码
            key_file: SSH密钥文件路径
            timeout: 连接超时时间（秒）
            
        Returns:
            bool: 连接是否成功
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
                'timeout': timeout
            }
            
            # 使用密码或密钥文件登录
            if password:
                connect_kwargs['password'] = password
            elif key_file:
                connect_kwargs['key_filename'] = key_file
            else:
                logger.error(f"需要提供密码或密钥文件才能连接到 {self.host}")
                return False
            
            logger.info(f"正在连接到 {self.host}...")
            self.client.connect(**connect_kwargs)
            self.connected = True
            logger.info(f"成功连接到 {self.host}")
            return True
            
        except paramiko.AuthenticationException:
            logger.error(f"认证失败: {self.host}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH连接错误: {self.host} - {str(e)}")
            return False
        except Exception as e:
            logger.error(f"连接到 {self.host} 失败: {str(e)}")
            return False
    
    def execute_command(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """
        执行SSH命令
        
        Args:
            command: 要执行的命令
            timeout: 命令执行超时时间（秒）
            
        Returns:
            Tuple[int, str, str]: (退出码, 标准输出, 标准错误)
        """
        if not self.connected or not self.client:
            logger.error("尚未连接，无法执行命令")
            return -1, "", "未连接到设备"
        
        try:
            logger.debug(f"在 {self.host} 上执行命令: {command}")
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')
            
            return exit_code, output, error
            
        except Exception as e:
            logger.error(f"执行命令错误: {str(e)}")
            return -1, "", str(e)
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        获取设备系统信息
        
        Returns:
            Dict[str, Any]: 包含系统信息的字典
        """
        info = {
            "os_type": "unknown",
            "os_version": "unknown",
            "hostname": "unknown",
            "uptime": "unknown",
            "cpu_info": "unknown",
            "memory_info": "unknown"
        }
        
        # 尝试获取操作系统类型
        exit_code, output, _ = self.execute_command("uname -a")
        if exit_code == 0:
            output = output.lower()
            # 检测常见操作系统
            if "linux" in output:
                info["os_type"] = "linux"
                # 获取Linux发行版信息
                _, release_info, _ = self.execute_command("cat /etc/os-release")
                if "VERSION=" in release_info:
                    for line in release_info.splitlines():
                        if line.startswith("VERSION="):
                            info["os_version"] = line.split("=")[1].strip('"')
                            break
            elif "darwin" in output:
                info["os_type"] = "macos"
                _, version, _ = self.execute_command("sw_vers -productVersion")
                info["os_version"] = version.strip()
        
        # 尝试获取主机名
        exit_code, output, _ = self.execute_command("hostname")
        if exit_code == 0:
            info["hostname"] = output.strip()
        
        # 获取运行时间
        if info["os_type"] == "linux":
            _, uptime, _ = self.execute_command("uptime -p")
            if uptime:
                info["uptime"] = uptime.strip()
        
        # 获取CPU信息
        if info["os_type"] == "linux":
            _, cpu_info, _ = self.execute_command("grep 'model name' /proc/cpuinfo | head -1")
            if "model name" in cpu_info:
                info["cpu_info"] = cpu_info.split(":")[1].strip()
            
            # 获取内存信息
            _, memory_info, _ = self.execute_command("free -h | grep Mem")
            if memory_info:
                info["memory_info"] = memory_info.strip()
        
        return info
    
    def test_connection(self) -> bool:
        """
        测试SSH连接是否可用
        
        Returns:
            bool: 连接是否可用
        """
        if not self.connected or not self.client:
            return False
        
        try:
            exit_code, _, _ = self.execute_command("echo 'SSH connection test'")
            return exit_code == 0
        except:
            return False
    
    def close(self) -> None:
        """
        关闭SSH连接
        """
        if self.client:
            self.client.close()
            self.connected = False
            logger.info(f"已关闭到 {self.host} 的连接")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def detect_device_type(self) -> str:
        """
        自动检测设备类型
        
        Returns:
            str: 设备类型，如 'linux', 'cisco', 'huawei', 'h3c', 等
        """
        if not self.connected or not self.client:
            logger.error("尚未连接，无法检测设备类型")
            return "unknown"
        
        # 首先尝试获取系统信息
        exit_code, output, _ = self.execute_command("uname -a", timeout=5)
        if exit_code == 0:
            output = output.lower()
            # 检测常见操作系统
            if "linux" in output:
                return "linux"
            elif "darwin" in output:
                return "macos"
            elif "freebsd" in output:
                return "freebsd"
        
        # 尝试检测网络设备
        # Cisco 设备检测
        exit_code, output, _ = self.execute_command("show version", timeout=5)
        if exit_code == 0 and ("cisco" in output.lower() or "ios" in output.lower()):
            return "cisco"
        
        # 华为设备检测
        exit_code, output, _ = self.execute_command("display version", timeout=5)
        if exit_code == 0 and "huawei" in output.lower():
            return "huawei"
        
        # H3C 设备检测
        if exit_code == 0 and "h3c" in output.lower():
            return "h3c"
        
        # 尝试检测交换机厂商
        vendors = [
            ("juniper", "juniper"),
            ("junos", "juniper"),
            ("arista", "arista"),
            ("eos", "arista"),
            ("fortinet", "fortinet"),
            ("fortigate", "fortinet"),
            ("palo alto", "paloalto"),
            ("panos", "paloalto")
        ]
        
        for keyword, vendor in vendors:
            if keyword in output.lower():
                return vendor
        
        # 如果前面的检测都失败，尝试检查登录提示或当前路径
        exit_code, output, _ = self.execute_command("pwd", timeout=5)
        if exit_code == 0:
            return "unix-like"
        
        return "unknown"
    
    def interactive_shell(self, timeout: int = 30) -> Tuple[paramiko.Channel, Any, Any]:
        """
        获取交互式shell会话
        
        Args:
            timeout: shell通道超时时间（秒）
            
        Returns:
            Tuple[paramiko.Channel, Any, Any]: (通道, stdin, stdout)
        """
        if not self.connected or not self.client:
            raise ConnectionError("尚未连接，无法获取交互式shell")
        
        channel = self.client.invoke_shell()
        channel.settimeout(timeout)
        stdin = channel.makefile('wb')
        stdout = channel.makefile('rb')
        
        return channel, stdin, stdout
    
    def wait_for_output(self, channel, timeout: int = 30) -> str:
        """
        等待并接收shell通道的输出
        
        Args:
            channel: 通道对象
            timeout: 等待超时时间（秒）
            
        Returns:
            str: 接收到的输出
        """
        output = ""
        start_time = time.time()
        
        while True:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode('utf-8', errors='replace')
                output += chunk
                
                # 如果输出中有登录提示或命令提示符，就可以认为命令执行完成
                if any(prompt in output for prompt in ['$', '#', '>', '~', 'Password:']):
                    break
            
            # 检查超时
            if time.time() - start_time > timeout:
                logger.warning("等待输出超时")
                break
                
            # 短暂休眠避免CPU过度使用
            time.sleep(0.1)
        
        return output
    
    def execute_command_with_retry(self, command: str, retries: int = 3, 
                                  timeout: int = 30) -> Tuple[int, str, str]:
        """
        带有重试功能的命令执行
        
        Args:
            command: 要执行的命令
            retries: 重试次数
            timeout: 命令执行超时时间（秒）
            
        Returns:
            Tuple[int, str, str]: (退出码, 标准输出, 标准错误)
        """
        for attempt in range(retries):
            try:
                result = self.execute_command(command, timeout)
                return result
            except Exception as e:
                logger.warning(f"执行命令失败，尝试 {attempt+1}/{retries}: {str(e)}")
                if attempt == retries - 1:  # 最后一次尝试失败
                    logger.error(f"执行命令最终失败: {str(e)}")
                    return -1, "", f"命令执行失败: {str(e)}"
                time.sleep(1)  # 在重试前稍等片刻
        
        return -1, "", "超过最大重试次数"
