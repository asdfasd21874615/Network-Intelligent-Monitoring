"""
SSH Command Templates

This module provides predefined command templates for various device types
and common network device management tasks.
"""

# Common command categories
SYSTEM_INFO = "system_info"
INTERFACE_INFO = "interface_info"
ROUTING_INFO = "routing_info"
SECURITY_INFO = "security_info"
PERFORMANCE_INFO = "performance_info"

# Device types
CISCO_IOS = "cisco_ios"
CISCO_NXOS = "cisco_nxos"
JUNIPER = "juniper"
HUAWEI = "huawei"
GENERIC_LINUX = "linux"

# Command templates organized by device type and category
COMMAND_TEMPLATES = {
    CISCO_IOS: {
        SYSTEM_INFO: [
            {"name": "版本信息", "command": "show version", "description": "显示设备型号、序列号、IOS版本等基本信息"},
            {"name": "运行时间", "command": "show uptime", "description": "显示设备运行时间"},
            {"name": "内存使用", "command": "show memory statistics", "description": "显示内存使用统计信息"},
            {"name": "CPU使用", "command": "show processes cpu sorted", "description": "显示CPU使用情况"},
            {"name": "配置", "command": "show running-config", "description": "显示当前运行配置"}
        ],
        INTERFACE_INFO: [
            {"name": "接口状态", "command": "show ip interface brief", "description": "显示所有接口的IP地址和状态概况"},
            {"name": "接口详情", "command": "show interfaces", "description": "显示接口详细信息"},
            {"name": "接口错误", "command": "show interfaces counters errors", "description": "显示接口错误计数器"}
        ],
        ROUTING_INFO: [
            {"name": "路由表", "command": "show ip route", "description": "显示IP路由表"},
            {"name": "BGP摘要", "command": "show ip bgp summary", "description": "显示BGP邻居状态摘要"},
            {"name": "OSPF邻居", "command": "show ip ospf neighbor", "description": "显示OSPF邻居状态"}
        ],
        SECURITY_INFO: [
            {"name": "ACL配置", "command": "show access-lists", "description": "显示配置的访问控制列表"},
            {"name": "登录会话", "command": "show users", "description": "显示当前登录的用户"}
        ],
        PERFORMANCE_INFO: [
            {"name": "接口流量", "command": "show interfaces counters", "description": "显示接口流量计数器"},
            {"name": "QoS统计", "command": "show policy-map interface", "description": "显示策略映射统计信息"}
        ]
    },
    CISCO_NXOS: {
        SYSTEM_INFO: [
            {"name": "版本信息", "command": "show version", "description": "显示NX-OS版本等系统信息"},
            {"name": "运行时间", "command": "show system uptime", "description": "显示设备运行时间"},
            {"name": "环境", "command": "show environment", "description": "显示环境信息(电源、风扇、温度)"}
        ],
        INTERFACE_INFO: [
            {"name": "接口状态", "command": "show ip interface brief", "description": "显示接口摘要信息"},
            {"name": "接口详情", "command": "show interface status", "description": "显示接口状态"}
        ]
    },
    JUNIPER: {
        SYSTEM_INFO: [
            {"name": "版本信息", "command": "show version", "description": "显示Junos版本"},
            {"name": "系统信息", "command": "show system information", "description": "显示系统基本信息"},
            {"name": "系统存储", "command": "show system storage", "description": "显示存储使用情况"}
        ],
        INTERFACE_INFO: [
            {"name": "接口信息", "command": "show interfaces terse", "description": "显示接口简要信息"}
        ]
    },
    HUAWEI: {
        SYSTEM_INFO: [
            {"name": "版本信息", "command": "display version", "description": "显示系统版本信息"},
            {"name": "设备信息", "command": "display device", "description": "显示设备详细信息"}
        ],
        INTERFACE_INFO: [
            {"name": "接口状态", "command": "display interface brief", "description": "显示接口摘要"},
            {"name": "接口详情", "command": "display interface", "description": "显示接口详细配置"}
        ]
    },
    GENERIC_LINUX: {
        SYSTEM_INFO: [
            {"name": "系统信息", "command": "uname -a", "description": "显示Linux内核版本和系统信息"},
            {"name": "发行版信息", "command": "cat /etc/*release", "description": "显示Linux发行版信息"},
            {"name": "运行时间", "command": "uptime", "description": "显示系统运行时间和负载"},
            {"name": "内存使用", "command": "free -h", "description": "显示内存使用情况"},
            {"name": "磁盘使用", "command": "df -h", "description": "显示磁盘使用情况"}
        ],
        INTERFACE_INFO: [
            {"name": "网络配置", "command": "ifconfig -a || ip addr", "description": "显示所有网络接口配置"},
            {"name": "路由表", "command": "route -n || ip route", "description": "显示路由表"}
        ],
        PERFORMANCE_INFO: [
            {"name": "进程信息", "command": "ps aux", "description": "显示所有运行进程"},
            {"name": "资源使用", "command": "top -b -n 1", "description": "显示资源使用情况"},
            {"name": "网络连接", "command": "netstat -tulpn || ss -tulpn", "description": "显示网络连接"}
        ],
        SECURITY_INFO: [
            {"name": "用户信息", "command": "who", "description": "显示当前登录用户"},
            {"name": "开放端口", "command": "netstat -tulpn || ss -tulpn", "description": "显示监听端口"}
        ]
    }
}

# Helper functions for command templates
def get_device_types():
    """Return a list of supported device types."""
    return list(COMMAND_TEMPLATES.keys())

def get_command_categories(device_type):
    """Return available command categories for a device type."""
    if device_type in COMMAND_TEMPLATES:
        return list(COMMAND_TEMPLATES[device_type].keys())
    return []

def get_commands(device_type, category):
    """Return command templates for a specific device type and category."""
    if device_type in COMMAND_TEMPLATES and category in COMMAND_TEMPLATES[device_type]:
        return COMMAND_TEMPLATES[device_type][category]
    return []

def get_all_commands(device_type):
    """Return all command templates for a specific device type."""
    if device_type not in COMMAND_TEMPLATES:
        return []
    
    all_commands = []
    for category in COMMAND_TEMPLATES[device_type]:
        all_commands.extend(COMMAND_TEMPLATES[device_type][category])
    return all_commands

def detect_device_type(output):
    """
    Attempt to detect device type based on command output
    
    Args:
        output (str): Command output from a device
        
    Returns:
        str: Detected device type or None
    """
    # Simple detection based on output patterns
    output = output.lower()
    
    if "cisco ios software" in output:
        return CISCO_IOS
    elif "cisco nexus" in output:
        return CISCO_NXOS
    elif "junos" in output:
        return JUNIPER
    elif "huawei" in output:
        return HUAWEI
    elif "linux" in output or "gnu" in output or "ubuntu" in output or "centos" in output:
        return GENERIC_LINUX
    
    return None
