import requests
import json
import logging

logger = logging.getLogger(__name__)

class DeepSeekAssistant:
    """
    DeepSeek AI助手，用于智能分析网络数据和问题
    """
    
    def __init__(self, api_key=None, api_url=None):
        """
        初始化DeepSeek助手
        
        Args:
            api_key: DeepSeek API密钥
            api_url: DeepSeek API URL
        """
        logger.info("初始化DeepSeek AI助手")
        self.api_key = api_key
        self.api_url = api_url or "https://api.deepseek.com/v1/chat/completions"
        
        # 系统提示，指导AI助手的行为
        self.system_prompt = """
        你是一个专业的网络监控平台AI助手，专门帮助用户分析和解决网络设备问题。
        你应该：
        1. 分析用户提供的网络状况，指出可能的问题和解决方案
        2. 解答用户关于网络设备、监控指标和性能的问题
        3. 提供专业的网络优化建议
        4. 协助排查网络故障
        请简洁明了地回答问题，避免过多的技术术语，确保普通用户也能理解。
        """
    
    def ask(self, query, context=None):
        """
        向DeepSeek API发送查询
        
        Args:
            query: 用户查询
            context: 可选的上下文信息
            
        Returns:
            str: DeepSeek的回复
        """
        try:
            logger.info(f"向DeepSeek发送查询: {query}")
            
            if not self.api_key:
                logger.warning("未配置DeepSeek API密钥，返回模拟回复")
                return self._mock_response(query, context)
            
            # 准备消息
            messages = [
                {"role": "system", "content": self.system_prompt}
            ]
            
            # 添加上下文（如果有）
            if context:
                messages.append({"role": "system", "content": f"当前网络状况: {context}"})
            
            # 添加用户查询
            messages.append({"role": "user", "content": query})
            
            # 准备请求数据
            data = {
                "model": "deepseek-chat",
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 1000
            }
            
            # 发送请求
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            response = requests.post(self.api_url, headers=headers, data=json.dumps(data), timeout=30)
            
            # 检查响应
            if response.status_code == 200:
                result = response.json()
                return result["choices"][0]["message"]["content"]
            else:
                logger.error(f"DeepSeek API请求失败: {response.status_code} - {response.text}")
                return f"抱歉，我无法回答您的问题。请稍后再试。(错误码: {response.status_code})"
        
        except Exception as e:
            logger.error(f"调用DeepSeek API出错: {str(e)}")
            return "抱歉，我无法回答您的问题。发生了内部错误，请稍后再试。"
    
    def _mock_response(self, query, context=None):
        """
        生成模拟回复（当API密钥未配置时使用）
        
        Args:
            query: 用户查询
            context: 可选的上下文信息
            
        Returns:
            str: 模拟的回复
        """
        # 基于查询关键词生成简单的模拟回复
        query = query.lower()
        
        if "cpu" in query or "处理器" in query:
            return "CPU使用率高可能是由于系统负载过大、某些进程消耗资源过多或软件配置不当引起的。建议检查是否有异常进程，优化网络设备配置，必要时考虑升级硬件。"
        
        elif "内存" in query or "memory" in query:
            return "内存使用率高通常意味着设备上运行的服务或应用占用了过多内存资源。建议检查内存泄漏问题，优化应用配置，必要时增加内存容量。"
        
        elif "带宽" in query or "bandwidth" in query:
            return "带宽使用率高表示网络连接接近饱和。建议分析流量来源，优化网络配置，考虑流量整形或扩展带宽容量，避免网络拥塞影响业务。"
        
        elif "丢包" in query or "packet loss" in query:
            return "丢包可能是由网络拥塞、硬件故障或配置错误导致的。建议检查网络设备是否正常工作，排查网络拥塞点，优化路由配置，并检查物理连接是否稳定。"
        
        elif "延迟" in query or "latency" in query:
            return "网络延迟高可能是由网络拥塞、路由优化不当或硬件性能问题导致的。建议优化网络路径，检查带宽使用情况，减少网络跳数，确保设备正常运行。"
        
        elif "告警" in query or "alert" in query:
            if context and "警报" in context:
                return f"根据当前状况{context}，建议优先处理未解决的告警，从严重程度高的开始。检查设备状态，解决根本原因而非仅仅清除告警。"
            else:
                return "告警系统帮助您及时发现网络问题。建议配置合理的告警阈值，避免误报和漏报，并建立告警升级流程以确保紧急问题得到及时处理。"
        
        elif "优化" in query or "optimize" in query:
            return "网络优化建议：1. 定期检查并更新设备固件；2. 合理规划网络拓扑结构；3. 实施流量整形和QoS策略；4. 监控关键性能指标并设置合理告警；5. 根据业务需求优化带宽分配；6. 减少不必要的网络服务。"
        
        elif "安全" in query or "security" in query:
            return "网络安全建议：1. 定期更新设备固件和安全补丁；2. 使用强密码和双因素认证；3. 实施网络分段和最小权限原则；4. 部署防火墙和入侵检测系统；5. 监控异常流量和行为；6. 制定安全事件响应计划。"
        
        elif "故障" in query or "问题" in query or "error" in query or "issue" in query:
            return "排查网络故障建议采用自底向上的方法：1. 检查物理连接和电源；2. 验证设备基本功能；3. 测试网络连通性；4. 检查配置是否正确；5. 分析日志文件寻找错误信息；6. 使用网络诊断工具定位问题。"
        
        else:
            return "作为网络监控平台的AI助手，我可以帮助您分析网络性能数据、排查问题、提供优化建议。您可以询问关于CPU使用率、内存使用、带宽、丢包率、延迟等方面的问题，也可以请我帮助解释告警信息或提供优化建议。"
