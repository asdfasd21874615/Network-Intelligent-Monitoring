import os
from dotenv import load_dotenv

# 加载环境变量
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    # Flask配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 监控配置
    COLLECTION_INTERVAL = int(os.environ.get('COLLECTION_INTERVAL') or 30)  # 数据收集间隔（秒）
    
    # 告警配置
    ALERT_CPU_THRESHOLD = float(os.environ.get('ALERT_CPU_THRESHOLD') or 80.0)  # CPU使用率阈值
    ALERT_MEMORY_THRESHOLD = float(os.environ.get('ALERT_MEMORY_THRESHOLD') or 80.0)  # 内存使用率阈值
    ALERT_BANDWIDTH_THRESHOLD = float(os.environ.get('ALERT_BANDWIDTH_THRESHOLD') or 90.0)  # 带宽使用率阈值
    ALERT_PACKET_LOSS_THRESHOLD = float(os.environ.get('ALERT_PACKET_LOSS_THRESHOLD') or 5.0)  # 丢包率阈值
    ALERT_LATENCY_THRESHOLD = float(os.environ.get('ALERT_LATENCY_THRESHOLD') or 100.0)  # 延迟阈值（毫秒）
    
    # DeepSeek API配置
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY') or 'your-deepseek-api-key'
    DEEPSEEK_API_URL = os.environ.get('DEEPSEEK_API_URL') or 'https://api.deepseek.com/v1'
