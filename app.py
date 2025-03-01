from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_moment import Moment
import os
import threading
import time
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import json
import requests

# 导入自定义模块
from models import db, User, Device, NetworkData, Alert
from config import Config
from utils.snmp_collector import SNMPCollector
from utils.active_agent import ActiveAgent
from utils.passive_agent import PassiveAgent
from utils.alert_manager import AlertManager
from utils.ai_assistant import DeepSeekAssistant

# 配置日志
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/network_monitor.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)

# 初始化Flask应用
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# 初始化Moment
moment = Moment(app)

# 添加日志处理器
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('网络监控平台启动')

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 添加Jinja2模板过滤器
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime(timestamp):
    """将时间戳转换为datetime对象"""
    if timestamp:
        return datetime.fromtimestamp(timestamp)
    return None

# 初始化数据收集器
snmp_collector = SNMPCollector()
active_agent = ActiveAgent()
passive_agent = PassiveAgent()
alert_manager = AlertManager()
ai_assistant = DeepSeekAssistant(api_key=app.config['DEEPSEEK_API_KEY'])

# 用户加载函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 路由: 首页
@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='网络监控平台')

# 路由: 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('用户名或密码错误')
            return redirect(url_for('login'))
        login_user(user, remember=request.form.get('remember_me'))
        return redirect(url_for('index'))
    return render_template('login.html', title='登录')

# 路由: 退出登录
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 路由: 设备页面
@app.route('/devices')
@login_required
def devices():
    all_devices = Device.query.all()
    return render_template('devices.html', title='设备管理', devices=all_devices)

# 路由: 添加设备
@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device():
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        device_type = request.form.get('device_type')
        snmp_community = request.form.get('snmp_community')
        
        device = Device(name=name, ip_address=ip_address, 
                       device_type=device_type, snmp_community=snmp_community)
        db.session.add(device)
        db.session.commit()
        flash('设备添加成功')
        return redirect(url_for('devices'))
    return render_template('add_device.html', title='添加设备')

# 路由: 设备详情
@app.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    # 获取该设备的最新监控数据
    recent_data = NetworkData.query.filter_by(device_id=device_id).order_by(NetworkData.timestamp.desc()).limit(100).all()
    return render_template('device_detail.html', title=device.name, device=device, data=recent_data)

# 路由: 查看警报
@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(100).all()
    
    return render_template('alerts.html', title='警报中心', alerts=all_alerts)

# 路由: AI助手页面
@app.route('/assistant')
@login_required
def assistant():
    return render_template('ai_assistant.html', title='AI助手')

# API: 与AI助手交互
@app.route('/api/assistant', methods=['POST'])
@login_required
def ask_assistant():
    data = request.get_json()
    query = data.get('query', '')
    if not query:
        return jsonify({'error': 'Query is required'}), 400
    
    # 获取网络状况作为上下文
    devices_count = Device.query.count()
    alerts_count = Alert.query.filter(Alert.resolved == False).count()
    context = f"网络中有{devices_count}台设备，其中{alerts_count}个未解决的警报。"
    
    # 调用DeepSeek API
    response = ai_assistant.ask(query, context)
    return jsonify({'response': response})

# API: 获取仪表盘数据
@app.route('/api/dashboard/summary')
@login_required
def get_dashboard_summary():
    # 获取设备状态统计
    total_devices = Device.query.count()
    online_devices = Device.query.filter_by(status='online').count()
    warning_devices = Device.query.filter_by(status='warning').count()
    error_devices = Device.query.filter_by(status='error').count()
    offline_devices = Device.query.filter_by(status='offline').count()
    
    # 未解决的警报
    unresolved_alerts = Alert.query.filter_by(resolved=False).count()
    
    # 返回汇总数据
    result = {
        'devices': {
            'total': total_devices,
            'online': online_devices,
            'warning': warning_devices,
            'error': error_devices,
            'offline': offline_devices
        },
        'alerts': {
            'unresolved': unresolved_alerts
        }
    }
    
    return jsonify(result)

# API: 获取网络性能趋势数据
@app.route('/api/dashboard/performance')
@login_required
def get_performance_trends():
    time_range = request.args.get('range', 'day')  # hour, day, week
    
    if time_range == 'hour':
        # 获取最近一小时的数据
        from_time = datetime.now().timestamp() - 3600
    elif time_range == 'day':
        # 获取最近一天的数据
        from_time = datetime.now().timestamp() - 86400
    else:
        # 获取最近一周的数据
        from_time = datetime.now().timestamp() - 604800
    
    # 获取所有设备在指定时间范围内的平均性能数据
    # 这里按一小时为间隔进行分组
    
    # 这里使用SQL获取聚合数据，实际实现可能需要根据数据库类型调整
    # 这是一个简化的实现，实际中可能需要更复杂的查询
    data = NetworkData.query.filter(NetworkData.timestamp > from_time).all()
    
    # 按照时间戳进行分组，每小时一个数据点
    hour_data = {}
    for record in data:
        # 将时间戳向下取整到小时
        hour_ts = int(record.timestamp / 3600) * 3600
        if hour_ts not in hour_data:
            hour_data[hour_ts] = {'count': 0, 'cpu': 0, 'memory': 0, 'bandwidth': 0, 'packet_loss': 0}
        
        hour_data[hour_ts]['count'] += 1
        hour_data[hour_ts]['cpu'] += record.cpu_usage
        hour_data[hour_ts]['memory'] += record.memory_usage
        hour_data[hour_ts]['bandwidth'] += record.bandwidth_usage
        hour_data[hour_ts]['packet_loss'] += record.packet_loss
    
    # 计算每小时的平均值
    result = {
        'timestamps': [],
        'cpu_usage': [],
        'memory_usage': [],
        'bandwidth_usage': [],
        'packet_loss': []
    }
    
    # 对数据进行排序
    for ts in sorted(hour_data.keys()):
        data_point = hour_data[ts]
        count = data_point['count']
        
        # 添加时间戳和平均值
        result['timestamps'].append(ts)
        result['cpu_usage'].append(round(data_point['cpu'] / count, 2) if count > 0 else 0)
        result['memory_usage'].append(round(data_point['memory'] / count, 2) if count > 0 else 0)
        result['bandwidth_usage'].append(round(data_point['bandwidth'] / count, 2) if count > 0 else 0)
        result['packet_loss'].append(round(data_point['packet_loss'] / count, 2) if count > 0 else 0)
    
    return jsonify(result)

# API: 获取设备状态分布数据
@app.route('/api/dashboard/device-status')
@login_required
def get_device_status_distribution():
    # 获取各状态设备数量
    online_count = Device.query.filter_by(status='online').count()
    warning_count = Device.query.filter_by(status='warning').count()
    error_count = Device.query.filter_by(status='error').count()
    offline_count = Device.query.filter_by(status='offline').count()
    
    result = {
        'labels': ['在线', '警告', '错误', '离线'],
        'data': [online_count, warning_count, error_count, offline_count]
    }
    
    return jsonify(result)

# API: 获取设备监控数据
@app.route('/api/device/<int:device_id>/data')
@login_required
def get_device_data(device_id):
    device = Device.query.get_or_404(device_id)
    time_range = request.args.get('range', 'hour')  # hour, day, week
    
    if time_range == 'hour':
        # 获取最近一小时的数据
        from_time = datetime.now().timestamp() - 3600
    elif time_range == 'day':
        # 获取最近一天的数据
        from_time = datetime.now().timestamp() - 86400
    else:
        # 获取最近一周的数据
        from_time = datetime.now().timestamp() - 604800
    
    data = NetworkData.query.filter(
        NetworkData.device_id == device_id,
        NetworkData.timestamp > from_time
    ).order_by(NetworkData.timestamp.asc()).all()
    
    result = {
        'timestamps': [d.timestamp for d in data],
        'cpu_usage': [d.cpu_usage for d in data],
        'memory_usage': [d.memory_usage for d in data],
        'bandwidth_usage': [d.bandwidth_usage for d in data],
        'packet_loss': [d.packet_loss for d in data]
    }
    
    return jsonify(result)

# 数据收集后台任务
def collect_data():
    with app.app_context():
        app.logger.info('数据收集后台任务启动')
        while True:
            try:
                devices = Device.query.all()
                for device in devices:
                    # 根据设备类型选择不同的收集方法
                    if device.snmp_community:
                        # 使用SNMP收集数据
                        data = snmp_collector.collect(device.ip_address, device.snmp_community)
                    else:
                        # 使用主动代理收集数据
                        data = active_agent.collect(device.ip_address)
                    
                    # 检查被动代理数据
                    passive_data = passive_agent.get_data(device.ip_address)
                    if passive_data:
                        # 合并数据
                        data.update(passive_data)
                    
                    # 存储数据
                    network_data = NetworkData(
                        device_id=device.id,
                        cpu_usage=data.get('cpu_usage', 0),
                        memory_usage=data.get('memory_usage', 0),
                        bandwidth_usage=data.get('bandwidth_usage', 0),
                        packet_loss=data.get('packet_loss', 0),
                        latency=data.get('latency', 0),
                        timestamp=datetime.now().timestamp()
                    )
                    db.session.add(network_data)
                    
                    # 检查告警条件
                    alerts = alert_manager.check_alerts(device, data)
                    for alert in alerts:
                        new_alert = Alert(
                            device_id=device.id,
                            alert_type=alert['type'],
                            message=alert['message'],
                            severity=alert['severity'],
                            timestamp=datetime.now().timestamp()
                        )
                        db.session.add(new_alert)
                
                db.session.commit()
            except Exception as e:
                app.logger.error(f'数据收集出错: {str(e)}')
            
            # 等待30秒再次收集
            time.sleep(30)

# 创建数据库表并启动后台任务
def initialize():
    with app.app_context():
        db.create_all()
        # 如果没有管理员用户，创建一个默认管理员
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
        
        # 启动数据收集后台任务
        collector_thread = threading.Thread(target=collect_data)
        collector_thread.daemon = True
        collector_thread.start()

if __name__ == '__main__':
    initialize()
    app.run(debug=True)
