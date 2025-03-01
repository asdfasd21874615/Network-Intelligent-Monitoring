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
from utils.ssh_connector import SSHConnector
from utils.network_analyzer import NetworkAnalyzer

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
network_analyzer = NetworkAnalyzer(alert_manager)

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
        location = request.form.get('location')
        description = request.form.get('description')
        
        # 检查IP地址是否已经存在
        existing_device = Device.query.filter_by(ip_address=ip_address).first()
        if existing_device:
            if 'update_existing' in request.form and request.form.get('update_existing') == '1':
                # 更新现有设备
                existing_device.name = name
                existing_device.device_type = device_type
                existing_device.snmp_community = snmp_community
                existing_device.location = location
                existing_device.description = description
                existing_device.ssh_enabled = 'ssh_enabled' in request.form
                existing_device.ssh_username = request.form.get('ssh_username')
                existing_device.ssh_password = request.form.get('ssh_password')
                existing_device.ssh_port = request.form.get('ssh_port', 22, type=int)
                existing_device.ssh_key_file = request.form.get('ssh_key_file')
                
                # 如果启用了SSH，尝试获取设备信息
                if existing_device.ssh_enabled and existing_device.ssh_username and (existing_device.ssh_password or existing_device.ssh_key_file):
                    try:
                        ssh = SSHConnector(ip_address, existing_device.ssh_username, existing_device.ssh_port)
                        
                        if existing_device.ssh_password:
                            connected = ssh.connect(password=existing_device.ssh_password)
                        else:
                            connected = ssh.connect(key_file=existing_device.ssh_key_file)
                        
                        if connected:
                            # 获取系统信息
                            system_info = ssh.get_system_info()
                            
                            # 更新设备信息
                            existing_device.os_type = system_info.get('os_type', 'unknown')
                            existing_device.os_version = system_info.get('os_version', 'unknown')
                            existing_device.ssh_last_connected = time.time()
                            existing_device.status = 'online'
                            
                            app.logger.info(f"通过SSH获取了设备信息: {existing_device.name}")
                            ssh.close()
                        else:
                            app.logger.warning(f"无法通过SSH连接到设备: {ip_address}")
                            existing_device.status = 'warning'
                    except Exception as e:
                        app.logger.error(f"SSH连接发生错误: {str(e)}")
                        existing_device.status = 'warning'
                
                db.session.commit()
                flash(f'设备 {name} ({ip_address}) 更新成功', 'success')
                return redirect(url_for('devices'))
            else:
                flash(f'设备添加失败：IP地址 {ip_address} 已经存在。您可以选择更新该设备。', 'danger')
                return render_template('add_device.html', title='添加设备', 
                                      existing_device=existing_device,
                                      form_data=request.form)
        else:
            # 获取SSH信息
            ssh_enabled = 'ssh_enabled' in request.form
            ssh_username = request.form.get('ssh_username')
            ssh_password = request.form.get('ssh_password')
            ssh_port = request.form.get('ssh_port', 22, type=int)
            ssh_key_file = request.form.get('ssh_key_file')
            
            device = Device(
                name=name, 
                ip_address=ip_address, 
                device_type=device_type, 
                snmp_community=snmp_community,
                location=location,
                description=description,
                # SSH信息
                ssh_enabled=ssh_enabled,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                ssh_port=ssh_port,
                ssh_key_file=ssh_key_file
            )
            
            # 如果启用了SSH，尝试获取设备信息
            if ssh_enabled and ssh_username and (ssh_password or ssh_key_file):
                try:
                    ssh = SSHConnector(ip_address, ssh_username, ssh_port)
                    
                    if ssh_password:
                        connected = ssh.connect(password=ssh_password)
                    else:
                        connected = ssh.connect(key_file=ssh_key_file)
                    
                    if connected:
                        # 获取系统信息
                        system_info = ssh.get_system_info()
                        
                        # 更新设备信息
                        device.os_type = system_info.get('os_type', 'unknown')
                        device.os_version = system_info.get('os_version', 'unknown')
                        device.ssh_last_connected = time.time()
                        device.status = 'online'
                        
                        app.logger.info(f"通过SSH获取了设备信息: {device.name}")
                        ssh.close()
                    else:
                        app.logger.warning(f"无法通过SSH连接到设备: {ip_address}")
                        device.status = 'warning'
                except Exception as e:
                    app.logger.error(f"SSH连接发生错误: {str(e)}")
                    device.status = 'warning'
            
            db.session.add(device)
            db.session.commit()
            flash('设备添加成功')
            return redirect(url_for('devices'))
    return render_template('add_device.html', title='添加设备')

# 路由: 编辑设备
@app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        device_type = request.form.get('device_type')
        snmp_community = request.form.get('snmp_community')
        location = request.form.get('location')
        description = request.form.get('description')
        
        # 检查IP地址是否已经存在且不是当前设备
        existing_device = Device.query.filter(Device.ip_address == ip_address, Device.id != device_id).first()
        if existing_device:
            flash(f'IP地址 {ip_address} 已被其他设备使用', 'danger')
            return render_template('edit_device.html', title='编辑设备', device=device)
            
        # 更新SSH相关字段
        ssh_enabled = request.form.get('ssh_enabled') == 'on'
        ssh_port = int(request.form.get('ssh_port', 22))
        ssh_username = request.form.get('ssh_username', '')
        ssh_password = request.form.get('ssh_password', '')
        ssh_key_file = request.form.get('ssh_key_file', '')
        
        # 更新设备信息
        device.name = name
        device.ip_address = ip_address
        device.device_type = device_type
        device.snmp_community = snmp_community
        device.location = location
        device.description = description
        device.ssh_enabled = ssh_enabled
        device.ssh_port = ssh_port
        device.ssh_username = ssh_username
        
        # 仅当用户提供了新密码时才更新密码
        if ssh_password:
            device.ssh_password = ssh_password
        
        # 仅当用户提供了新的密钥文件路径时才更新
        if ssh_key_file:
            device.ssh_key_file = ssh_key_file
        
        db.session.commit()
        flash('设备信息已更新', 'success')
        return redirect(url_for('devices'))
    
    return render_template('edit_device.html', title='编辑设备', device=device)

# 路由: 删除设备
@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    try:
        # 删除设备相关的所有监控数据
        NetworkData.query.filter_by(device_id=device_id).delete()
        
        # 删除设备相关的告警
        Alert.query.filter_by(device_id=device_id).delete()
        
        # 删除设备本身
        db.session.delete(device)
        db.session.commit()
        
        flash(f'设备 "{device.name}" 已成功删除', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"删除设备时出错: {str(e)}")
        flash(f'删除设备失败: {str(e)}', 'danger')
    
    return redirect(url_for('devices'))

# 路由: 设备详情
@app.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    # 获取该设备的最新监控数据
    recent_data = NetworkData.query.filter_by(device_id=device_id).order_by(NetworkData.timestamp.desc()).limit(100).all()
    # 获取设备相关的告警信息
    device_alerts = Alert.query.filter_by(device_id=device_id).order_by(Alert.timestamp.desc()).limit(10).all()
    return render_template('device_detail.html', title=device.name, device=device, data=recent_data, alerts=device_alerts)

# 路由: 设备SSH终端
@app.route('/device/<int:device_id>/ssh_terminal')
@login_required
def ssh_terminal(device_id):
    device = Device.query.get_or_404(device_id)
    if not device.ssh_enabled:
        flash('此设备未启用SSH连接', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))
    return render_template('ssh_terminal.html', device=device)

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
    # 获取所有设备列表，用于诊断表单的设备选择
    devices = Device.query.all()
    return render_template('ai_assistant.html', title='AI助手', devices=devices)

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

# API: 测试SSH连接
@app.route('/api/test_ssh_connection', methods=['POST'])
@login_required
def test_ssh_connection():
    data = request.get_json()
    
    if not data or not data.get('ip_address') or not data.get('username'):
        return jsonify({'success': False, 'error': '缺少必要的连接信息'}), 400
    
    ip_address = data.get('ip_address')
    username = data.get('username')
    password = data.get('password')
    port = data.get('port', 22)
    key_file = data.get('key_file')
    
    if not password and not key_file:
        return jsonify({'success': False, 'error': '需要提供密码或密钥文件'}), 400
    
    try:
        # 创建SSH连接器
        ssh = SSHConnector(ip_address, username, port)
        
        # 尝试连接
        if password:
            connected = ssh.connect(password=password)
        else:
            connected = ssh.connect(key_file=key_file)
        
        if connected:
            # 测试连接是否可用
            if ssh.test_connection():
                # 尝试获取一些基本系统信息
                system_info = ssh.get_system_info()
                
                ssh.close()
                
                return jsonify({
                    'success': True, 
                    'message': '连接成功', 
                    'system_info': system_info
                })
            else:
                ssh.close()
                return jsonify({'success': False, 'error': '无法执行命令'})
        else:
            return jsonify({'success': False, 'error': '连接失败，请检查凭据'})
    
    except Exception as e:
        app.logger.error(f"测试SSH连接时出错: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# API: 在设备上执行SSH命令
@app.route('/api/device/<int:device_id>/execute', methods=['POST'])
@login_required
def execute_device_command(device_id):
    device = Device.query.get_or_404(device_id)
    
    if not device.ssh_enabled:
        return jsonify({'success': False, 'error': '此设备未启用SSH连接'}), 400
    
    data = request.get_json()
    command = data.get('command')
    
    if not command:
        return jsonify({'success': False, 'error': '缺少命令参数'}), 400
    
    try:
        # 创建SSH连接器
        ssh = SSHConnector(device.ip_address, device.ssh_username, device.ssh_port)
        
        # 尝试连接
        if device.ssh_password:
            connected = ssh.connect(password=device.ssh_password)
        elif device.ssh_key_file:
            connected = ssh.connect(key_file=device.ssh_key_file)
        else:
            return jsonify({'success': False, 'error': '设备缺少SSH登录凭据'}), 400
        
        if connected:
            # 执行命令
            exit_code, output, error = ssh.execute_command(command)
            ssh.close()
            
            # 更新设备最后连接时间
            device.ssh_last_connected = time.time()
            db.session.commit()
            
            return jsonify({
                'success': exit_code == 0,
                'exit_code': exit_code,
                'output': output,
                'error': error
            })
        else:
            return jsonify({'success': False, 'error': '无法连接到设备'})
    
    except Exception as e:
        app.logger.error(f"执行SSH命令时出错: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# API: 获取设备命令模板
@app.route('/api/device/<int:device_id>/command_templates', methods=['GET'])
@login_required
def get_command_templates(device_id):
    from utils.ssh_command_templates import get_all_commands, get_command_categories, get_device_types
    
    device = Device.query.get_or_404(device_id)
    
    # 默认为Linux设备类型
    device_type = "linux"
    
    # 尝试从设备属性中获取设备类型
    if hasattr(device, 'device_type') and device.device_type:
        device_type = device.device_type
    
    # 如果设备类型不在支持的列表中，使用默认值
    if device_type not in get_device_types():
        device_type = "linux"
    
    # 按类别获取命令
    templates = {}
    for category in get_command_categories(device_type):
        from utils.ssh_command_templates import get_commands
        templates[category] = get_commands(device_type, category)
    
    return jsonify({
        'success': True,
        'device_id': device_id,
        'device_type': device_type,
        'templates': templates
    })

# API: 测试设备的SSH连接
@app.route('/api/device/<int:device_id>/test_ssh_connection', methods=['GET'])
@login_required
def test_device_ssh_connection(device_id):
    device = Device.query.get_or_404(device_id)
    
    if not device.ssh_enabled:
        return jsonify({'success': False, 'message': '此设备未启用SSH连接'}), 400
    
    if not device.ssh_username:
        return jsonify({'success': False, 'message': '缺少SSH用户名'}), 400
    
    if not device.ssh_password and not device.ssh_key_file:
        return jsonify({'success': False, 'message': '需要提供SSH密码或密钥文件'}), 400
    
    try:
        # 创建SSH连接器
        ssh = SSHConnector(device.ip_address, device.ssh_username, device.ssh_port)
        
        # 尝试连接
        if device.ssh_password:
            connected = ssh.connect(password=device.ssh_password, timeout=5)
        else:
            connected = ssh.connect(key_file=device.ssh_key_file, timeout=5)
        
        if connected:
            # 测试连接是否可用
            if ssh.test_connection():
                # 尝试获取系统信息以检测设备类型
                system_info = ssh.get_system_info()
                
                # 更新最后连接时间
                device.ssh_last_connected = time.time()
                
                # 使用新的设备类型检测方法
                device_type = ssh.detect_device_type()
                
                # 如果成功检测到设备类型且设备当前没有设置类型，则更新设备类型
                if device_type != "unknown" and (not device.device_type or device.device_type == "unknown"):
                    device.device_type = device_type
                
                db.session.commit()
                
                ssh.close()
                
                return jsonify({
                    'success': True,
                    'message': '连接成功！',
                    'system_info': system_info,
                    'device_type': device_type
                })
            else:
                ssh.close()
                return jsonify({'success': False, 'message': '连接测试失败'})
        else:
            return jsonify({'success': False, 'message': '无法建立SSH连接'})
            
    except Exception as e:
        app.logger.error(f"测试SSH连接时出错: {str(e)}")
        return jsonify({'success': False, 'message': f'连接错误: {str(e)}'})

# API: 自动检测设备类型
@app.route('/api/device/<int:device_id>/detect_type', methods=['POST'])
@login_required
def detect_device_type(device_id):
    device = Device.query.get_or_404(device_id)
    
    if not device.ssh_enabled:
        return jsonify({'success': False, 'message': '此设备未启用SSH连接，无法检测设备类型'}), 400
    
    try:
        # 创建SSH连接器
        ssh = SSHConnector(device.ip_address, device.ssh_username, device.ssh_port)
        
        # 尝试连接
        if device.ssh_password:
            connected = ssh.connect(password=device.ssh_password, timeout=5)
        else:
            connected = ssh.connect(key_file=device.ssh_key_file, timeout=5)
        
        if not connected:
            return jsonify({'success': False, 'message': '无法建立SSH连接'}), 400
        
        # 检测设备类型
        device_type = ssh.detect_device_type()
        
        if device_type == "unknown":
            ssh.close()
            return jsonify({'success': False, 'message': '无法检测设备类型'}), 400
        
        # 更新设备类型
        old_type = device.device_type
        device.device_type = device_type
        device.ssh_last_connected = time.time()
        db.session.commit()
        
        ssh.close()
        
        return jsonify({
            'success': True, 
            'message': f'设备类型检测成功，从 "{old_type or "未知"}" 更新为 "{device_type}"',
            'device_type': device_type
        })
        
    except Exception as e:
        app.logger.error(f"检测设备类型时出错: {str(e)}")
        return jsonify({'success': False, 'message': f'检测设备类型时出错: {str(e)}'}), 500

# API: 获取设备性能分析
@app.route('/api/device/<int:device_id>/analysis', methods=['GET'])
@login_required
def get_device_analysis(device_id):
    """获取特定设备的性能分析和建议"""
    time_range = request.args.get('time_range', 'day')
    analysis = network_analyzer.analyze_device_performance(device_id, time_range)
    return jsonify(analysis)

# API: 诊断网络问题
@app.route('/api/device/diagnose', methods=['POST'])
@login_required
def diagnose_device_issue():
    # 诊断设备网络问题
    data = request.get_json()
    device_id = data.get('device_id')
    issue_description = data.get('issue_description')
    
    if not device_id or not issue_description:
        return jsonify({'success': False, 'message': '设备ID和问题描述为必填项'}), 400
    
    # 使用NetworkAnalyzer进行诊断
    diagnosis_result = network_analyzer.diagnose_network_issue(device_id, issue_description)
    return jsonify(diagnosis_result)

# 路由: 网络分析与建议
@app.route('/network_analysis')
@login_required
def network_analysis():
    """显示网络分析和优化建议页面"""
    health_data = network_analyzer.analyze_network_health()
    optimization_suggestions = network_analyzer.get_optimization_suggestions()
    
    # 获取所有设备以便用户选择查看详细分析
    devices = Device.query.all()
    
    return render_template('network_analysis.html', 
                           title='网络分析与建议',
                           health_data=health_data,
                           devices=devices,
                           suggestions=optimization_suggestions)

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
