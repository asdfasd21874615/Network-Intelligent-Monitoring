"""
数据库迁移脚本
用于更新现有数据库结构以匹配当前模型
"""

import os
import sys
import sqlite3
from datetime import datetime

# 添加项目根目录到sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db

def migrate_database():
    """迁移数据库结构"""
    with app.app_context():
        # 获取数据库文件路径
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        
        print(f"正在迁移数据库: {db_path}")
        
        # 连接到SQLite数据库
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 检查并添加User表中的新字段
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [column[1] for column in cursor.fetchall()]
        
        if 'role' not in user_columns:
            print("添加 User.role 字段")
            cursor.execute("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'user'")
        
        if 'name' not in user_columns:
            print("添加 User.name 字段")
            cursor.execute("ALTER TABLE user ADD COLUMN name VARCHAR(64)")
        
        if 'created_at' not in user_columns:
            print("添加 User.created_at 字段")
            cursor.execute("ALTER TABLE user ADD COLUMN created_at FLOAT")
        elif any(column[1] == 'created_at' and column[2] != 'FLOAT' for column in cursor.fetchall()):
            # 如果created_at已存在但类型不是FLOAT
            print("更新 User.created_at 字段类型为 FLOAT")
            cursor.execute("DROP TABLE user_backup")
            cursor.execute("CREATE TABLE user_backup AS SELECT * FROM user")
            cursor.execute("DROP TABLE user")
            # 重新创建表
            cursor.execute("""
            CREATE TABLE user (
                id INTEGER PRIMARY KEY,
                username VARCHAR(64) UNIQUE,
                email VARCHAR(120) UNIQUE,
                password_hash VARCHAR(128),
                role VARCHAR(20) DEFAULT 'user',
                name VARCHAR(64),
                created_at FLOAT,
                last_login FLOAT
            )
            """)
            # 复制数据
            cursor.execute("""
            INSERT INTO user 
            SELECT id, username, email, password_hash, role, name, 
                   strftime('%s', created_at) AS created_at, 
                   strftime('%s', last_login) AS last_login
            FROM user_backup
            """)
            cursor.execute("DROP TABLE user_backup")
        
        if 'last_login' not in user_columns:
            print("添加 User.last_login 字段")
            cursor.execute("ALTER TABLE user ADD COLUMN last_login FLOAT")
        
        # 检查并添加Device表中的新字段
        cursor.execute("PRAGMA table_info(device)")
        device_columns = [column[1] for column in cursor.fetchall()]
        
        if 'os_type' not in device_columns:
            print("添加 Device.os_type 字段")
            cursor.execute("ALTER TABLE device ADD COLUMN os_type VARCHAR(32)")
        
        if 'os_version' not in device_columns:
            print("添加 Device.os_version 字段")
            cursor.execute("ALTER TABLE device ADD COLUMN os_version VARCHAR(64)")
        
        # 提交更改
        conn.commit()
        
        # 关闭连接
        cursor.close()
        conn.close()
        
        print("数据库迁移完成")

if __name__ == '__main__':
    migrate_database()
