"""
Add SSH fields to Device model

This migration script adds SSH connectivity fields to the Device model.
"""
import sqlite3
import sys
import os
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """
    执行数据库迁移，添加Device表的SSH字段
    """
    try:
        # 连接到SQLite数据库
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 检查数据库是否存在
        logger.info(f"连接到数据库: {db_path}")
        
        # 检查device表是否有ssh_enabled字段
        cursor.execute("PRAGMA table_info(device)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        # 如果没有新字段，添加它们
        if 'ssh_enabled' not in column_names:
            logger.info("添加SSH字段到device表...")
            
            # 添加ssh_enabled字段
            cursor.execute("ALTER TABLE device ADD COLUMN ssh_enabled BOOLEAN DEFAULT 0")
            
            # 添加ssh_username字段
            cursor.execute("ALTER TABLE device ADD COLUMN ssh_username VARCHAR(64)")
            
            # 添加ssh_password字段
            cursor.execute("ALTER TABLE device ADD COLUMN ssh_password VARCHAR(128)")
            
            # 添加ssh_port字段
            cursor.execute("ALTER TABLE device ADD COLUMN ssh_port INTEGER DEFAULT 22")
            
            # 添加ssh_key_file字段
            cursor.execute("ALTER TABLE device ADD COLUMN ssh_key_file VARCHAR(256)")
            
            # 添加ssh_last_connected字段
            cursor.execute("ALTER TABLE device ADD COLUMN ssh_last_connected FLOAT")
            
            # 提交更改
            conn.commit()
            logger.info("迁移成功完成")
        else:
            logger.info("SSH字段已存在，无需迁移")
        
    except sqlite3.Error as e:
        logger.error(f"数据库错误: {e}")
        return 1
    except Exception as e:
        logger.error(f"执行迁移时出错: {e}")
        return 1
    finally:
        # 关闭连接
        if conn:
            conn.close()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
