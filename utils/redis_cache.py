import redis
import json
import logging
from functools import wraps

class RedisCache:
    def __init__(self, app=None):
        self.app = app
        self.redis_client = None
        self.default_ttl = 3600  # 默认缓存时间1小时
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """初始化Redis连接"""
        self.app = app
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        self.default_ttl = app.config.get('REDIS_TTL', 3600)
        
        try:
            self.redis_client = redis.from_url(redis_url)
            # 测试连接
            self.redis_client.ping()
            app.logger.info("Redis连接成功")
        except redis.exceptions.ConnectionError as e:
            app.logger.error(f"Redis连接失败: {str(e)}")
            self.redis_client = None
    
    def get(self, key):
        """从Redis获取数据"""
        if self.redis_client is None:
            return None
        
        try:
            data = self.redis_client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            self.app.logger.error(f"Redis获取数据失败: {str(e)}")
            return None
    
    def set(self, key, value, ttl=None):
        """将数据存储到Redis"""
        if self.redis_client is None:
            return False
        
        if ttl is None:
            ttl = self.default_ttl
        
        try:
            self.redis_client.setex(key, ttl, json.dumps(value))
            return True
        except Exception as e:
            self.app.logger.error(f"Redis存储数据失败: {str(e)}")
            return False
    
    def delete(self, key):
        """删除缓存数据"""
        if self.redis_client is None:
            return False
        
        try:
            self.redis_client.delete(key)
            return True
        except Exception as e:
            self.app.logger.error(f"Redis删除数据失败: {str(e)}")
            return False
    
    def clear(self, pattern="*"):
        """清除所有或匹配模式的缓存"""
        if self.redis_client is None:
            return False
        
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                self.redis_client.delete(*keys)
            return True
        except Exception as e:
            self.app.logger.error(f"Redis清除缓存失败: {str(e)}")
            return False
    
    def cached(self, key_prefix, ttl=None):
        """装饰器：缓存函数返回值
        
        用法示例:
        @redis_cache.cached('dashboard_summary')
        def get_dashboard_summary():
            # 函数逻辑
            return data
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # 生成缓存键
                key = f"{key_prefix}:{f.__name__}"
                if args:
                    key += f":{':'.join(str(arg) for arg in args)}"
                if kwargs:
                    key += f":{':'.join(f'{k}={v}' for k, v in kwargs.items())}"
                
                # 尝试从缓存获取
                cached_data = self.get(key)
                if cached_data is not None:
                    return cached_data
                
                # 如果缓存中没有，执行原函数
                data = f(*args, **kwargs)
                
                # 缓存结果
                self.set(key, data, ttl)
                
                return data
            return decorated_function
        return decorator

# 实例化Redis缓存
redis_cache = RedisCache()
