# Redis 集成指南

本项目已经集成了 Redis 作为缓存系统，用于提高应用程序性能和响应速度。以下是安装和配置 Redis 的步骤。

## Windows 安装 Redis

Windows 系统上安装 Redis 有两种主要方式：

### 方法 1：使用 Redis Windows 版本（推荐）

1. 下载 Windows 版的 Redis: https://github.com/tporadowski/redis/releases
2. 下载 `.msi` 安装文件并运行安装
3. 安装完成后，Redis 服务会自动启动
4. 可以在服务管理器中查看 Redis 服务是否正在运行

### 方法 2：使用 WSL (Windows Subsystem for Linux)

1. 启用 WSL（Windows Subsystem for Linux）
2. 安装 Ubuntu 发行版
3. 在 Ubuntu 中安装 Redis：
   ```bash
   sudo apt update
   sudo apt install redis-server
   ```
4. 启动 Redis 服务：
   ```bash
   sudo service redis-server start
   ```

### 方法 3：使用 Docker

1. 安装 Docker Desktop for Windows
2. 运行 Redis 容器：
   ```bash
   docker run --name my-redis -p 6379:6379 -d redis
   ```

## 验证 Redis 安装

安装完成后，可以通过以下方式验证 Redis 是否正常工作：

1. 打开命令行，运行 `redis-cli`
2. 输入 `ping`，应该得到 `PONG` 的响应
3. 也可以通过简单的 SET 和 GET 命令测试：
   ```
   SET test "Hello, Redis!"
   GET test
   ```

## 项目配置

本项目已经配置好了 Redis 连接，默认连接到 `localhost:6379`。如果需要修改连接参数，请编辑 `config.py` 文件中的以下配置：

```python
# Redis配置
REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
REDIS_TTL = int(os.environ.get('REDIS_TTL') or 3600)  # 默认缓存过期时间（秒）
```

您也可以通过设置环境变量 `REDIS_URL` 来自定义 Redis 连接，例如：

```
REDIS_URL=redis://username:password@your-redis-server:6379/0
```

## Redis 缓存功能

本项目中的 Redis 缓存主要用于以下功能：

1. **API 响应缓存**：减少数据库查询，提高响应速度
2. **用户会话数据**：保存用户设置和偏好
3. **仪表盘数据缓存**：缓存仪表盘统计数据，减轻数据库压力

## 管理缓存

项目提供了缓存管理 API，可以用于清除特定类型的缓存：

- 清除所有缓存：`POST /api/cache/clear` 设置 `{"type": "all"}`
- 清除仪表盘缓存：`POST /api/cache/clear` 设置 `{"type": "dashboard"}`
- 清除特定设备缓存：`POST /api/cache/clear` 设置 `{"type": "device", "device_id": 设备ID}`

## 故障排除

如果 Redis 连接失败，应用程序会回退到无缓存模式，所有操作将直接访问数据库。日志文件中会记录 Redis 连接错误信息。
