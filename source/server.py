#!/usr/bin/env python3
import json
import logging
import os
import time
import asyncio
import websockets
import psutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Set, Any
from collections import defaultdict
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import re
import ssl
from enum import Enum
import signal  # Added missing import
from aiohttp import web

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}

@dataclass(frozen=True)
class SecurityConfig:
    cors_origin: str = os.getenv("CORS_ALLOWED_ORIGIN", "*")
    ws_auth_token: str = os.getenv("WS_AUTH_TOKEN", "secret-token")
    ssl_cert_file: Optional[str] = os.getenv("SSL_CERT_FILE")
    ssl_key_file: Optional[str] = os.getenv("SSL_KEY_FILE")
    allowed_ips: List[str] = field(default_factory=lambda: os.getenv("ALLOWED_IPS", "").split(",") if os.getenv("ALLOWED_IPS") else [])
    max_request_size: int = int(os.getenv("MAX_REQUEST_SIZE", "1048576"))

    def __post_init__(self):
        if self.cors_origin != "*" and not re.match(r'^https?://[\w\-\.]+(:\d+)?$', self.cors_origin):
            raise ValueError(f"Invalid CORS origin: {self.cors_origin}")
        if self.ssl_cert_file and not Path(self.ssl_cert_file).exists():
            raise ValueError(f"SSL certificate file not found: {self.ssl_cert_file}")
        if self.ssl_key_file and not Path(self.ssl_key_file).exists():
            raise ValueError(f"SSL key file not found: {self.ssl_key_file}")

@dataclass(frozen=True)
class RateLimitConfig:
    http_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    http_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    ws_requests: int = int(os.getenv("WS_RATE_LIMIT_REQUESTS", "10"))
    ws_window: int = int(os.getenv("WS_RATE_LIMIT_WINDOW", "60"))
    ws_connection_limit: int = int(os.getenv("WS_CONNECTION_LIMIT", "100"))

    def __post_init__(self):
        if any(x <= 0 for x in [self.http_requests, self.http_window, self.ws_requests, self.ws_window, self.ws_connection_limit]):
            raise ValueError("All rate limit values must be positive")

@dataclass(frozen=True)
class ServerConfig:
    host: str = os.getenv("TCP_SERVER_HOST", "0.0.0.0")
    port: int = int(os.getenv("TCP_SERVER_PORT", "3333"))
    ws_port: int = int(os.getenv("WS_PORT", "3334"))
    static_dir: Path = Path(os.getenv("STATIC_DIR", "."))
    server_version: str = os.getenv("SERVER_VERSION", "2.1.0")
    cache_duration: float = float(os.getenv("CACHE_DURATION", "0.5"))
    config_file: Optional[str] = os.getenv("CONFIG_FILE")
    log_level: LogLevel = LogLevel(os.getenv("LOG_LEVEL", "INFO"))
    shutdown_timeout: int = int(os.getenv("SHUTDOWN_TIMEOUT", "5"))

    def __post_init__(self):
        if not 0 < self.port <= 65535 or not 0 < self.ws_port <= 65535:
            raise ValueError(f"Invalid port number: {self.port} or {self.ws_port}")
        if not self.static_dir.exists() or not self.static_dir.is_dir():
            raise ValueError(f"Static directory {self.static_dir} does not exist or is not a directory")
        if self.cache_duration <= 0:
            raise ValueError(f"Invalid cache duration: {self.cache_duration}")
        if self.config_file:
            self._load_config_file()

    def _load_config_file(self):
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
                for key, value in config_data.items():
                    if hasattr(self, key):
                        object.__setattr__(self, key, value)
        except Exception as e:
            raise ValueError(f"Failed to load config file {self.config_file}: {str(e)}")

class RateLimiter:
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_ip: str, endpoint: str) -> bool:
        async with self._lock:
            key = (client_ip, endpoint)
            now = datetime.now()
            self.clients[key] = [
                t for t in self.clients[key]
                if now - t < timedelta(seconds=self.window)
            ]
            if len(self.clients[key]) >= self.requests:
                return False
            self.clients[key].append(now)
            return True

class TCPStateCache:
    def __init__(self, cache_duration: float):
        self.cache_duration = cache_duration
        self.last_update = 0.0
        self.cache: Optional[Dict[str, int]] = None
        self._lock = asyncio.Lock()

    async def get_states(self) -> Dict[str, int]:
        async with self._lock:
            now = time.time()
            if self.cache is None or now - self.last_update >= self.cache_duration:
                self.cache = await self._parse_tcp_states()
                self.last_update = now
            return self.cache.copy()

    async def _parse_tcp_states(self) -> Dict[str, int]:
        files = []
        if Path("/proc/net/tcp").exists():
            files.append("/proc/net/tcp")
        if Path("/proc/net/tcp6").exists():
            files.append("/proc/net/tcp6")
        
        if not files:
            logging.error("No TCP proc files found")
            return {name: 0 for name in TCP_STATES.values()}
        
        state_count = {name: 0 for name in TCP_STATES.values()}
        state_count["UNKNOWN"] = 0

        for file in files:
            try:
                with open(file, "r", encoding="utf-8") as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) < 12 or not re.match(r'^[0-9A-F]{2}$', parts[3]):
                            continue
                        state_code = parts[3]
                        state_name = TCP_STATES.get(state_code, "UNKNOWN")
                        state_count[state_name] += 1
            except Exception as e:
                logging.error(f"Error parsing {file}: {e}")
        return state_count

class ConnectionManager:
    def __init__(self, max_connections: int = 100):
        self.max_connections = max_connections
        self.connections: Set[websockets.WebSocketServerProtocol] = set()
        self._lock = asyncio.Lock()

    async def add_connection(self, websocket: websockets.WebSocketServerProtocol) -> bool:
        async with self._lock:
            if len(self.connections) >= self.max_connections:
                return False
            self.connections.add(websocket)
            return True

    async def remove_connection(self, websocket: websockets.WebSocketServerProtocol):
        async with self._lock:
            self.connections.discard(websocket)

    async def get_count(self) -> int:
        async with self._lock:
            return len(self.connections)

    async def broadcast(self, message: str):
        async with self._lock:
            disconnected = set()
            for ws in self.connections:
                try:
                    await ws.send(message)
                except websockets.exceptions.ConnectionClosed:
                    disconnected.add(ws)
            for ws in disconnected:
                self.connections.discard(ws)

    async def close_all(self):
        async with self._lock:
            for ws in self.connections:
                await ws.close(code=1001, reason="Server shutdown")
            self.connections.clear()

class HTTPServer:
    def __init__(self, config: ServerConfig, security: SecurityConfig, 
                 rate_limiter: RateLimiter, server_start_time: float,
                 tcp_cache: TCPStateCache, connection_manager: ConnectionManager):
        self.config = config
        self.security = security
        self.rate_limiter = rate_limiter
        self.server_start_time = server_start_time
        self.tcp_cache = tcp_cache
        self.connection_manager = connection_manager
        self.app = web.Application()
        self.runner = None
        self.site = None
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_get('/tcpstates', self.handle_tcp_states)
        self.app.router.add_get('/health', self.handle_health_check)
        self.app.router.add_get('/metrics', self.handle_metrics)
        self.app.router.add_get('/ws/info', self.handle_ws_info)
        self.app.router.add_static('/', self.config.static_dir)

    async def _check_ip_allowlist(self, request: web.Request) -> bool:
        if not self.security.allowed_ips:
            return True
        client_ip = request.remote
        return client_ip in self.security.allowed_ips

    async def handle_tcp_states(self, request: web.Request):
        if not await self._check_ip_allowlist(request):
            return web.json_response({"error": "Forbidden", "details": "IP address not allowed"}, status=403)

        client_ip = request.remote
        if not await self.rate_limiter.is_allowed(client_ip, "/tcpstates"):
            return web.json_response({"error": "Too Many Requests"}, status=429)

        stats = await self.tcp_cache.get_states()
        return web.json_response({
            "timestamp": int(time.time()),
            "tcp_states": stats,
            "server": "TCP Monitoring Service",
            "version": self.config.server_version
        })

    async def handle_health_check(self, request: web.Request):
        if not await self._check_ip_allowlist(request):
            return web.json_response({"error": "Forbidden", "details": "IP address not allowed"}, status=403)

        client_ip = request.remote
        if not await self.rate_limiter.is_allowed(client_ip, "/health"):
            return web.json_response({"error": "Too Many Requests"}, status=429)

        try:
            stats = await self.tcp_cache.get_states()
            ws_count = await self.connection_manager.get_count()
            return web.json_response({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(stats.values()),
                "memory_usage": psutil.virtual_memory().percent,
                "cpu_usage": psutil.cpu_percent(interval=None),
                "websocket_connections": ws_count,
                "uptime": int(time.time() - self.server_start_time),
                "cache_hit": self.tcp_cache.cache is not None
            })
        except Exception as e:
            return web.json_response({"error": "Service unavailable", "details": str(e)}, status=503)

    async def handle_metrics(self, request: web.Request):
        if not await self._check_ip_allowlist(request):
            return web.json_response({"error": "Forbidden", "details": "IP address not allowed"}, status=403)

        client_ip = request.remote
        if not await self.rate_limiter.is_allowed(client_ip, "/metrics"):
            return web.json_response({"error": "Too Many Requests"}, status=429)

        stats = await self.tcp_cache.get_states()
        ws_count = await self.connection_manager.get_count()
        
        metrics = [
            "# HELP tcp_connections_total Total TCP connections by state",
            "# TYPE tcp_connections_total gauge"
        ]
        
        for state, count in stats.items():
            metrics.append(f'tcp_connections_total{{state="{state}"}} {count}')
        
        metrics.extend([
            "# HELP websocket_connections_active Active WebSocket connections",
            "# TYPE websocket_connections_active gauge",
            f'websocket_connections_active {ws_count}',
            "# HELP server_uptime_seconds Server uptime in seconds",
            "# TYPE server_uptime_seconds gauge",
            f'server_uptime_seconds {int(time.time() - self.server_start_time)}',
            "# HELP server_memory_usage_percent Server memory usage percentage",
            "# TYPE server_memory_usage_percent gauge",
            f'server_memory_usage_percent {psutil.virtual_memory().percent}',
            "# HELP server_cpu_usage_percent Server CPU usage percentage",
            "# TYPE server_cpu_usage_percent gauge",
            f'server_cpu_usage_percent {psutil.cpu_percent(interval=None)}'
        ])
        
        return web.Response(text="\n".join(metrics), content_type="text/plain")

    async def handle_ws_info(self, request: web.Request):
        if not await self._check_ip_allowlist(request):
            return web.json_response({"error": "Forbidden", "details": "IP address not allowed"}, status=403)

        client_ip = request.remote
        if not await self.rate_limiter.is_allowed(client_ip, "/ws/info"):
            return web.json_response({"error": "Too Many Requests"}, status=429)

        ws_count = await self.connection_manager.get_count()
        return web.json_response({
            "websocket_connections": ws_count,
            "max_connections": self.connection_manager.max_connections,
            "ws_endpoint": f"ws://{self.config.host}:{self.config.ws_port}/ws/tcpstates"
        })

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        ssl_context = None
        if self.security.ssl_cert_file and self.security.ssl_key_file:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.security.ssl_cert_file, self.security.ssl_key_file)

        self.site = web.TCPSite(self.runner, self.config.host, self.config.port, ssl_context=ssl_context)
        await self.site.start()
        logging.info(f"HTTP Server started on http://{self.config.host}:{self.config.port}")

    async def stop(self):
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        logging.info("HTTP server stopped")

async def websocket_handler(websocket, path, config: ServerConfig, security: SecurityConfig, 
                          ws_rate_limiter: RateLimiter, tcp_cache: TCPStateCache, 
                          connection_manager: ConnectionManager):
    client_ip = websocket.remote_address[0]
    logging.info(f"WebSocket client connected from {client_ip}")
    
    if not await connection_manager.add_connection(websocket):
        await websocket.close(code=1013, reason="Too many connections")
        return

    try:
        if path != "/ws/tcpstates":
            await websocket.send(json.dumps({"error": "Invalid WebSocket path"}))
            return
        
        auth_token = websocket.request_headers.get("Authorization")
        if auth_token != f"Bearer {security.ws_auth_token}":
            await websocket.send(json.dumps({"error": "Unauthorized", "details": "Invalid or missing auth token"}))
            return
        
        if not await ws_rate_limiter.is_allowed(client_ip, path):
            await websocket.send(json.dumps({
                "error": "Too Many Requests",
                "details": f"WebSocket rate limit exceeded: {config.ws_rate_limit_requests} connections per {config.ws_rate_limit_window} seconds"
            }))
            return
        
        await websocket.send(json.dumps({"type": "connected", "message": "WebSocket connection established"}))
        
        while True:
            stats = await tcp_cache.get_states()
            response = json.dumps({ 
                "timestamp": int(time.time()), 
                "tcp_states": stats, 
                "type": "tcp_state_update",
                "server_version": config.server_version
            })
            await websocket.send(response)
            await asyncio.sleep(1)
            
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"WebSocket connection closed from {client_ip}")
    except Exception as e:
        logging.error(f"WebSocket error for {client_ip}: {e}")
        try:
            await websocket.send(json.dumps({"error": "Internal server error", "type": "error"}))
        except:
            pass
    finally:
        await connection_manager.remove_connection(websocket)

def configure_logging(log_level: LogLevel = LogLevel.INFO):
    logger = logging.getLogger()
    logger.setLevel(log_level.value)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    
    file_handler = RotatingFileHandler(
        "server.log",
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)

class ServerManager:
    def __init__(self, config: ServerConfig, security: SecurityConfig, rate_config: RateLimitConfig):
        self.config = config
        self.security = security
        self.rate_config = rate_config
        self.http_server = None
        self.ws_server = None
        self.connection_manager = ConnectionManager(rate_config.ws_connection_limit)
        self.tcp_cache = TCPStateCache(config.cache_duration)
        self.http_rate_limiter = RateLimiter(rate_config.http_requests, rate_config.http_window)
        self.ws_rate_limiter = RateLimiter(rate_config.ws_requests, rate_config.ws_window)
        self.server_start_time = time.time()

    async def start_servers(self):
        # Start HTTP server
        self.http_server = HTTPServer(
            self.config, self.security, self.http_rate_limiter,
            self.server_start_time, self.tcp_cache, self.connection_manager
        )
        await self.http_server.start()
        
        # Start WebSocket server
        ssl_context = None
        if self.security.ssl_cert_file and self.security.ssl_key_file:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(self.security.ssl_cert_file, self.security.ssl_key_file)

        self.ws_server = await websockets.serve(
            lambda ws, path: websocket_handler(ws, path, self.config, self.security, 
                                             self.ws_rate_limiter, self.tcp_cache, 
                                             self.connection_manager),
            self.config.host, 
            self.config.ws_port,
            ssl=ssl_context,
            ping_interval=20,
            ping_timeout=60
        )
        
        logging.info(f"WebSocket Server started on ws://{self.config.host}:{self.config.ws_port}")
        if ssl_context:
            logging.info(f"SSL/TLS enabled for WebSocket connections")

    async def shutdown(self):
        logging.info("Initiating server shutdown")
        
        # Shutdown WebSocket server first
        if self.ws_server:
            logging.info("Shutting down WebSocket server...")
            self.ws_server.close()
            await asyncio.wait_for(self.ws_server.wait_closed(), timeout=self.config.shutdown_timeout)
            logging.info("WebSocket server shut down")
        
        # Close all WebSocket connections
        logging.info("Closing WebSocket connections...")
        await self.connection_manager.close_all()
        
        # Shutdown HTTP server
        if self.http_server:
            logging.info("Shutting down HTTP server...")
            await self.http_server.stop()
            logging.info("HTTP server shut down")
        
        logging.info("Server shutdown complete")

async def main():
    configure_logging()
    
    try:
        config = ServerConfig()
        security = SecurityConfig()
        rate_config = RateLimitConfig()
    except ValueError as e:
        logging.critical(f"Configuration error: {e}")
        return 1

    server_manager = ServerManager(config, security, rate_config)
    
    # Create shutdown event
    shutdown_event = asyncio.Event()
    
    # Set up signal handlers using asyncio
    def signal_handler():
        logging.info("Received shutdown signal")
        shutdown_event.set()
    
    loop = asyncio.get_running_loop()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        await server_manager.start_servers()
        logging.info("Servers started. Press Ctrl+C to stop.")
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        logging.info("Shutdown signal received")
        
    except KeyboardInterrupt:
        logging.info("Received KeyboardInterrupt directly")
    except Exception as e:
        logging.critical(f"Server failure: {e}")
        return 1
    finally:
        await server_manager.shutdown()
    
    logging.info("Server stopped successfully")
    return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))
