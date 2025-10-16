#!/usr/bin/env python3
import json
import logging
import os
import time
import asyncio
import websockets
import psutil
from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Set, Any
from collections import defaultdict
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import re
import ssl
from enum import Enum
import signal

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

class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, config: ServerConfig, security: SecurityConfig, 
                 rate_limiter: RateLimiter, server_start_time: float, 
                 tcp_cache: TCPStateCache, connection_manager: ConnectionManager, **kwargs):
        self.config = config
        self.security = security
        self.rate_limiter = rate_limiter
        self.server_start_time = server_start_time
        self.tcp_cache = tcp_cache
        self.connection_manager = connection_manager
        super().__init__(*args, directory=str(self.config.static_dir), **kwargs)

    def _check_ip_allowlist(self) -> bool:
        if not self.security.allowed_ips:
            return True
        return self.client_address[0] in self.security.allowed_ips

    def _send_response(self, content: bytes, content_type: str = "application/json", status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", self.security.cors_origin)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Cache-Control", "no-store, no-cache")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.end_headers()
        self.wfile.write(content)

    def _send_error_response(self, status: int, message: str, details: Optional[str] = None):
        error_data = {
            "error": message,
            "status": status,
            "timestamp": int(time.time()),
            "details": details or "No additional details available"
        }
        self._send_response(json.dumps(error_data).encode("utf-8"), status=status)

    def do_GET(self):
        asyncio.run(self._handle_request_async())

    async def _handle_request_async(self):
        try:
            if not self._check_ip_allowlist():
                return self._send_error_response(403, "Forbidden", "IP address not allowed")

            endpoint = self.path.split('?', 1)[0] or "/"
            
            if not await self.rate_limiter.is_allowed(self.client_address[0], endpoint):
                return self._send_error_response(429, "Too Many Requests", 
                    f"Rate limit exceeded: {self.config.rate_limit_requests} requests per {self.config.rate_limit_window} seconds")

            if len(self.path) > 256:
                return self._send_error_response(414, "Request URI too long")

            if self.path == "/tcpstates":
                await self._handle_tcp_states()
            elif self.path == "/health":
                await self._handle_health_check()
            elif self.path == "/metrics":
                await self._handle_metrics()
            elif self.path == "/ws/info":
                await self._handle_ws_info()
            else:
                self._handle_static()

        except Exception as e:
            logging.exception(f"Request processing failed for {self.client_address[0]}: {e}")
            self._send_error_response(500, "Internal server error", str(e))

    async def _handle_tcp_states(self):
        stats = await self.tcp_cache.get_states()
        response = json.dumps({
            "timestamp": int(time.time()),
            "tcp_states": stats,
            "server": "TCP Monitoring Service",
            "version": self.config.server_version
        }).encode("utf-8")
        self._send_response(response)

    async def _handle_health_check(self):
        try:
            stats = await self.tcp_cache.get_states()
            ws_count = await self.connection_manager.get_count()
            response = json.dumps({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(stats.values()),
                "memory_usage": psutil.virtual_memory().percent,
                "cpu_usage": psutil.cpu_percent(interval=None),
                "websocket_connections": ws_count,
                "uptime": int(time.time() - self.server_start_time),
                "cache_hit": self.tcp_cache.cache is not None
            }).encode("utf-8")
            self._send_response(response)
        except Exception as e:
            self._send_error_response(503, "Service unavailable", str(e))

    async def _handle_metrics(self):
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
        
        self._send_response("\n".join(metrics).encode("utf-8"), "text/plain")

    async def _handle_ws_info(self):
        ws_count = await self.connection_manager.get_count()
        response = json.dumps({
            "websocket_connections": ws_count,
            "max_connections": self.connection_manager.max_connections,
            "ws_endpoint": f"ws://{self.config.host}:{self.config.ws_port}/ws/tcpstates"
        }).encode("utf-8")
        self._send_response(response)

    def _handle_static(self):
        try:
            path = self.path.split('?', 1)[0].split('#', 1)[0]
            
            if path == '/':
                path = '/index.html'
            
            if not path.startswith('/'):
                path = '/' + path
            
            full_path = self.config.static_dir / path.lstrip('/')
            full_path = full_path.resolve()
            
            static_dir = self.config.static_dir.resolve()
            try:
                full_path.relative_to(static_dir)
            except ValueError:
                return self._send_error_response(403, "Access denied", "Path traversal attempt detected")
            
            if full_path.is_dir():
                full_path = full_path / "index.html"
                if not full_path.is_file():
                    return self._send_error_response(404, "File not found", "Directory index not available")
            
            if not full_path.is_file():
                return self._send_error_response(404, "File not found", f"Requested path: {self.path}")
            
            self.path = str(full_path.relative_to(static_dir))
            super().do_GET()
            
        except Exception as e:
            logging.error(f"Static file handling error for {self.client_address[0]}: {e}")
            self._send_error_response(500, "Internal server error", str(e))

    def log_message(self, format: str, *args: Any) -> None:
        logging.info(f"{self.client_address[0]} - {format % args}")

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
        self.shutdown_event = asyncio.Event()

    async def start_servers(self):
        def handler_factory(*args, **kwargs):
            return TCPMonitoringHandler(
                *args, 
                config=self.config, 
                security=self.security,
                rate_limiter=self.http_rate_limiter,
                server_start_time=self.server_start_time,
                tcp_cache=self.tcp_cache,
                connection_manager=self.connection_manager,
                **kwargs
            )
        
        self.http_server = ThreadingHTTPServer((self.config.host, self.config.port), handler_factory)
        
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
        
        logging.info(f"HTTP Server started on http://{self.config.host}:{self.config.port}")
        logging.info(f"WebSocket Server started on ws://{self.config.host}:{self.config.ws_port}")
        if ssl_context:
            logging.info(f"SSL/TLS enabled for WebSocket connections")

    async def shutdown(self):
        logging.info("Initiating server shutdown")
        
        if self.ws_server:
            self.ws_server.close()
            await self.ws_server.wait_closed()
        
        await self.connection_manager.close_all()
        
        if self.http_server:
            self.http_server.shutdown()
            self.http_server.server_close()
        
        logging.info("Server shutdown complete")

    async def run_forever(self):
        await self.start_servers()
        
        loop = asyncio.get_event_loop()
        http_task = loop.run_in_executor(None, self.http_server.serve_forever)
        
        try:
            await asyncio.gather(http_task, self._wait_for_shutdown())
        except KeyboardInterrupt:
            logging.info("Received shutdown signal")
        finally:
            await self.shutdown()

    async def _wait_for_shutdown(self):
        await self.shutdown_event.wait()

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
    
    def signal_handler(signum, frame):
        logging.info(f"Received signal {signum}, initiating shutdown")
        server_manager.shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await server_manager.run_forever()
    except Exception as e:
        logging.critical(f"Server failure: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))
