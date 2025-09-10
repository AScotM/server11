#!/usr/bin/env python3
import json
import logging
import os
import time
import asyncio
import websockets
import psutil
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Set
from collections import defaultdict
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import re

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
class Config:
    """Configuration for the TCP monitoring server."""
    host: str = os.getenv("TCP_SERVER_HOST", "0.0.0.0")
    port: int = int(os.getenv("TCP_SERVER_PORT", "3333"))
    ws_port: int = int(os.getenv("WS_PORT", "3334"))
    static_dir: Path = Path(os.getenv("STATIC_DIR", "."))
    cors_origin: str = os.getenv("CORS_ALLOWED_ORIGIN", "*")
    max_request_size: int = 1024 * 1024
    allowed_extensions: Tuple[str, ...] = ('.html', '.js', '.css', '.png', '.ico', '.json')
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    server_version: str = os.getenv("SERVER_VERSION", "2.0.0")
    ws_rate_limit_requests: int = int(os.getenv("WS_RATE_LIMIT_REQUESTS", "10"))
    ws_rate_limit_window: int = int(os.getenv("WS_RATE_LIMIT_WINDOW", "60"))
    ws_auth_token: str = os.getenv("WS_AUTH_TOKEN", "secret-token")
    cache_duration: float = float(os.getenv("CACHE_DURATION", "0.5"))
    config_file: Optional[str] = os.getenv("CONFIG_FILE")

    def __post_init__(self):
        """Validate configuration parameters."""
        if not 0 < self.port <= 65535 or not 0 < self.ws_port <= 65535:
            raise ValueError(f"Invalid port number: {self.port} or {self.ws_port}")
        if not self.static_dir.exists() or not self.static_dir.is_dir():
            raise ValueError(f"Static directory {self.static_dir} does not exist or is not a directory")
        if self.cors_origin != "*" and not re.match(r'^https?://[\w\-\.]+(:\d+)?$', self.cors_origin):
            raise ValueError(f"Invalid CORS origin: {self.cors_origin}")
        if self.cache_duration <= 0:
            raise ValueError(f"Invalid cache duration: {self.cache_duration}")
        if self.rate_limit_requests <= 0 or self.ws_rate_limit_requests <= 0:
            raise ValueError("Rate limit requests must be positive")
        if self.rate_limit_window <= 0 or self.ws_rate_limit_window <= 0:
            raise ValueError("Rate limit window must be positive")
        if self.config_file:
            self._load_config_file()

    def _load_config_file(self):
        """Load configuration from a JSON file, if specified."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
                for key, value in config_data.items():
                    if hasattr(self, key):
                        object.__setattr__(self, key, value)
        except Exception as e:
            raise ValueError(f"Failed to load config file {self.config_file}: {str(e)}")

class RateLimiter:
    """Rate limiter for HTTP and WebSocket requests with endpoint-specific tracking."""
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)

    def is_allowed(self, client_ip: str, endpoint: str) -> bool:
        """Check if a client is allowed to make a request for a specific endpoint."""
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
    """Cache for TCP state parsing to reduce I/O."""
    def __init__(self, cache_duration: float):
        self.cache_duration = cache_duration
        self.last_update = 0.0
        self.cache = None

    def get_states(self) -> Dict[str, int]:
        """Get cached TCP states or refresh if stale."""
        now = time.time()
        if self.cache is None or now - self.last_update >= self.cache_duration:
            self.cache = parse_tcp_states()
            self.last_update = now
        return self.cache

def parse_tcp_states() -> Dict[str, int]:
    """Parse TCP states from /proc/net/tcp and /proc/net/tcp6."""
    files = []
    if Path("/proc/net/tcp").exists():
        files.append("/proc/net/tcp")
    if Path("/proc/net/tcp6").exists():
        files.append("/proc/net/tcp6")
    
    if not files:
        logging.error({"message": "No TCP proc files found"})
        return {name: 0 for name in TCP_STATES.values()}
    
    state_count = {name: 0 for name in TCP_STATES.values()}
    state_count["UNKNOWN"] = 0

    for file in files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) < 12 or not re.match(r'^[0-9A-F]{2}$', parts[3]):
                        logging.warning({"message": f"Invalid line format in {file}", "line": line.strip()})
                        continue
                    state_code = parts[3]
                    state_name = TCP_STATES.get(state_code, "UNKNOWN")
                    state_count[state_name] += 1
        except FileNotFoundError:
            logging.warning({"message": f"{file} not found"})
        except Exception as e:
            logging.error({"message": f"Error parsing {file}", "error": str(e)})
    return state_count

class ConnectionCounter:
    """Track active WebSocket connections with proper management."""
    def __init__(self):
        self.count = 0
        self.connections: Set[websockets.WebSocketServerProtocol] = set()

    def add_connection(self, websocket: websockets.WebSocketServerProtocol):
        """Add a WebSocket connection to tracking."""
        self.connections.add(websocket)
        self.count += 1

    def remove_connection(self, websocket: websockets.WebSocketServerProtocol):
        """Remove a WebSocket connection from tracking."""
        if websocket in self.connections:
            self.connections.remove(websocket)
            self.count = max(0, self.count - 1)

    def get_count(self) -> int:
        """Get current connection count."""
        return self.count

    def close_all(self):
        """Close all active WebSocket connections."""
        for ws in self.connections:
            asyncio.create_task(ws.close())
        self.connections.clear()
        self.count = 0

class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for TCP monitoring and static file serving."""
    
    def __init__(self, *args, config: Config, rate_limiter: RateLimiter, server_start_time: float, tcp_cache: TCPStateCache, connection_counter: ConnectionCounter, **kwargs):
        self.config = config
        self.rate_limiter = rate_limiter
        self.server_start_time = server_start_time
        self.tcp_cache = tcp_cache
        self.connection_counter = connection_counter
        super().__init__(*args, directory=str(self.config.static_dir), **kwargs)

    def _send_response(self, content: bytes, content_type: str = "application/json", status: int = 200):
        """Send HTTP response with security headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", self.config.cors_origin)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Cache-Control", "no-store, no-cache")
        self.end_headers()
        self.wfile.write(content)
        logging.info({
            "client_ip": self.client_address[0],
            "path": self.path,
            "status": status,
            "method": "GET"
        })

    def _handle_error(self, status: int, message: str, details: Optional[str] = None):
        """Send error response with details."""
        error_data = {
            "error": message,
            "status": status,
            "timestamp": int(time.time()),
            "details": details or "No additional details available"
        }
        self._send_response(json.dumps(error_data).encode("utf-8"), status=status)

    def do_GET(self):
        """Handle GET requests for TCP states, health checks, metrics, or static files."""
        try:
            endpoint = self.path.split('?', 1)[0] or "/"
            if not self.rate_limiter.is_allowed(self.client_address[0], endpoint):
                return self._handle_error(429, "Too Many Requests", 
                    f"Rate limit exceeded: {self.config.rate_limit_requests} requests per {self.config.rate_limit_window} seconds for {endpoint}")
            
            if len(self.path) > 256:
                return self._handle_error(414, "Request URI too long")
            
            if self.path == "/tcpstates":
                self._handle_tcp_states()
            elif self.path == "/health":
                self._handle_health_check()
            elif self.path == "/metrics":
                self._handle_metrics()
            else:
                self._handle_static()
        except Exception as e:
            logging.exception({"message": f"Request processing failed for {self.client_address[0]}", "error": str(e)})
            self._handle_error(500, "Internal server error", str(e))

    def _handle_tcp_states(self):
        """Handle TCP states request."""
        stats = self.tcp_cache.get_states()
        response = json.dumps({
            "timestamp": int(time.time()),
            "tcp_states": stats,
            "server": "TCP Monitoring Service",
            "version": self.config.server_version
        }).encode("utf-8")
        self._send_response(response)

    def _handle_health_check(self):
        """Handle health check request."""
        try:
            stats = self.tcp_cache.get_states()
            response = json.dumps({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(stats.values()),
                "memory_usage": f"{psutil.virtual_memory().percent}%",
                "cpu_usage": f"{psutil.cpu_percent(interval=None)}%",
                "websocket_connections": self.connection_counter.get_count(),
                "uptime": int(time.time() - self.server_start_time),
                "cache_hit": self.tcp_cache.cache is not None
            }).encode("utf-8")
            self._send_response(response)
        except Exception as e:
            self._handle_error(503, "Service unavailable", str(e))

    def _handle_metrics(self):
        """Handle metrics endpoint for monitoring."""
        stats = self.tcp_cache.get_states()
        metrics = [
            f"# HELP tcp_connections_total Total TCP connections by state",
            f"# TYPE tcp_connections_total gauge"
        ]
        
        for state, count in stats.items():
            metrics.append(f'tcp_connections_total{{state="{state}"}} {count}')
        
        metrics.extend([
            f"# HELP websocket_connections_active Active WebSocket connections",
            f"# TYPE websocket_connections_active gauge",
            f'websocket_connections_active {self.connection_counter.get_count()}',
            f"# HELP server_uptime_seconds Server uptime in seconds",
            f"# TYPE server_uptime_seconds gauge",
            f'server_uptime_seconds {int(time.time() - self.server_start_time)}'
        ])
        
        self._send_response("\n".join(metrics).encode("utf-8"), "text/plain")

    def _handle_static(self):
        """Handle static file requests."""
        try:
            path = self.path.split('?', 1)[0]
            path = path.split('#', 1)[0]
            
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
                return self._handle_error(403, "Access denied", "Path traversal attempt detected")
            
            if full_path.is_dir():
                full_path = full_path / "index.html"
                if not full_path.is_file():
                    return self._handle_error(404, "File not found", "Directory index not available")
            
            if not full_path.suffix or full_path.suffix not in self.config.allowed_extensions:
                return self._handle_error(403, "File type not allowed", f"Invalid or missing extension for {full_path}")
            
            if not full_path.is_file():
                return self._handle_error(404, "File not found", f"Requested path: {self.path}")
            
            self.path = str(full_path.relative_to(static_dir))
            super().do_GET()
            
        except Exception as e:
            logging.error({"message": f"Static file handling error for {self.client_address[0]}", "error": str(e)})
            self._handle_error(500, "Internal server error", str(e))

async def websocket_handler(websocket, path, config: Config, ws_rate_limiter: RateLimiter, tcp_cache: TCPStateCache, connection_counter: ConnectionCounter):
    """Handle WebSocket connections for real-time TCP state updates."""
    client_ip = websocket.remote_address[0]
    logging.info({"message": f"WebSocket client connected", "client_ip": client_ip})
    connection_counter.add_connection(websocket)
    
    try:
        if path != "/ws/tcpstates":
            await websocket.send(json.dumps({"error": "Invalid WebSocket path"}))
            return
        
        auth_token = websocket.request_headers.get("Authorization")
        if auth_token != f"Bearer {config.ws_auth_token}":
            await websocket.send(json.dumps({"error": "Unauthorized", "details": "Invalid or missing auth token"}))
            return
        
        if not ws_rate_limiter.is_allowed(client_ip, path):
            await websocket.send(json.dumps({
                "error": "Too Many Requests",
                "details": f"WebSocket rate limit exceeded: {config.ws_rate_limit_requests} connections per {config.ws_rate_limit_window} seconds"
            }))
            return
        
        while True:
            stats = tcp_cache.get_states()
            response = json.dumps({ 
                "timestamp": int(time.time()), 
                "tcp_states": stats, 
                "type": "tcp_state_update",
                "server_version": config.server_version
            })
            await websocket.send(response)
            await asyncio.sleep(1)
    except websockets.exceptions.ConnectionClosed:
        logging.info({"message": f"WebSocket connection closed", "client_ip": client_ip})
    except Exception as e:
        logging.error({"message": f"WebSocket error for {client_ip}", "error": str(e)})
        await websocket.send(json.dumps({"error": "Internal server error"}))
    finally:
        connection_counter.remove_connection(websocket)

def configure_logging():
    """Configure logging with rotation and dual JSON/human-readable output."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    class JSONFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
                "name": record.name,
                "level": record.levelname,
                "message": record.getMessage()
            }
            if record.exc_info:
                log_data["exception"] = self.formatException(record.exc_info)
            return json.dumps(log_data)
    
    class HumanReadableFormatter(logging.Formatter):
        def format(self, record):
            return f"{self.formatTime(record, '%Y-%m-%d %H:%M:%S')} [{record.levelname}] {record.getMessage()}"

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(HumanReadableFormatter())
    
    file_handler = RotatingFileHandler(
        "server.log",
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setFormatter(JSONFormatter())
    
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)

async def shutdown(http_server, ws_server, connection_counter, timeout=5):
    """Gracefully shut down servers with a timeout."""
    logger = logging.getLogger(__name__)
    logger.info({"message": "Initiating server shutdown"})
    
    # Close all WebSocket connections
    connection_counter.close_all()
    
    ws_server.close()
    try:
        await asyncio.wait_for(ws_server.wait_closed(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning({"message": f"WebSocket server shutdown timed out after {timeout} seconds"})
    
    http_server.shutdown()
    http_server.server_close()
    logger.info({"message": "Server shutdown complete"})

async def run_server():
    """Run the HTTP and WebSocket servers."""
    configure_logging()
    logger = logging.getLogger(__name__)
    
    server_start_time = time.time()
    config = Config()
    tcp_cache = TCPStateCache(config.cache_duration)
    connection_counter = ConnectionCounter()
    
    http_rate_limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window)
    ws_rate_limiter = RateLimiter(config.ws_rate_limit_requests, config.ws_rate_limit_window)
    
    try:
        def handler_factory(*args, **kwargs):
            return TCPMonitoringHandler(
                *args, 
                config=config, 
                rate_limiter=http_rate_limiter,
                server_start_time=server_start_time,
                tcp_cache=tcp_cache,
                connection_counter=connection_counter,
                **kwargs
            )
        
        http_server = ThreadingHTTPServer((config.host, config.port), handler_factory)
        logger.info({"message": f"HTTP Server started", "address": f"http://{config.host}:{config.port}"})
        logger.info({"message": f"Serving static files", "directory": str(config.static_dir)})
        
        ws_server = await websockets.serve(
            lambda ws, path: websocket_handler(ws, path, config, ws_rate_limiter, tcp_cache, connection_counter),
            config.host, 
            config.ws_port, 
            ping_interval=20, 
            ping_timeout=60 
        )
        logger.info({"message": f"WebSocket Server started", "address": f"ws://{config.host}:{config.ws_port}"})
        
        loop = asyncio.get_event_loop()
        http_task = loop.run_in_executor(None, http_server.serve_forever)
        
        try:
            await asyncio.gather(http_task)
        except KeyboardInterrupt:
            logger.info({"message": "Server received shutdown signal"})
            await shutdown(http_server, ws_server, connection_counter)
    except Exception as e:
        logger.critical({"message": "Server failure", "error": str(e)})
        return 1
    return 0

if __name__ == "__main__":
    exit(asyncio.run(run_server()))
