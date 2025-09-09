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
from typing import Dict, Optional, Tuple, List
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
    static_dir: Path = Path(".")
    cors_origin: str = os.getenv("CORS_ALLOWED_ORIGIN", "*")
    max_request_size: int = 1024 * 1024
    allowed_extensions: Tuple[str, ...] = ('.html', '.js', '.css', '.png', '.ico', '.json')
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    server_version: str = os.getenv("SERVER_VERSION", "2.0.0")
    ws_rate_limit_requests: int = int(os.getenv("WS_RATE_LIMIT_REQUESTS", "10"))
    ws_rate_limit_window: int = int(os.getenv("WS_RATE_LIMIT_WINDOW", "60"))
    ws_auth_token: str = os.getenv("WS_AUTH_TOKEN", "secret-token")  # Added for WebSocket authentication

    def __post_init__(self):
        """Validate configuration parameters."""
        if not 0 < self.port <= 65535 or not 0 < self.ws_port <= 65535:
            raise ValueError(f"Invalid port number: {self.port} or {self.ws_port}")
        if not self.static_dir.exists() or not self.static_dir.is_dir():
            raise ValueError(f"Static directory {self.static_dir} does not exist or is not a directory")
        if self.cors_origin != "*" and not re.match(r'^https?://[\w\-\.]+(:\d+)?$', self.cors_origin):
            raise ValueError(f"Invalid CORS origin: {self.cors_origin}")

class RateLimiter:
    """Rate limiter for HTTP and WebSocket requests."""
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, List[datetime]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if a client is allowed to make a request."""
        now = datetime.now()
        self.clients[client_ip] = [
            t for t in self.clients[client_ip]
            if now - t < timedelta(seconds=self.window)
        ]
        if len(self.clients[client_ip]) >= self.requests:
            return False
        self.clients[client_ip].append(now)
        return True

class TCPStateCache:
    """Cache for TCP state parsing to reduce I/O."""
    def __init__(self, cache_duration: float = 0.5):
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
    files = ["/proc/net/tcp", "/proc/net/tcp6"]
    state_count = {name: 0 for name in TCP_STATES.values()}
    state_count["UNKNOWN"] = 0

    for file in files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) < 4 or not re.match(r'^[0-9A-F]{2}$', parts[3]):
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

class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for TCP monitoring and static file serving."""
    
    def __init__(self, *args, config: Config, rate_limiter: RateLimiter, server_start_time: float, tcp_cache: TCPStateCache, **kwargs):
        self.config = config
        self.rate_limiter = rate_limiter
        self.server_start_time = server_start_time
        self.tcp_cache = tcp_cache
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
        """Handle GET requests for TCP states, health checks, or static files."""
        try:
            if not self.rate_limiter.is_allowed(self.client_address[0]):
                return self._handle_error(429, "Too Many Requests", 
                    f"Rate limit exceeded: {self.config.rate_limit_requests} requests per {self.config.rate_limit_window} seconds")
            
            if len(self.path) > 256:
                return self._handle_error(414, "Request URI too long")
            
            if self.path == "/tcpstates":
                self._handle_tcp_states()
            elif self.path == "/health":
                self._handle_health_check()
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
                "uptime": int(time.time() - self.server_start_time)
            }).encode("utf-8")
            self._send_response(response)
        except Exception as e:
            self._handle_error(503, "Service unavailable", str(e))

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

async def websocket_handler(websocket, path, config: Config, ws_rate_limiter: RateLimiter, tcp_cache: TCPStateCache):
    """Handle WebSocket connections for real-time TCP state updates."""
    client_ip = websocket.remote_address[0]
    logging.info({"message": f"WebSocket client connected", "client_ip": client_ip})
    try:
        if path != "/ws/tcpstates":
            await websocket.send(json.dumps({"error": "Invalid WebSocket path"}))
            return
        
        auth_token = websocket.request_headers.get("Authorization")
        if auth_token != f"Bearer {config.ws_auth_token}":
            await websocket.send(json.dumps({"error": "Unauthorized", "details": "Invalid or missing auth token"}))
            return
        
        if not ws_rate_limiter.is_allowed(client_ip):
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
                "type": "tcp_state_update" 
            })
            await websocket.send(response)
            await asyncio.sleep(1)
    except websockets.exceptions.ConnectionClosed:
        logging.info({"message": f"WebSocket connection closed", "client_ip": client_ip})
    except Exception as e:
        logging.error({"message": f"WebSocket error for {client_ip}", "error": str(e)})

def configure_logging():
    """Configure logging with rotation and structured JSON output."""
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
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(JSONFormatter())
    
    file_handler = RotatingFileHandler(
        "server.log",
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setFormatter(JSONFormatter())
    
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)

async def shutdown(http_server, ws_server, timeout=5):
    """Gracefully shut down servers with a timeout."""
    logger = logging.getLogger(__name__)
    logger.info({"message": "Initiating server shutdown"})
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
    tcp_cache = TCPStateCache()
    
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
                **kwargs
            )
        
        http_server = ThreadingHTTPServer((config.host, config.port), handler_factory)
        logger.info({"message": f"HTTP Server started", "address": f"http://{config.host}:{config.port}"})
        logger.info({"message": f"Serving static files", "directory": str(config.static_dir)})
        
        ws_server = await websockets.serve(
            lambda ws, path: websocket_handler(ws, path, config, ws_rate_limiter, tcp_cache),
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
            await shutdown(http_server, ws_server)
    except Exception as e:
        logger.critical({"message": "Server failure", "error": str(e)})
        return 1
    return 0

if __name__ == "__main__":
    exit(asyncio.run(run_server()))
