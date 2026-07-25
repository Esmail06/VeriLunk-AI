"""Safe URL reachability checks for VeriLunk AI."""

import asyncio
import ipaddress
import os
import socket
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

REQUEST_TIMEOUT_SECONDS = 8
MAX_URL_LENGTH = 2048
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 20
request_log: dict[str, deque[float]] = defaultdict(deque)

app = FastAPI(title="VeriLunk AI API", version="1.0.0")
allowed_origins = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=False, allow_methods=["POST", "GET"], allow_headers=["Content-Type"])


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)


class ReachabilityResult(BaseModel):
    reachable: bool
    status_code: int | None = None
    checked_url: str
    message: str


def ensure_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    entries = request_log[client_ip]
    while entries and now - entries[0] >= RATE_LIMIT_WINDOW_SECONDS:
        entries.popleft()
    if len(entries) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many scan requests. Please try again shortly.")
    entries.append(now)


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URLs containing credentials cannot be scanned.")
    return value


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


async def validate_public_host(hostname: str) -> None:
    if hostname.lower() in {"localhost", "localhost.localdomain"} or hostname.lower().endswith(".local"):
        raise HTTPException(status_code=400, detail="Local network addresses cannot be scanned.")
    try:
        addresses = await asyncio.get_running_loop().run_in_executor(None, lambda: socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM))
        resolved_ips = {entry[4][0] for entry in addresses}
    except socket.gaierror as error:
        raise HTTPException(status_code=422, detail="The domain could not be resolved.") from error
    if not resolved_ips or any(not is_public_address(address) for address in resolved_ips):
        raise HTTPException(status_code=400, detail="Private or non-public network addresses cannot be scanned.")


async def check_reachability(url: str) -> ReachabilityResult:
    parsed = urlparse(url)
    await validate_public_host(parsed.hostname or "")
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=4.0)
    headers = {"User-Agent": "VeriLunk-AI-URL-Scanner/1.0", "Accept": "text/html,application/xhtml+xml"}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers) as client:
            async with client.stream("GET", url) as response:
                status_code = response.status_code
                if 300 <= status_code < 400:
                    return ReachabilityResult(reachable=True, status_code=status_code, checked_url=url, message="The server responded with a redirect. Redirect destinations are not followed automatically.")
                return ReachabilityResult(reachable=True, status_code=status_code, checked_url=url, message=f"The server responded with HTTP {status_code}.")
    except httpx.TimeoutException:
        return ReachabilityResult(reachable=False, checked_url=url, message="The server did not respond before the timeout.")
    except httpx.HTTPError:
        return ReachabilityResult(reachable=False, checked_url=url, message="The server could not be reached from the scanner.")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ReachabilityResult)
async def scan(payload: ScanRequest, request: Request) -> ReachabilityResult:
    ensure_rate_limit(request.client.host if request.client else "unknown")
    return await check_reachability(normalize_url(payload.url))


frontend_directory = Path(__file__).resolve().parent.parent
app.mount("/", StaticFiles(directory=frontend_directory, html=True), name="frontend")
