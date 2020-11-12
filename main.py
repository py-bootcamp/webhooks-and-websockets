import hashlib
import hmac
import json
import logging
from asyncio import sleep
from datetime import datetime, timezone
from http.client import HTTPException
from typing import Dict
from uuid import uuid4

import httpx
import websockets
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute

log = logging.getLogger("uvicorn")


IPs = ("localhost", "127.0.0.1")
SECRET = "SUPER-SECRET"


def process_data(body: bytes) -> None:
    try:
        payload = json.loads(body)
    except ValueError:
        log.warning("Invalid json!")
    else:
        log.info(payload)


async def health(request):
    return JSONResponse({"status": "OK"})


async def trigger(request):
    task = BackgroundTask(
        call_webhook,
        body={"data": "Some data"},
        url="http://localhost:8000/webhook",
        id=uuid4().hex,
    )
    return JSONResponse({"message": "triggering webhook"}, background=task)


def verify_ip(ip: str) -> bool:
    return ip in IPs


def make_signature(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify_signature(header: str, body: bytes, secret: str) -> bool:
    return hmac.compare_digest(make_signature(secret, body), header)


async def incoming_webhook(request):
    body = await request.body()
    try:
        if not verify_ip(request.client.host):
            log.warning("Webhook coming from invalid IP")
            raise ValueError("Invalid IP")

        if not verify_signature(
            request.headers.get("WebHook-Signature", ""), body, SECRET
        ):
            log.warning("Webhook with invalid signature")
            raise ValueError("Invalid payload signature")
    except ValueError:
        return JSONResponse({"message": "ko"}, status_code=403)

    try:
        process_data(body)
    except ValueError:
        return JSONResponse({"message": "ko"}, status_code=400)

    return JSONResponse({"message": "ok"})


async def websocket_endpoint(websocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_text("ping")
            message = await websocket.receive_text()
            log.info(message)
            await sleep(1)
    except (websockets.exceptions.WebSocketException):
        pass
    finally:
        log.info("ws closed")
        await websocket.close()


async def call_webhook(body: Dict, id: str, url: str):
    # background job to execute a webhook
    signature = make_signature(SECRET, json.dumps(body).encode())
    headers = {
        "WebHook-ID": id,
        "WebHook-Signature": signature,
        "WebHook-Timestamp": f"{datetime.now(tz=timezone.utc).timestamp()}",
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(url, json=body, headers=headers)
        try:
            body = r.json()
        except ValueError:
            body = r.text
        log.info(body)
        if (r.status_code // 100) > 3:
            raise HTTPException("Error, request failed")


routes = [
    Route("/healthz", health, methods=["GET"]),
    Route("/trigger", trigger, methods=["GET"]),
    Route("/webhook", incoming_webhook, methods=["GET", "POST"]),
    WebSocketRoute("/ws", websocket_endpoint),
]

app = Starlette(debug=True, routes=routes)
