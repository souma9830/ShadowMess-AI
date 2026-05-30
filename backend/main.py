import socketio
import asyncio
from fastapi import FastAPI
from contextlib import asynccontextmanager
from backend.database.neo4j_client import neo4j_client
from backend.api.routes import router as api_router, set_sio
from backend.events import EVENTS

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
set_sio(sio)

@sio.event
async def connect(sid, environ):
    print(f'Client connected: {sid}')
    await sio.emit(EVENTS['STATUS'], {'message': 'ShadowMesh active', 'deception': False}, to=sid)

@sio.event
async def disconnect(sid):
    print(f'Client disconnected: {sid}')

@sio.event
async def ping(sid, data):
    await sio.emit('pong', data, to=sid)

@sio.on(EVENTS['TRIGGER_SCAN'])
async def handle_trigger_scan(sid):
    from backend.models import ScanEvent
    from backend.api.routes import detect_scan
    scan = ScanEvent(
        source_ip='192.168.1.100', 
        scan_type='port_scan', 
        ports_hit=[22,80,443], 
        timestamp=0.0
    )
    await detect_scan(scan)

@sio.on(EVENTS['TRIGGER_LOGIN'])
async def handle_trigger_login(sid):
    from backend.models import AttackerAction
    from backend.api.routes import attacker_action, current_topology
    node_id = current_topology.nodes[0].node_id if current_topology.nodes else 'node_demo'
    action = AttackerAction(
        attacker_ip='192.168.1.100',
        action_type='login_attempt',
        detail='SSH brute force: root/admin123',
        target_node_id=node_id,
        timestamp=0.0
    )
    await attacker_action(action)

@sio.on(EVENTS['TRIGGER_MUTATE'])
async def handle_trigger_mutate(sid):
    from backend.api.routes import mutate_topology
    await mutate_topology()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await neo4j_client.connect_with_retry()
    
    print("ShadowMesh backend online")
    yield
    # Shutdown
    await neo4j_client.close()

app = FastAPI(title='ShadowMesh API', lifespan=lifespan)

# Global Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    print(f"Global exception caught: {exc}")
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"error": str(exc)})

app.include_router(api_router, prefix="/api")

socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

@app.get("/health")
async def health():
    healthy = await neo4j_client.health_check()
    return {
        "status": "ok",
        "neo4j": healthy,
        "mitre_loaded": False,
        "active_containers": 0
    }

if __name__ == "__main__":
    import uvicorn
    # CRITICAL: serve socket_app (the ASGI wrapper), not app (FastAPI alone)
    uvicorn.run("backend.main:socket_app", host="0.0.0.0", port=8000, reload=False)
