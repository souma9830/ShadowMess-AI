import socketio
import asyncio
import logging
from fastapi import FastAPI
from contextlib import asynccontextmanager
from backend.database.neo4j_client import neo4j_client
from backend.api.routes import router as api_router, set_sio
from backend.events import EVENTS
from backend.mitre.mapper import mitre_mapper
from backend.deception.container_manager import active_containers

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend")

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
    import backend.api.routes as routes_module
    # Read current_topology from the module at call time (not import time)
    # so we always get the live topology, not the initial empty snapshot
    topo = routes_module.current_topology
    node_id = topo.nodes[0].node_id if topo.nodes else 'node_demo'
    action = AttackerAction(
        attacker_ip='192.168.1.100',
        action_type='login_attempt',
        detail='SSH brute force: root/admin123',
        target_node_id=node_id,
        timestamp=0.0
    )
    await routes_module.attacker_action(action)

@sio.on(EVENTS['TRIGGER_MUTATE'])
async def handle_trigger_mutate(sid):
    import backend.api.routes as routes_module
    await routes_module.mutate_topology()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        await neo4j_client.init_schema()
    except Exception as e:
        logger.warning(f"Neo4j init_schema failed: {e}")

    try:
        healthy = await neo4j_client.health_check()
    except Exception as e:
        logger.warning(f"Neo4j health check failed: {e}")
        healthy = False

    if healthy:
        try:
            await neo4j_client.seed_demo_data()
        except Exception as e:
            logger.warning(f"Neo4j seed_demo_data failed: {e}")
        logger.info("Neo4j connected")
    else:
        logger.error("Neo4j connection failed")
    
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
    try:
        healthy = await neo4j_client.health_check()
    except Exception:
        healthy = False

    try:
        mitre_loaded = bool(mitre_mapper._is_initialized)
    except Exception:
        mitre_loaded = False

    try:
        container_count = len(active_containers)
    except Exception:
        container_count = 0

    return {
        "status": "ok",
        "neo4j": healthy,
        "mitre_loaded": mitre_loaded,
        "active_containers": container_count
    }

if __name__ == "__main__":
    import uvicorn
    # CRITICAL: serve socket_app (the ASGI wrapper), not app (FastAPI alone)
    uvicorn.run("backend.main:socket_app", host="0.0.0.0", port=8000, reload=False)
