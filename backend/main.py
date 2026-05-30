import socketio
import asyncio
import time
from fastapi import FastAPI
from contextlib import asynccontextmanager
from backend.database.neo4j_client import neo4j_client
from backend.api.routes import router as api_router, set_sio
from backend.events import EVENTS
from backend.mitre.mapper import mitre_mapper
from backend.deception.container_manager import active_containers

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
        timestamp=time.time()
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
        timestamp=time.time()
    )
    await routes_module.attacker_action(action)

@sio.on(EVENTS['TRIGGER_MUTATE'])
async def handle_trigger_mutate(sid):
    import backend.api.routes as routes_module
    await routes_module.mutate_topology()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await neo4j_client.connect_with_retry()
    
    from backend.detection.scanner import ReconDetector, detect_network_interface
    import os
    from backend.models import ScanEvent
    from backend.api import routes
    from backend.ai import topology
    from backend.deception import container_manager
    
    async def on_recon_detected(scan_event: ScanEvent):
        # Emit to all connected frontend clients
        await sio.emit(EVENTS['RECON_DETECTED'], scan_event.model_dump())
        # Use the same _deception_activated flag as detect_scan to prevent race
        import backend.api.routes as routes_module
        async with routes_module.state_lock:
            already_active = routes_module._deception_activated
            if not already_active:
                routes_module._deception_activated = True

        if not already_active:
            try:
                new_topology = await topology.generate_topology(generation=0)
                await routes.set_topology(new_topology)
                await sio.emit(EVENTS['TOPOLOGY_UPDATE'], new_topology.model_dump())
                asyncio.create_task(container_manager.spawn_topology(new_topology, sio))
                await sio.emit(EVENTS['ALERT'], {
                    'message': f'Recon detected from {scan_event.source_ip} — deception fabric activated',
                    'severity': 'critical'
                })
            except Exception as e:
                async with routes_module.state_lock:
                    routes_module._deception_activated = False
                print(f"[ERROR] on_recon_detected: topology generation failed, flag reset: {e}")
        # Log to Neo4j
        await neo4j_client.create_attacker(scan_event.source_ip)

    interface = detect_network_interface()
    detector = ReconDetector(interface=interface, callback=on_recon_detected)
    loop = asyncio.get_running_loop()
    detector.start(loop)
    
    print("ShadowMesh backend online")
    yield
    # Shutdown
    detector.stop()
    from backend.deception import container_manager
    await container_manager.teardown_all()
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
        "mitre_loaded": mitre_mapper._is_initialized,
        "active_containers": len(active_containers)
    }

if __name__ == "__main__":
    import uvicorn
    # CRITICAL: serve socket_app (the ASGI wrapper), not app (FastAPI alone)
    uvicorn.run("backend.main:socket_app", host="0.0.0.0", port=8000, reload=False)
