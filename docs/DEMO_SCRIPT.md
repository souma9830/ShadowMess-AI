## ShadowMesh — 5 Minute Demo Script

### Setup (before judges arrive)
- [ ] docker-compose up -d (all services healthy)
- [ ] Frontend open at localhost:5173 on the presentation screen
- [ ] scripts/simulate_attacker.py ready in a terminal (not yet run)
- [ ] Neo4j Browser open at localhost:7474 (optional — shows graph DB if asked)
- [ ] .env has valid GROQ_API_KEY

### Minute 1 — The Problem (talking points, no typing)
Explain: "Sophisticated attackers don't immediately steal data. They spend weeks mapping a network — and current defenses are blind to this phase."
Show: dashboard idle, "Monitoring" status. "This is ShadowMesh — watching silently."

### Minute 2 — The Attack Begins
Action: Click "⚡ Trigger Scan" from the Demo Control Bar (or run `python scripts/simulate_attacker.py`).
Narrate: "An attacker just got inside our network and started a port scan."
Show: Dashboard status flips to THREAT ACTIVE. Network graph animates — nodes appear.
Say: "ShadowMesh just generated a completely fake enterprise network — in real time. Everything the attacker sees is a trap."

### Minute 3 — Attacker Engages Fake Assets
Action: Click "🔑 Simulate Login" from the Demo Control Bar.
Narrate: "The attacker found what looks like an SSH server and a database. They're logging in."
Show: AlertFeed filling with events. Nodes glowing. 
Say: "Every keystroke is logged. Every command captured. They have no idea they're in our fabric."

### Minute 4 — The Mutation (money shot)
Action: Click "🌫 Trigger Mutation" from the Demo Control Bar.
Narrate: "Now the attacker gets suspicious. They run an OS fingerprinting probe."
Watch: Topology fog animation. Scanline sweeps. Graph reshuffles with completely new architecture.
Say: "The moment ShadowMesh detected fingerprinting — it regenerated the entire topology. The attacker's map is now useless. They're starting from zero."

### Minute 5 — The Intelligence
Show: "We've been watching for 3 minutes. Here is what we know about this attacker."
Point to: Live alerts, nodes explored, dwell time on the Stats bar.
Closing: "ShadowMesh doesn't just block attacks. It turns every attacker into an intelligence source."
