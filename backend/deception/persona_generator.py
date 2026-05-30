"""
ShadowMesh - Task 11.1: Persona Generator
==========================================
Generates fake human identities injected into honeypot containers at spawn
time, making each container appear to have been used by a real employee for
years.

Architecture:
  PersonaManager.generate_for_node(node_id, node_type)
      -> Persona (dataclass)
      -> stored in _personas[node_id]

  container_manager calls generate_for_node() before spawn,
  clear_for_node() on teardown -- same lifecycle as cred_manager / canary_manager.

Security invariants:
  - Credential-adjacent values use secrets module (cryptographically secure).
  - AWS key IDs are prefixed FAKEAKIA (not AKIA) -- structurally plausible but
    provably non-real; prevents accidental AWS API calls if exfiltrated.
  - SSH key bodies contain a SHADOWMESH-FAKE marker -- invalid PEM, passes
    visual inspection.
  - All hostnames use .shadowmesh.internal / .fake.local -- unresolvable
    outside the deception network.
  - Usernames are derived deterministically from node_id hash for
    cross-artifact consistency (same persona across bash_history, .env, etc.).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

log = logging.getLogger("persona_generator")

# ---------------------------------------------------------------------------
# Corpus data
# ---------------------------------------------------------------------------

_FIRST_NAMES: List[str] = [
    "alex", "blake", "casey", "dana", "drew", "elliot", "finley", "gray",
    "harper", "indira", "jordan", "kendall", "lane", "morgan", "noel",
    "oakley", "parker", "quinn", "reese", "sage", "taylor", "uri",
    "val", "wren", "xen", "yael", "zuri",
]

_LAST_NAMES: List[str] = [
    "abrams", "chen", "delacroix", "erikson", "foster", "garcia", "huang",
    "ibrahim", "jensen", "kowalski", "larsson", "mehta", "nakamura",
    "okonkwo", "patel", "qureshi", "reyes", "svensson", "tanaka",
    "ueda", "vasquez", "walsh", "xu", "yamamoto", "ziegler",
]

_DEPARTMENTS: Dict[str, str] = {
    "linux_admin":      "infrastructure",
    "developer":        "engineering",
    "finance_analyst":  "finance",
}

_COMPANY_DOMAINS: List[str] = [
    "corp.shadowmesh.internal",
    "internal.shadowmesh.fake.local",
    "employees.shadowmesh.internal",
]

_INTERNAL_HOSTS: List[str] = [
    "gitlab.shadowmesh.internal",
    "jira.shadowmesh.internal",
    "confluence.shadowmesh.internal",
    "jenkins.shadowmesh.internal",
    "nexus.shadowmesh.internal",
    "vault.shadowmesh.internal",
    "ldap.shadowmesh.internal",
    "monitoring.shadowmesh.internal",
]

# node_type -> persona role mapping
_NODE_TYPE_ROLE: Dict[str, str] = {
    "web_server":    "developer",
    "api_gateway":   "developer",
    "db_server":     "linux_admin",
    "auth_service":  "linux_admin",
    "file_server":   "linux_admin",
    "mail_server":   "linux_admin",
    "workstation":   "finance_analyst",
}

_SRNG = secrets.SystemRandom()


# ---------------------------------------------------------------------------
# Persona dataclass
# ---------------------------------------------------------------------------

@dataclass
class Persona:
    """Complete fake human identity for a single honeypot container."""

    node_id:        str
    role:           str          # linux_admin | developer | finance_analyst
    username:       str
    full_name:      str
    email:          str
    hostname:       str
    department:     str
    employee_id:    str          # e.g. EMP-00472
    years_tenure:   int
    ssh_pubkey:     str          # fake but structurally valid-looking
    gpg_key_id:     str          # 16-char hex
    git_config:     str          # contents of ~/.gitconfig
    bash_history:   str          # contents of ~/.bash_history
    aws_config:     str          # contents of ~/.aws/credentials
    ssh_config:     str          # contents of ~/.ssh/config
    vimrc:          str          # contents of ~/.vimrc
    cron_jobs:      str          # contents of crontab -l
    last_login:     str          # last login line shown at SSH banner
    home_dir_files: List[str]    # list of filenames to plant in $HOME
    extra: Dict[str, str]        = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal generators
# ---------------------------------------------------------------------------

def _deterministic_pick(corpus: List[str], seed_bytes: bytes, salt: str) -> str:
    """Pick one item from corpus deterministically from node_id-derived seed."""
    digest = hashlib.sha256(seed_bytes + salt.encode()).digest()
    return corpus[int.from_bytes(digest[:4], "big") % len(corpus)]


def _build_identity(node_id: str) -> tuple[str, str, str, str, str]:
    """Return (username, full_name, email, hostname, employee_id)."""
    seed = node_id.encode()
    first = _deterministic_pick(_FIRST_NAMES, seed, "first")
    last  = _deterministic_pick(_LAST_NAMES,  seed, "last")
    domain = _deterministic_pick(_COMPANY_DOMAINS, seed, "domain")

    # username: first initial + last name + 2-digit numeric suffix from hash
    suffix_bytes = hashlib.sha256(seed + b"suffix").digest()
    suffix = str(int.from_bytes(suffix_bytes[:2], "big") % 100).zfill(2)
    username = f"{first[0]}{last}{suffix}"

    full_name = f"{first.capitalize()} {last.capitalize()}"
    email     = f"{username}@{domain}"
    hostname  = f"{last}-ws-{suffix}.shadowmesh.internal"

    emp_num = int.from_bytes(hashlib.sha256(seed + b"empid").digest()[:3], "big") % 90000 + 10000
    employee_id = f"EMP-{emp_num}"

    return username, full_name, email, hostname, employee_id


def _fake_ssh_pubkey(username: str) -> str:
    token = secrets.token_hex(32)
    return f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{token}SHADOWMESH-FAKE {username}@shadowmesh.internal"


def _fake_gpg_key_id() -> str:
    return secrets.token_hex(8).upper()


def _fake_aws_key() -> tuple[str, str]:
    """Return (access_key_id, secret_access_key). FAKEAKIA prefix prevents real AWS calls."""
    key_id  = "FAKEAKIA" + secrets.token_hex(6).upper()
    secret  = secrets.token_urlsafe(30)
    return key_id, secret


def _years_tenure(node_id: str) -> int:
    seed = hashlib.sha256(node_id.encode() + b"tenure").digest()
    return 1 + int.from_bytes(seed[:1], "big") % 8  # 1–8 years


def _last_login_line(username: str, node_id: str) -> str:
    seed = hashlib.sha256(node_id.encode() + b"login").digest()
    days_ago = int.from_bytes(seed[:2], "big") % 14
    hour     = int.from_bytes(seed[2:3], "big") % 24
    minute   = int.from_bytes(seed[3:4], "big") % 60
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hour, minutes=minute)
    src_ip = f"10.{seed[4]}.{seed[5]}.{seed[6]}"
    return f"Last login: {dt.strftime('%a %b %d %H:%M:%S %Y')} from {src_ip}"


# ---------------------------------------------------------------------------
# Role-specific generators
# ---------------------------------------------------------------------------

def _git_config(full_name: str, email: str) -> str:
    return textwrap.dedent(f"""\
        [user]
            name = {full_name}
            email = {email}
        [core]
            editor = vim
            autocrlf = input
            pager = less -FRX
        [push]
            default = simple
        [pull]
            rebase = true
        [alias]
            st = status
            co = checkout
            br = branch
            lg = log --oneline --graph --decorate --all
        [color]
            ui = auto
    """)


def _aws_config(username: str, node_id: str) -> str:
    key_id, secret = _fake_aws_key()
    region_seed = hashlib.sha256(node_id.encode() + b"region").digest()
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
    region = regions[region_seed[0] % len(regions)]
    return textwrap.dedent(f"""\
        [default]
        aws_access_key_id = {key_id}
        aws_secret_access_key = {secret}
        region = {region}
        output = json

        [profile {username}-deploy]
        aws_access_key_id = FAKEAKIA{secrets.token_hex(6).upper()}
        aws_secret_access_key = {secrets.token_urlsafe(30)}
        region = {region}
        role_arn = arn:aws:iam::123456789012:role/deploy-role-shadowmesh-fake
    """)


def _ssh_config(username: str) -> str:
    host_lines = "\n".join(
        f"Host {h.split('.')[0]}\n    HostName {h}\n    User {username}\n    IdentityFile ~/.ssh/id_rsa\n"
        for h in _SRNG.sample(_INTERNAL_HOSTS, k=4)
    )
    return f"# SSH client config -- managed by Ansible\n\n{host_lines}"


def _vimrc() -> str:
    return textwrap.dedent("""\
        set nocompatible
        set number
        set relativenumber
        set tabstop=4
        set shiftwidth=4
        set expandtab
        set autoindent
        set hlsearch
        set incsearch
        set ignorecase
        set smartcase
        set ruler
        set showcmd
        set wildmenu
        syntax on
        colorscheme desert
        filetype plugin indent on
    """)


# -- Bash history generators -------------------------------------------------

def _bash_history_linux_admin(username: str, hostname: str, node_id: str) -> str:
    seed = hashlib.sha256(node_id.encode() + b"hist").digest()
    db_pass = secrets.token_urlsafe(16)
    vault_token = secrets.token_hex(20)
    commands = [
        "sudo apt-get update && sudo apt-get upgrade -y",
        "systemctl status nginx",
        "journalctl -u postgresql -n 100 --no-pager",
        f"ssh {_SRNG.choice(_INTERNAL_HOSTS).split('.')[0]}",
        "df -h",
        "free -m",
        "top -bn1 | head -20",
        "netstat -tulpn | grep LISTEN",
        "ss -tulpn",
        "tail -f /var/log/syslog",
        "tail -f /var/log/auth.log",
        "grep 'Failed password' /var/log/auth.log | tail -20",
        "iptables -L -n -v",
        "ufw status verbose",
        "crontab -e",
        "ansible-playbook -i inventory/prod site.yml --check",
        "ansible-playbook -i inventory/prod site.yml",
        f"psql -h db.shadowmesh.internal -U postgres_admin -d proddb -c '\\dt'",
        f"PGPASSWORD={db_pass} pg_dump -h db.shadowmesh.internal -U postgres_admin proddb > /backup/proddb_$(date +%Y%m%d).sql",
        "ls -lah /backup/",
        "du -sh /var/log/*",
        "find /etc -name '*.conf' -newer /etc/passwd",
        f"vault login -method=ldap username={username}",
        f"vault kv get -field=password secret/prod/db",
        f"export VAULT_TOKEN={vault_token}",
        "docker ps -a",
        "docker system prune -f",
        "kubectl get pods -n production",
        "kubectl logs -n production deploy/api-gateway --tail=50",
        "htop",
        "iostat -x 1 5",
        "vmstat 1 5",
        "lsof -i :5432",
        "strace -p $(pgrep nginx | head -1) -e trace=network",
        "openssl s_client -connect vault.shadowmesh.internal:8200",
        "curl -s http://monitoring.shadowmesh.internal/health | jq .",
        "history | grep ansible",
        "cat /etc/passwd | grep -v nologin",
        "last -n 20",
        "who",
        "w",
        "uptime",
        "uname -a",
        "lsb_release -a",
        "dpkg -l | grep -i security",
        "apt-cache policy openssl",
        "sudo visudo",
        "id",
        "groups",
        "sudo -l",
        "ls -la ~/.ssh/",
        "cat ~/.ssh/authorized_keys",
        "ssh-keygen -t ed25519 -C f'{username}@shadowmesh.internal'",
        "scp backup.tar.gz nexus.shadowmesh.internal:/mnt/backups/",
        "rsync -avz /etc/ nexus.shadowmesh.internal:/config-backup/$(hostname)/",
        "tar czf /tmp/logs_$(date +%Y%m%d).tar.gz /var/log/",
        "gpg --list-keys",
        "gpg --encrypt --recipient ops@corp.shadowmesh.internal report.txt",
        "exit",
    ]
    # Shuffle deterministically using node_id seed
    rng = secrets.SystemRandom()
    shuffled = list(commands)
    # Use seed-based shuffle for reproducibility per node
    for i in range(len(shuffled) - 1, 0, -1):
        j = int.from_bytes(hashlib.sha256(node_id.encode() + i.to_bytes(2, "big")).digest()[:4], "big") % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    return "\n".join(shuffled[:40]) + "\n"


def _bash_history_developer(username: str, node_id: str) -> str:
    repo_seed = hashlib.sha256(node_id.encode() + b"repo").digest()
    repos = ["api-gateway", "auth-service", "data-pipeline", "frontend-app", "ml-inference"]
    repo = repos[repo_seed[0] % len(repos)]
    branch = f"feature/{username}-{secrets.token_hex(3)}"
    commands = [
        f"cd ~/projects/{repo}",
        "git fetch --all --prune",
        "git pull origin main",
        f"git checkout -b {branch}",
        "git status",
        "git diff HEAD~1",
        "git log --oneline -10",
        "git stash",
        "git stash pop",
        "make test",
        "make lint",
        "pytest tests/ -v --tb=short",
        "pytest tests/unit/ -k 'not slow' -x",
        "python -m mypy src/ --ignore-missing-imports",
        "black src/ tests/",
        "isort src/ tests/",
        "flake8 src/",
        "docker-compose up -d",
        "docker-compose logs -f api",
        "docker-compose down",
        f"docker build -t {repo}:dev .",
        f"docker run --rm -it {repo}:dev bash",
        "pip install -r requirements.txt",
        "pip install -r requirements-dev.txt",
        "pip list --outdated",
        "pip-audit",
        "cat .env.example > .env",
        "vim .env",
        f"curl -s http://localhost:8080/health | jq .",
        f"curl -X POST http://localhost:8080/api/v1/auth/login -H 'Content-Type: application/json' -d '{{\"user\":\"test\"}}'",
        "redis-cli ping",
        "redis-cli monitor",
        "psql $DATABASE_URL -c 'SELECT count(*) FROM users;'",
        "alembic upgrade head",
        "alembic revision --autogenerate -m 'add_user_index'",
        "celery -A app.worker inspect active",
        "celery -A app.worker purge",
        "k9s",
        "kubectl port-forward svc/api-gateway 8080:80",
        "helm upgrade --install api-gateway ./charts/api-gateway -f values.prod.yaml --dry-run",
        "terraform plan -out=tfplan",
        "terraform apply tfplan",
        f"git add -p",
        f"git commit -m 'fix: resolve race condition in token refresh handler'",
        f"git push origin {branch}",
        "gh pr create --fill",
        "gh pr checks",
        "exit",
    ]
    for i in range(len(commands) - 1, 0, -1):
        j = int.from_bytes(hashlib.sha256(node_id.encode() + b"dev" + i.to_bytes(2, "big")).digest()[:4], "big") % (i + 1)
        commands[i], commands[j] = commands[j], commands[i]
    return "\n".join(commands[:40]) + "\n"


def _bash_history_finance_analyst(username: str, node_id: str) -> str:
    commands = [
        "ls ~/reports/",
        "ls ~/data/",
        "cd ~/reports/Q2_2025/",
        "python3 reconcile.py --month=2025-04",
        "python3 reconcile.py --month=2025-05",
        "python3 generate_report.py --output=pdf",
        "cat pipeline.log | grep ERROR",
        "tail -f pipeline.log",
        "scp reports/Q2_summary.xlsx nexus.shadowmesh.internal:/finance/shared/",
        "sftp nexus.shadowmesh.internal",
        "ssh gitlab.shadowmesh.internal",
        "git pull origin main",
        "git status",
        "git log --oneline -5",
        "jupyter notebook --no-browser --port=8888",
        "jupyter nbconvert --to html analysis.ipynb",
        "python3 -c \"import pandas as pd; df = pd.read_csv('data/transactions.csv'); print(df.describe())\"",
        "python3 -c \"import pandas as pd; df = pd.read_csv('data/ledger.csv'); print(df.shape)\"",
        "psql -h db.shadowmesh.internal -U finance_ro -d financedb -c 'SELECT SUM(amount) FROM transactions WHERE month=202504;'",
        "psql -h db.shadowmesh.internal -U finance_ro -d financedb -c '\\d transactions'",
        "cat ~/.pgpass",
        "gpg --decrypt Q2_forecast_encrypted.xlsx.gpg > Q2_forecast.xlsx",
        "gpg --encrypt --recipient cfo@corp.shadowmesh.internal Q2_summary.xlsx",
        "ls -lah ~/data/*.csv",
        "wc -l ~/data/transactions_2025*.csv",
        "md5sum ~/data/transactions_2025_05.csv",
        "diff reports/Q1_summary.csv reports/Q2_summary.csv",
        "crontab -l",
        "cat /etc/cron.d/finance-pipeline",
        "sudo systemctl status finance-etl",
        "sudo journalctl -u finance-etl -n 50",
        "curl -s http://monitoring.shadowmesh.internal/api/jobs/finance-etl | jq .last_run",
        "vim ~/scripts/monthly_close.sh",
        "bash ~/scripts/monthly_close.sh --dry-run",
        "history | grep psql",
        "exit",
    ]
    for i in range(len(commands) - 1, 0, -1):
        j = int.from_bytes(hashlib.sha256(node_id.encode() + b"fin" + i.to_bytes(2, "big")).digest()[:4], "big") % (i + 1)
        commands[i], commands[j] = commands[j], commands[i]
    return "\n".join(commands[:35]) + "\n"


def _cron_jobs_linux_admin(username: str) -> str:
    return textwrap.dedent(f"""\
        # Crontab for {username} -- managed by Ansible (do not edit manually)
        SHELL=/bin/bash
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

        # Daily backup
        0 2 * * * /home/{username}/scripts/backup.sh >> /var/log/backup.log 2>&1
        # Weekly log rotation
        0 3 * * 0 /home/{username}/scripts/rotate_logs.sh
        # Hourly health check
        */15 * * * * /home/{username}/scripts/healthcheck.sh | logger -t healthcheck
        # Monthly certificate renewal check
        0 9 1 * * certbot renew --quiet
    """)


def _cron_jobs_developer(username: str) -> str:
    return textwrap.dedent(f"""\
        # Crontab for {username}
        SHELL=/bin/bash
        PATH=/home/{username}/.local/bin:/usr/local/bin:/usr/bin:/bin

        # Nightly dependency audit
        0 1 * * * cd ~/projects && pip-audit -r requirements.txt >> ~/logs/audit.log 2>&1
        # Weekly git fetch all repos
        0 8 * * 1 find ~/projects -name '.git' -maxdepth 2 -execdir git fetch --all --prune \\;
    """)


def _cron_jobs_finance_analyst(username: str) -> str:
    return textwrap.dedent(f"""\
        # Crontab for {username}
        SHELL=/bin/bash
        PATH=/usr/local/bin:/usr/bin:/bin

        # Monthly close pipeline (1st of month, 6am)
        0 6 1 * * /home/{username}/scripts/monthly_close.sh >> /home/{username}/logs/close.log 2>&1
        # Daily data sync from ERP
        30 7 * * 1-5 /home/{username}/scripts/sync_erp.sh
        # Weekly report generation
        0 9 * * 5 python3 /home/{username}/scripts/generate_report.py --output=pdf
    """)


def _home_dir_files(role: str, username: str) -> List[str]:
    base = [".bash_history", ".bashrc", ".profile", ".vimrc", ".gitconfig",
            ".ssh/config", ".ssh/id_rsa.pub", ".aws/credentials", ".aws/config"]
    role_files: Dict[str, List[str]] = {
        "linux_admin": [
            "scripts/backup.sh", "scripts/healthcheck.sh", "scripts/rotate_logs.sh",
            "notes/runbook.md", "notes/incident_2024_11.md", ".ansible.cfg",
        ],
        "developer": [
            f"projects/api-gateway/README.md", ".local/bin/pip-audit",
            "logs/audit.log", ".npmrc", ".pypirc",
        ],
        "finance_analyst": [
            "reports/Q1_2025/summary.xlsx", "reports/Q2_2025/summary.xlsx",
            "data/transactions_2025_05.csv", "scripts/monthly_close.sh",
            "scripts/sync_erp.sh", "logs/close.log", ".pgpass",
        ],
    }
    return base + role_files.get(role, [])


# ---------------------------------------------------------------------------
# PersonaManager
# ---------------------------------------------------------------------------

class PersonaManager:
    """
    Singleton manager for Persona lifecycle.
    Mirrors the interface of CredentialManager and CanaryManager so
    container_manager.py can treat all three identically.
    """

    def __init__(self) -> None:
        self._personas: Dict[str, Persona] = {}

    def generate_for_node(self, node_id: str, node_type: str = "db_server") -> Persona:
        """
        Generate and store a Persona for node_id.
        Calling again with the same node_id overwrites the previous persona.
        """
        role = _NODE_TYPE_ROLE.get(node_type, "linux_admin")
        username, full_name, email, hostname, employee_id = _build_identity(node_id)
        department = _DEPARTMENTS[role]
        years = _years_tenure(node_id)

        if role == "linux_admin":
            bash_history = _bash_history_linux_admin(username, hostname, node_id)
            cron_jobs    = _cron_jobs_linux_admin(username)
        elif role == "developer":
            bash_history = _bash_history_developer(username, node_id)
            cron_jobs    = _cron_jobs_developer(username)
        else:
            bash_history = _bash_history_finance_analyst(username, node_id)
            cron_jobs    = _cron_jobs_finance_analyst(username)

        persona = Persona(
            node_id       = node_id,
            role          = role,
            username      = username,
            full_name     = full_name,
            email         = email,
            hostname      = hostname,
            department    = department,
            employee_id   = employee_id,
            years_tenure  = years,
            ssh_pubkey    = _fake_ssh_pubkey(username),
            gpg_key_id    = _fake_gpg_key_id(),
            git_config    = _git_config(full_name, email),
            bash_history  = bash_history,
            aws_config    = _aws_config(username, node_id),
            ssh_config    = _ssh_config(username),
            vimrc         = _vimrc(),
            cron_jobs     = cron_jobs,
            last_login    = _last_login_line(username, node_id),
            home_dir_files= _home_dir_files(role, username),
        )

        self._personas[node_id] = persona
        log.info(
            "[persona] Generated %s persona '%s' (%s) for node %s",
            role, username, employee_id, node_id,
        )
        return persona

    def get_for_node(self, node_id: str) -> Optional[Persona]:
        """Return the Persona for node_id, or None if not generated."""
        return self._personas.get(node_id)

    def clear_for_node(self, node_id: str) -> None:
        """Remove the Persona for node_id (called on container teardown)."""
        if self._personas.pop(node_id, None) is not None:
            log.debug("[persona] Cleared persona for node %s", node_id)

    def all_node_ids(self) -> List[str]:
        return list(self._personas.keys())


# Singleton -- imported by container_manager
persona_manager = PersonaManager()
