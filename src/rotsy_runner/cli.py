"""Command line: ``rotsy-runner register | run | status | tools | unregister | version``.

Registration is designed so the one-time enrollment token does not have to
land in shell history: by default ``register`` prompts for it (no echo). For
automation it can come from ``--token-file``, ``--token-stdin`` or the
``ROTSY_ENROLLMENT_TOKEN`` environment variable. ``--token`` works too, for
parity with GitLab-style instructions, and says so. The token is single-use
and short-lived either way, so a copy left in history is spent.

Exit codes: 0 success · 1 error · 2 usage · 3 credential rejected / token refused.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import PROTOCOL_VERSION, __version__, hostinfo, logs, state
from .agent import CAPABILITIES, Agent
from .client import AuthError, ClientError, RequestError, ServerClient, TokenError
from .config import Config, ConfigError, validate_server_url

logger = logging.getLogger("rotsy_runner")


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _read_token(args: argparse.Namespace) -> str:
    if args.token_file:
        return Path(args.token_file).read_text().strip()
    if args.token_stdin:
        return sys.stdin.readline().strip()
    if args.token:
        sys.stderr.write(
            "warning: --token puts the token in shell history and the process list; "
            "it is single-use, but --token-file or the prompt avoid that.\n"
        )
        return args.token.strip()
    if os.environ.get("ROTSY_ENROLLMENT_TOKEN"):
        return os.environ["ROTSY_ENROLLMENT_TOKEN"].strip()
    if sys.stdin.isatty():
        return getpass.getpass("Enrollment token (from Rotsy → Runners → Create runner): ").strip()
    raise ConfigError("no enrollment token: use the prompt, --token-file, --token-stdin or ROTSY_ENROLLMENT_TOKEN")


async def _register(config: Config, server_url: str, token: str) -> state.Identity:
    os_name, arch = hostinfo.current()
    client = ServerClient(config, server_url)
    try:
        resp = await client.register(
            token,
            {
                "hostname": hostinfo.hostname(),
                "os": os_name,
                "arch": arch,
                "version": __version__,
                "protocol_version": PROTOCOL_VERSION,
                "capabilities": CAPABILITIES,
                "concurrency": config.concurrency,
            },
        )
    finally:
        await client.aclose()
    logs.register_secret(resp.credential)
    identity = state.Identity(
        server_url=server_url,
        runner_uid=resp.runner_uid,
        name=resp.name,
        registered_at=datetime.now(timezone.utc).isoformat(),
        protocol_version=resp.protocol_version,
    )
    state.save(config.state_dir, identity, resp.credential)
    return identity


def cmd_register(args: argparse.Namespace, config: Config) -> int:
    server_url = validate_server_url(args.server, allow_insecure_http=config.allow_insecure_http)
    if state.load(config.state_dir) is not None and not args.force:
        _out(f"This runner is already registered (see `rotsy-runner status`, data dir {config.data_dir}).")
        _out("Pass --force to replace that registration.")
        return 1
    token = _read_token(args)
    logs.register_secret(token)
    try:
        identity = asyncio.run(_register(config, server_url, token))
    except TokenError as exc:
        _out(f"Registration refused: {exc}")
        return 3
    except AuthError as exc:
        _out(f"Registration refused: {exc}")
        return 3
    except RequestError as exc:
        _out(f"Registration failed: {exc}")
        return 1
    except ClientError as exc:
        _out(f"Could not reach {server_url}: {exc}")
        return 1
    _out(f"Runner registered: {identity.name} ({identity.runner_uid})")
    _out(f"Server:            {identity.server_url}")
    _out(f"Credential stored: {config.state_dir / state.CREDENTIAL_FILE} (mode 0600)")
    _out("Start it with:     rotsy-runner run")
    return 0


def cmd_run(args: argparse.Namespace, config: Config) -> int:
    loaded = state.load(config.state_dir)
    if loaded is None:
        token = os.environ.get("ROTSY_ENROLLMENT_TOKEN")
        server = os.environ.get("ROTSY_SERVER_URL")
        if not (token and server):
            _out(f"This runner is not registered (no identity in {config.state_dir}).")
            _out(
                "Run `rotsy-runner register --server https://rotsy.example.com` first, or set "
                "ROTSY_SERVER_URL and ROTSY_ENROLLMENT_TOKEN to register on first start."
            )
            return 1
        logs.register_secret(token)
        server_url = validate_server_url(server, allow_insecure_http=config.allow_insecure_http)
        try:
            asyncio.run(_register(config, server_url, token))
        except (TokenError, AuthError) as exc:
            _out(f"Registration refused: {exc}")
            return 3
        loaded = state.load(config.state_dir)
        assert loaded is not None
        logger.info("Registered on first start as %s", loaded[0].name)
    identity, credential = loaded
    validate_server_url(identity.server_url, allow_insecure_http=config.allow_insecure_http)
    return asyncio.run(Agent(config, identity, credential).run())


def cmd_status(args: argparse.Namespace, config: Config) -> int:
    loaded = state.load(config.state_dir)
    from .tools import ToolManager

    manager = ToolManager(config)
    # A fresh process has no cached database probe; check now so `status`
    # reports what a scan would actually find.
    asyncio.run(manager.refresh_probes(force=True))
    report = manager.report()
    info = {
        "version": __version__,
        "protocol_version": PROTOCOL_VERSION,
        "data_dir": str(config.data_dir),
        "registered": loaded is not None,
        "runner": None if loaded is None else {k: v for k, v in loaded[0].__dict__.items()},
        "tools": report,
    }
    if args.json:
        _out(json.dumps(info, indent=2))
    else:
        _out(f"rotsy-runner {__version__} (protocol v{PROTOCOL_VERSION}), data dir {config.data_dir}")
        if loaded is None:
            _out("Not registered.")
        else:
            ident = loaded[0]
            _out(f"Runner {ident.name} ({ident.runner_uid}) → {ident.server_url}, registered {ident.registered_at}")
        for tool in report:
            _out(
                f"  {tool['name']:<14} {tool['version'] or '-':<22} {tool['status']:<10} "
                f"{'ready' if tool['ready'] else 'not ready'}  {tool['error']}"
            )
    return 0


def cmd_unregister(args: argparse.Namespace, config: Config) -> int:
    removed = state.clear(config.state_dir)
    _out(
        "Local registration removed. Delete the runner on the server's Runners page too."
        if removed
        else "This runner was not registered."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rotsy-runner", description="Execution agent for Rotsy.")
    parser.add_argument(
        "--data-dir", help="state, tools and caches (default: $ROTSY_RUNNER_DATA_DIR or /var/lib/rotsy-runner)"
    )
    parser.add_argument(
        "--allow-insecure-http", action="store_true", help="permit a plain-http server URL (local test setups only)"
    )
    parser.add_argument("--ca-file", help="CA bundle for a server certificate from a private CA")
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", help="exchange an enrollment token for a runner credential")
    reg.add_argument("--server", required=True, help="Rotsy server origin, e.g. https://rotsy.example.com")
    source = reg.add_mutually_exclusive_group()
    source.add_argument("--token", help="enrollment token (prefer the prompt or --token-file)")
    source.add_argument("--token-file", help="read the enrollment token from this file")
    source.add_argument("--token-stdin", action="store_true", help="read the enrollment token from stdin")
    reg.add_argument("--force", action="store_true", help="replace an existing registration")

    sub.add_parser("run", help="run the agent (heartbeat, tool sync, scans)")
    st = sub.add_parser("status", help="show this runner's registration and installed tools")
    st.add_argument("--json", action="store_true")
    sub.add_parser("tools", help="alias for `status`")
    sub.add_parser("unregister", help="forget this runner's local registration")
    sub.add_parser("version", help="print the version")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        _out(f"rotsy-runner {__version__} (protocol v{PROTOCOL_VERSION})")
        return 0
    try:
        config = Config.from_env(
            data_dir=args.data_dir, ca_file=args.ca_file, allow_insecure_http=True if args.allow_insecure_http else None
        )
        logs.setup(config.log_level)
        handler = {
            "register": cmd_register,
            "run": cmd_run,
            "status": cmd_status,
            "tools": cmd_status,
            "unregister": cmd_unregister,
        }[args.command]
        if args.command == "tools":
            args.json = False
        return handler(args, config)
    except ConfigError as exc:
        _out(f"configuration error: {exc}")
        return 2
    except PermissionError as exc:
        _out(f"permission error: {exc}")
        return 1
    except KeyboardInterrupt:
        return 130
