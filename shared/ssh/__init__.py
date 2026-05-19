"""Reusable SSH engine for the Single Digits Engineering Platform shell."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import re
import socket
import time
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

try:
    import paramiko
except ImportError:  # pragma: no cover - handled at runtime with a clean message
    paramiko = None

from shared.commands import DETECTION_COMMANDS, CENTRAL_DETECTION_COMMANDS, get_paging_disable_commands
from shared.models import AuthMethod, CommandResult, Credentials, SSHOptions, SSHSessionResult, SwitchTarget, Vendor
from shared.parsers import clean_output
from shared.security.redaction import safe_client_error, redact_text
from shared.vendors import detect_vendor

LOGGER = logging.getLogger("sd_shell.shared.ssh")

_PROMPT_RE = re.compile(rb"(?m)^\s*(?:\*\s*)?([A-Za-z0-9_.()/: -]+(?:\.\d+)?\s*[>#])\s*$")
_MORE_PATTERNS = [b"--More--", b"More:", b"Press any key to continue", b"press RETURN to continue"]


def clean_terminal_text(text: str) -> str:
    """Strip ANSI/control noise from interactive switch terminal output."""
    if text is None:
        return ""

    s = str(text)
    s = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", s)
    s = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", s)
    s = s.replace("\x1b", "").replace("\x07", "")
    s = s.replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    s = "".join(ch for ch in s if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    s = re.sub(r"\n{4,}", "\n\n", s)
    return s


def extract_network_prompt(text: str) -> str:
    """Return the last visible switch prompt found anywhere in cleaned output."""
    clean = clean_terminal_text(text)
    matches = re.findall(
        r"(?m)(?:^|\n)\s*([A-Za-z0-9][A-Za-z0-9_.-]{1,80}(?:\([^)]+\))?[#>])\s*",
        clean,
    )
    return matches[-1].strip() if matches else ""


def has_network_prompt(text: str) -> bool:
    return bool(extract_network_prompt(text))


def drain_shell(shell, limit: int = 20) -> str:
    """Drain currently ready shell bytes and return decoded text."""
    chunks = []
    for _ in range(limit):
        try:
            if not shell.recv_ready():
                break
            chunks.append(shell.recv(65535).decode("utf-8", errors="ignore"))
            time.sleep(0.01)
        except Exception:
            break
    return "".join(chunks)


def settle_shell_prompt(shell, enters: int = 3, pause: float = 0.25, timeout: float = 2.5) -> tuple[str, str]:
    """Send blank enters after login and return (cleaned_text, prompt)."""
    transcript = ""
    try:
        transcript += drain_shell(shell)
    except Exception:
        pass

    for _ in range(max(1, enters)):
        try:
            shell.send("\n")
            time.sleep(pause)
            transcript += drain_shell(shell)
        except Exception:
            break

    end = time.time() + max(0.5, timeout)
    while time.time() < end:
        try:
            if shell.recv_ready():
                transcript += shell.recv(65535).decode("utf-8", errors="ignore")
                if has_network_prompt(transcript):
                    break
            else:
                time.sleep(0.03)
        except Exception:
            break

    clean = clean_terminal_text(transcript)
    return clean, extract_network_prompt(clean)



def configure_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    LOGGER.setLevel(level)
    if not LOGGER.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        LOGGER.addHandler(handler)
    paramiko_logger = logging.getLogger("paramiko")
    paramiko_logger.setLevel(logging.DEBUG if debug else logging.CRITICAL)


def expand_targets(raw_targets: str, default_port: int = 22) -> List[SwitchTarget]:
    targets: List[SwitchTarget] = []
    seen = set()
    tokens = re.split(r"[\s,;]+", raw_targets.strip()) if raw_targets else []
    for token in filter(None, tokens):
        host, port = _parse_host_port(token, default_port)
        if "/" in host:
            network = ipaddress.ip_network(host, strict=False)
            for ip in network.hosts():
                key = (str(ip), port)
                if key not in seen:
                    targets.append(SwitchTarget(host=str(ip), port=port))
                    seen.add(key)
        else:
            key = (host, port)
            if key not in seen:
                targets.append(SwitchTarget(host=host, port=port))
                seen.add(key)
    return targets


def _parse_host_port(token: str, default_port: int) -> Tuple[str, int]:
    token = token.strip()
    if token.startswith("[") and "]:" in token:
        host, port = token.rsplit(":", 1)
        return host.strip("[]"), int(port)
    if token.count(":") == 1 and "/" not in token.split(":", 1)[1]:
        host, port = token.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return token, default_port


def scan_switches(
    raw_targets: str,
    credentials: Credentials,
    commands: Optional[Sequence[str]] = None,
    options: Optional[SSHOptions] = None,
    progress_callback: Optional[Callable[[SSHSessionResult], None]] = None,
) -> List[SSHSessionResult]:
    opts = options or SSHOptions()
    configure_logging(opts.debug)
    targets = expand_targets(raw_targets, default_port=opts.default_port)
    workers = opts.normalized_concurrency()
    results: List[SSHSessionResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(scan_single_switch, target, credentials, commands or [], opts): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(future_map):
            try:
                result = future.result()
            except Exception as exc:
                target = future_map[future]
                error = safe_client_error(exc, default="SSH scan worker failed.")
                result = SSHSessionResult(target=target, ok=False, error=error)
            results.append(result)
            if progress_callback:
                progress_callback(result)
    return results


def scan_single_switch(
    target: SwitchTarget,
    credentials: Credentials,
    commands: Sequence[str],
    options: Optional[SSHOptions] = None,
) -> SSHSessionResult:
    opts = options or SSHOptions()
    debug_log: List[str] = []

    def dbg(message: str) -> None:
        if opts.debug:
            debug_log.append(message)
            LOGGER.debug("%s %s", target.endpoint, message)

    result = SSHSessionResult(target=target, ok=False, debug_log=debug_log)
    auth_attempts = _auth_attempts(credentials)
    last_error: Optional[str] = None

    for username, password, method in auth_attempts:
        try:
            dbg(f"connecting as {username}")
            client = _connect(target, username, password, opts)
            result.auth_method = method
            if method != AuthMethod.USER_PROVIDED:
                result.non_standard_password_note = f"TP-Link fallback authentication succeeded using {method.value}. Verify and replace this credential."
            try:
                shell = client.invoke_shell(width=240, height=1000)
                prompt = _prime_shell(shell, opts, dbg)
                result.prompt = prompt
                detection_output = _run_detection(shell, opts, dbg)
                detection = detect_vendor(detection_output)
                result.detection = detection
                result.vendor = detection.vendor
                result.hostname = detection.hostname

                for pager_cmd in get_paging_disable_commands(result.vendor):
                    _send_command(shell, pager_cmd, opts, dbg, tolerate_errors=True)

                if result.vendor == Vendor.ARUBA_CX:
                    for central_cmd in CENTRAL_DETECTION_COMMANDS.get(Vendor.ARUBA_CX, []):
                        out = _send_command(shell, central_cmd, opts, dbg, tolerate_errors=True)
                        central_detection = detect_vendor(detection_output + "\n" + out)
                        result.detection.central_connected = central_detection.central_connected

                for command in commands:
                    try:
                        output = _send_command(shell, command, opts, dbg)
                        result.command_results.append(CommandResult(command=command, output=output, ok=True))
                    except Exception as exc:
                        result.command_results.append(CommandResult(command=command, output="", ok=False, error=safe_client_error(exc, default="Command failed.")))
                result.ok = True
                return result
            finally:
                client.close()
        except Exception as exc:
            last_error = safe_client_error(exc, default="SSH scan worker failed.")
            dbg(f"auth/connect failed: {redact_text(last_error or 'SSH connection failed.', [credentials.password])}")
            # Fallback auth is intended for TP-Link-style media panel devices only.
            # We cannot reliably know vendor before login, so try limited fallbacks after the user credential fails.
            continue

    result.error = last_error or "Unable to connect"
    return result


def _auth_attempts(credentials: Credentials) -> List[Tuple[str, str, AuthMethod]]:
    # Security baseline Alpha 0.7.6: no hardcoded fallback credentials.
    # Legacy/TP-Link fallback auth must be handled explicitly by a future opt-in
    # configuration mechanism, never by embedded default passwords.
    return [(credentials.username, credentials.password, AuthMethod.USER_PROVIDED)]


def _connect(target: SwitchTarget, username: str, password: str, opts: SSHOptions) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("Paramiko is required for SSH operations. Install requirements.txt in the app bundle.")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if opts.old_kex:
        _enable_legacy_kex_if_available()

    connect_kwargs = dict(
        hostname=target.host,
        port=target.port,
        username=username,
        password=password,
        timeout=opts.timeout,
        banner_timeout=opts.banner_timeout,
        auth_timeout=opts.auth_timeout,
        look_for_keys=opts.look_for_keys,
        allow_agent=opts.allow_agent,
    )
    try:
        client.connect(**connect_kwargs)
    except paramiko.ssh_exception.IncompatiblePeer:
        if not opts.old_kex:
            raise
        # Paramiko 3 can still negotiate legacy KEX on many systems if disabled algorithms are not forced.
        # Retry with a fresh client and no extra restrictions. The UI/debug log should flag hosts that need this.
        client.close()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(**connect_kwargs)
    return client


def _enable_legacy_kex_if_available() -> None:
    """Allow old Ruckus/ICX KEX algorithms when Paramiko still has them available.

    This supports older switches that only offer algorithms such as
    diffie-hellman-group1-sha1. If the installed Paramiko/cryptography stack
    removed the algorithm entirely, the clean connection error is returned to
    the caller instead of printing a traceback.
    """
    if paramiko is None:
        return
    transport = getattr(paramiko, "Transport", None)
    if not transport or not hasattr(transport, "_preferred_kex"):
        return
    preferred = list(getattr(transport, "_preferred_kex", ()))
    legacy = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ]
    changed = False
    for alg in legacy:
        if alg not in preferred:
            preferred.append(alg)
            changed = True
    if changed:
        transport._preferred_kex = tuple(preferred)


def _prime_shell(shell: paramiko.Channel, opts: SSHOptions, dbg: Callable[[str], None]) -> str:
    time.sleep(0.2)
    _drain(shell)
    shell.send("\n")
    output = _read_until_prompt(shell, opts.command_timeout, dbg)
    prompt = _extract_prompt(output) or ""
    dbg(f"prompt={prompt!r}")
    # ProCurve often waits for a keypress after banner/login notice.
    if "press any key" in output.lower() or "continue" in output.lower():
        shell.send(" \n")
        output += _read_until_prompt(shell, opts.command_timeout, dbg)
        prompt = _extract_prompt(output) or prompt
    return prompt


def _run_detection(shell: paramiko.Channel, opts: SSHOptions, dbg: Callable[[str], None]) -> str:
    outputs = []
    for command in DETECTION_COMMANDS:
        try:
            outputs.append(_send_command(shell, command, opts, dbg, tolerate_errors=True))
        except Exception:
            continue
    return "\n".join(outputs)


def _send_command(
    shell: paramiko.Channel,
    command: str,
    opts: SSHOptions,
    dbg: Callable[[str], None],
    tolerate_errors: bool = False,
) -> str:
    dbg(f"cmd={command}")
    _drain(shell)
    shell.send(command + "\n")
    raw = _read_until_prompt(shell, opts.command_timeout, dbg)
    output = clean_output(raw)
    if output.lower().strip().endswith(command.lower()):
        output = output[: -len(command)].strip()
    return output


def _read_until_prompt(shell: paramiko.Channel, timeout: int, dbg: Callable[[str], None]) -> str:
    end = time.time() + timeout
    buf = b""
    while time.time() < end:
        if shell.recv_ready():
            chunk = shell.recv(65535)
            buf += chunk
            if any(marker in chunk for marker in _MORE_PATTERNS):
                shell.send(" ")
            if _PROMPT_RE.search(buf[-500:]):
                break
        else:
            time.sleep(0.03)
    return buf.decode(errors="ignore")


def _drain(shell: paramiko.Channel) -> str:
    data = b""
    while shell.recv_ready():
        data += shell.recv(65535)
        time.sleep(0.01)
    return data.decode(errors="ignore")


def _extract_prompt(output: str) -> Optional[str]:
    match = re.search(r"(?m)^\s*(?:\*\s*)?([A-Za-z0-9_.()/: -]+(?:\.\d+)?\s*[>#])\s*$", output or "")
    return match.group(1).strip() if match else None



def run_commands(host: str, username: str = "", password: str = "", commands=None, port: int = 22, timeout: int = 12, **kwargs):
    """Compatibility helper used by older shell modules.

    Returns a simple {command: output} dict while using the shared scan_single_switch
    engine underneath.
    """
    commands = commands or []
    target = SwitchTarget(host=host, port=port)
    creds = Credentials(username=username or kwargs.get("user", ""), password=password or kwargs.get("pass", ""))
    opts = SSHOptions(timeout=timeout, command_timeout=kwargs.get("command_timeout", 25), debug=bool(kwargs.get("debug", False)))
    result = scan_single_switch(target, creds, commands, opts)
    return {row.command: row.output for row in result.command_results}
