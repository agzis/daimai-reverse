"""Frida transport for the official Damai application runtime bridge."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class RuntimeTransport:
    """Attach to an already-running app process and expose bridge RPCs."""

    def __init__(self, device_id: str, pid: int, bundle_path: str | Path, timeout_seconds: float):
        self.device_id = device_id
        self.pid = pid
        self.bundle_path = Path(bundle_path)
        self.timeout_seconds = float(timeout_seconds)
        if not device_id:
            raise ValueError("device_id must be non-empty")
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive integer")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._device = None
        self._device_manager = None
        self._remote_address = None
        self._session = None
        self._script = None

    def __enter__(self) -> "RuntimeTransport":
        try:
            import frida
        except ImportError as exc:
            raise RuntimeError("Frida Python bindings are unavailable; install frida in this interpreter") from exc
        try:
            if not self.bundle_path.is_file():
                raise FileNotFoundError(f"Bridge bundle not found: {self.bundle_path}")
            if ":" in self.device_id:
                self._device_manager = frida.get_device_manager()
                self._remote_address = self.device_id
                self._device = self._device_manager.add_remote_device(self.device_id)
            else:
                self._device = frida.get_device(self.device_id, timeout=self.timeout_seconds)
            self._session = self._device.attach(self.pid)
            source = self.bundle_path.read_text(encoding="utf-8")
            self._script = self._session.create_script(source)
            self._script.load()
            return self
        except Exception as exc:
            self.close()
            raise RuntimeError(f"Unable to attach/load Frida bridge for pid {self.pid}: {exc}") from exc

    def status(self) -> dict[str, Any]:
        return self._rpc("status")

    def request(self, spec: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(spec, dict):
            raise TypeError("spec must be a dictionary")
        return self._rpc("request", spec)

    def _rpc(self, method: str, *args: Any) -> dict[str, Any]:
        if self._script is None:
            raise RuntimeError("RuntimeTransport is not open")
        import frida

        script = self._script
        done = threading.Event()
        outcome: dict[str, Any] = {}
        cancellable = frida.Cancellable()

        def invoke() -> None:
            try:
                with cancellable:
                    outcome["result"] = getattr(script.exports_sync, method)(*args)
            except Exception as exc:
                outcome["error"] = exc
            finally:
                done.set()

        worker = threading.Thread(target=invoke, daemon=True)
        worker.start()
        if not done.wait(self.timeout_seconds):
            cancellable.cancel()
            worker.join(timeout=1)
            self.close()
            raise TimeoutError(f"Frida {method} RPC exceeded {self.timeout_seconds:g}s; outcome unknown")
        if "error" in outcome:
            exc = outcome["error"]
            raise RuntimeError(f"Frida {method} RPC failed ({type(exc).__name__}); SDK details omitted to protect credentials") from exc
        result = outcome["result"]
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Frida {method} returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise RuntimeError(f"Frida {method} returned an unexpected result type")
        return result

    def close(self) -> None:
        script, self._script = self._script, None
        session, self._session = self._session, None
        device_manager, self._device_manager = self._device_manager, None
        remote_address, self._remote_address = self._remote_address, None
        self._device = None
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if device_manager is not None and remote_address is not None:
            try:
                device_manager.remove_remote_device(remote_address)
            except Exception:
                pass
    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
