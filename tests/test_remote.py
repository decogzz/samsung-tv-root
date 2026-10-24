import asyncio
import base64
from pathlib import PurePosixPath
from types import SimpleNamespace

from samsung_tv_root.config import (
    RemoteConfiguration,
    RemoteDeviceConfiguration,
    RemoteRuleConfiguration,
    TelevisionConfiguration,
)
from samsung_tv_root.remote import (
    REMOTE_DIRECTORIES,
    RemoteInputCoordinator,
    _blocked_tokens,
    _capability_request,
    _matches,
    _parse_identity,
    parse_input_devices,
)


def test_remote_identity_preserves_device_metadata() -> None:
    encoded = [
        base64.b64encode(value.encode()).decode()
        for value in ("Smart Control", "/dev/input/event4", "bluetooth", "VG-TM2560")
    ]
    identity = _parse_identity(
        "\t".join(("AUTH", "123", "0", "0", *encoded, "observe"))
    )
    assert identity.device == "Smart Control"
    assert identity.transport == "bluetooth"
    assert identity.model == "VG-TM2560"
    assert identity.mode == "observe"


def test_remote_filter_blocks_only_explicit_rule_tokens() -> None:
    rules = (
        RemoteRuleConfiguration(action="suppress", key="XF86Caption"),
        RemoteRuleConfiguration(action="source.select", code=59, source="HDMI1"),
    )
    assert _blocked_tokens(rules) == ("59", "XF86Caption")
    assert _matches(
        rules[0],
        {"action": "down", "key": "XF86Caption", "code": 213},
    )
    assert not _matches(
        rules[0],
        {"action": "up", "key": "XF86Caption", "code": 213},
    )


def test_app_launch_action_maps_to_capability_request() -> None:
    action, request = _capability_request(
        RemoteRuleConfiguration(action="app.launch", key="XF86Home", app="FreeMyTV.tizen")
    )
    assert action == "app.launch"
    assert request == {"app": "FreeMyTV.tizen"}


def test_remote_local_dimming_action_maps_to_packaged_capability() -> None:
    action, request = _capability_request(
        RemoteRuleConfiguration(action="local_dimming.enable", key="XF86Guide")
    )
    assert action == "local_dimming.set"
    assert request == {"enabled": True}


def test_input_device_inventory_keeps_kernel_device_strings() -> None:
    devices = parse_input_devices(
        "I: Bus=0005 Vendor=04e8 Product=0001 Version=0001\n"
        'N: Name="Smart Control"\n'
        "H: Handlers=kbd event4\n\n"
        'N: Name="No Event Node"\n'
        "H: Handlers=sysrq\n"
    )
    assert len(devices) == 1
    assert devices[0].name == "Smart Control"
    assert devices[0].node == "/dev/input/event4"
    assert devices[0].bus == "0005"
    assert devices[0].vendor == "04e8"


class _FakeRootConnection:
    def __init__(self, writable_directory: PurePosixPath | None) -> None:
        self.writable_directory = writable_directory
        self.written: list[str] = []
        self.executed: list[str] = []

    async def write_file(self, path, data: bytes, timeout: float = 5.0) -> None:
        self.written.append(str(path))

    async def execute(self, command: str, timeout: float = 5.0) -> object:
        self.executed.append(command)
        return SimpleNamespace(
            stdout="", stderr="", exit_code=0, timed_out=False
        )


class _FakeRemoteInputServer:
    def __init__(self, *args, **kwargs) -> None:
        self.port = 41234
        self.closed = False

    async def start(self) -> None:
        pass

    async def wait(self, timeout: float) -> object:
        return SimpleNamespace(
            identity=SimpleNamespace(
                process_id=123,
                user_id=0,
                group_id=0,
                device="Smart Control",
                node="/dev/input/event3",
                transport="bluetooth",
                model="VG",
            )
        )

    async def close(self) -> None:
        self.closed = True


def _archive_television() -> TelevisionConfiguration:
    return TelevisionConfiguration(
        name="s90d",
        model="archive",
        host="192.0.2.36",
        device_id=None,
        root_on_presence=True,
        disable_native_execution_policy=False,
        remote=RemoteConfiguration(
            enabled=True,
            devices=(
                RemoteDeviceConfiguration(
                    name="Smart Control", transport="bluetooth", model="VG"
                ),
            ),
            rules=(),
        ),
    )


def test_launch_writes_token_into_archive_staging_directory(monkeypatch) -> None:
    """The archive root agent only accepts WRITEFILE inside its per-session
    staging directory; the remote-input token must go there."""
    import samsung_tv_root.remote as remote_module

    monkeypatch.setattr(remote_module, "RemoteInputServer", _FakeRemoteInputServer)
    coordinator = RemoteInputCoordinator(
        _archive_television(), lambda *_: None, lambda *a, **k: {}, (30.0,)
    )
    staging = PurePosixPath("/home/owner/share/tmp/sdk_tools/archive-root-abcd")
    root = _FakeRootConnection(staging)

    async def run() -> None:
        session = await coordinator._launch(
            root,
            "192.0.2.36",
            coordinator.television.remote.devices[0],
        )
        await session.server.close()

    asyncio.run(run())

    assert len(root.written) == 1
    written = root.written[0]
    assert written.startswith(str(staging))
    assert "/rt-" in written
    # The launch command must reference the token path and the agent dll
    # that lives in the model's shared remote directory.
    assert str(REMOTE_DIRECTORIES["archive"]) in root.executed[0]
    assert written in root.executed[0]


def test_launch_falls_back_to_model_directory_without_restriction(monkeypatch) -> None:
    """Connections without a writable_directory restriction (qn90b/qn90f)
    keep writing tokens to the model's shared remote directory."""
    import samsung_tv_root.remote as remote_module

    monkeypatch.setattr(remote_module, "RemoteInputServer", _FakeRemoteInputServer)
    coordinator = RemoteInputCoordinator(
        _archive_television(), lambda *_: None, lambda *a, **k: {}, (30.0,)
    )
    root = _FakeRootConnection(None)

    async def run() -> None:
        session = await coordinator._launch(
            root,
            "192.0.2.36",
            coordinator.television.remote.devices[0],
        )
        await session.server.close()

    asyncio.run(run())

    assert len(root.written) == 1
    written = root.written[0]
    assert written.startswith(str(REMOTE_DIRECTORIES["archive"]))
    assert "/rt-" in written
