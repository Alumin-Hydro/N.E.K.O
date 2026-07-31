import asyncio
import copy
import hashlib
import json
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.responses import JSONResponse

from main_routers.characters_router import crud


PLUGIN_ID = "auto_prompt_harness"
BINDING_ID = "0123456789abcdef01234567"
OVERLAY_NAME = "小柚（自适应）"
ORIGINAL_NAME = "小柚"
THIRD_NAME = "小葵"


class _DummyRequest:
    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


class _FakeConfigManager:
    def __init__(self, characters, *, allow_save=False):
        self.characters = characters
        self.allow_save = allow_save
        self.load_calls = 0
        self.save_calls = 0

    async def aload_characters(self):
        self.load_calls += 1
        return self.characters

    async def asave_characters(self, characters):
        self.save_calls += 1
        if not self.allow_save:
            raise AssertionError("this request must not write character cards")
        self.characters = copy.deepcopy(characters)


def _prompt_fingerprint(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _card_fingerprint(card: dict) -> str:
    canonical = json.dumps(
        card,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _characters(prompt: str = "你是小柚。") -> dict:
    return {
        "主人": {"昵称": "主人"},
        "当前猫娘": OVERLAY_NAME,
        "猫娘": {
            ORIGINAL_NAME: {
                "昵称": "小柚",
                "_reserved": {"system_prompt": "你是小柚。"},
            },
            OVERLAY_NAME: {
                "昵称": "小柚",
                "_reserved": {
                    "system_prompt": prompt,
                    "auto_prompt_harness": {
                        "plugin_id": PLUGIN_ID,
                        "kind": "adaptive_overlay",
                        "schema_version": 2,
                        "binding_id": BINDING_ID,
                        "original_name": ORIGINAL_NAME,
                    },
                },
            },
            THIRD_NAME: {
                "昵称": "小葵",
                "_reserved": {"system_prompt": "你是小葵。"},
            },
        },
    }


def _request_payload(prompt: str = "你是小柚。") -> dict:
    return {
        "character_name": OVERLAY_NAME,
        "plugin_id": PLUGIN_ID,
        "binding_id": BINDING_ID,
        "prompt_fingerprint": _prompt_fingerprint(prompt),
    }


def _restore_payload() -> dict:
    return {
        "plugin_id": PLUGIN_ID,
        "binding_id": BINDING_ID,
        "overlay_name": OVERLAY_NAME,
        "original_name": ORIGINAL_NAME,
    }


def _delete_payload(card: dict) -> dict:
    return {
        "plugin_id": PLUGIN_ID,
        "binding_id": BINDING_ID,
        "overlay_name": OVERLAY_NAME,
        "expected_card_fingerprint": _card_fingerprint(card),
    }


def _response_payload(response: JSONResponse) -> dict:
    return json.loads(response.body.decode("utf-8"))


def _install_delete_runtime(monkeypatch, config_manager, tmp_path):
    config_manager.app_docs_dir = tmp_path
    config_manager.memory_dir = tmp_path / "memory"
    config_manager.card_faces_dir = tmp_path / "card_faces"
    config_manager.card_face_meta_path = (
        lambda name: tmp_path / "card_face_meta" / f"{name}.json"
    )

    release = AsyncMock(return_value=True)
    remove_one = AsyncMock()
    notify_reload = AsyncMock(return_value=True)
    remove_pending = AsyncMock()
    delete_storage = Mock(return_value=[])

    monkeypatch.setattr(crud, "_current_catgirl_switch_lock", asyncio.Lock())
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(crud, "release_memory_server_character", release)
    monkeypatch.setattr(crud, "list_character_memory_paths", lambda *_: [])
    monkeypatch.setattr(
        crud,
        "delete_character_memory_storage",
        delete_storage,
    )
    monkeypatch.setattr(crud, "is_cloudsave_disabled", lambda: True)
    monkeypatch.setattr(crud, "assert_cloudsave_writable", lambda *_, **__: None)
    monkeypatch.setattr(crud, "get_remove_one_catgirl", lambda: remove_one)
    monkeypatch.setattr(crud, "notify_memory_server_reload", notify_reload)
    monkeypatch.setattr(
        crud,
        "remove_new_character_greeting_pending",
        remove_pending,
    )
    monkeypatch.setattr(
        "main_routers.workshop_router.mark_session_deleted_character_name",
        lambda *_: None,
    )
    return {
        "release": release,
        "remove_one": remove_one,
        "notify_reload": notify_reload,
        "remove_pending": remove_pending,
        "delete_storage": delete_storage,
    }


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_refresh_verifies_card_and_refreshes_without_writing(
    monkeypatch,
):
    prompt = "你是小柚。\n请保持温柔。"
    characters = _characters(prompt)
    config_manager = _FakeConfigManager(characters)
    refresh = AsyncMock(
        return_value={
            "context_refreshed": True,
            "recent_history_cleared": True,
            "session_restarted": True,
        }
    )
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(
        crud,
        "_refresh_catgirl_context_after_profile_change",
        refresh,
    )

    result = await crud.refresh_managed_overlay_prompt(
        _DummyRequest(_request_payload(prompt))
    )

    assert result == {
        "success": True,
        "character_name": OVERLAY_NAME,
        "binding_id": BINDING_ID,
        "prompt_fingerprint": _prompt_fingerprint(prompt),
        "context_refreshed": True,
        "recent_history_cleared": True,
        "session_restarted": True,
    }
    refresh.assert_awaited_once_with(
        config_manager,
        OVERLAY_NAME,
        characters,
        reload_message="自适应角色提示词已更新，页面即将刷新",
    )
    assert config_manager.save_calls == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_refresh_rejects_provenance_mismatch(monkeypatch):
    characters = _characters()
    characters["猫娘"][OVERLAY_NAME]["_reserved"]["auto_prompt_harness"][
        "binding_id"
    ] = "fedcba9876543210fedcba98"
    config_manager = _FakeConfigManager(characters)
    refresh = AsyncMock()
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(
        crud,
        "_refresh_catgirl_context_after_profile_change",
        refresh,
    )

    response = await crud.refresh_managed_overlay_prompt(
        _DummyRequest(_request_payload())
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 409
    assert _response_payload(response) == {
        "success": False,
        "code": "MANAGED_OVERLAY_PROVENANCE_MISMATCH",
        "error": "角色卡不是该绑定拥有的自适应副本",
    }
    refresh.assert_not_awaited()
    assert config_manager.save_calls == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_restore_atomically_switches_to_original(monkeypatch):
    characters = _characters()
    cards_before = copy.deepcopy(characters["猫娘"])
    config_manager = _FakeConfigManager(characters, allow_save=True)
    side_effects = AsyncMock()
    monkeypatch.setattr(crud, "_current_catgirl_switch_lock", asyncio.Lock())
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(crud, "get_session_manager", lambda: {})
    monkeypatch.setattr(
        crud,
        "_apply_current_catgirl_switch_side_effects",
        side_effects,
    )

    result = await crud.restore_managed_overlay_original(
        _DummyRequest(_restore_payload())
    )

    assert result == {
        "success": True,
        "switched": True,
        "preserved_user_choice": False,
        "current_catgirl": ORIGINAL_NAME,
        "original_name": ORIGINAL_NAME,
        "overlay_name": OVERLAY_NAME,
    }
    assert config_manager.save_calls == 1
    assert config_manager.characters["当前猫娘"] == ORIGINAL_NAME
    assert config_manager.characters["猫娘"] == cards_before
    side_effects.assert_awaited_once_with(OVERLAY_NAME, ORIGINAL_NAME, {})


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_restore_preserves_third_card_without_writing(
    monkeypatch,
):
    characters = _characters()
    characters["当前猫娘"] = THIRD_NAME
    config_manager = _FakeConfigManager(characters)
    side_effects = AsyncMock()
    monkeypatch.setattr(crud, "_current_catgirl_switch_lock", asyncio.Lock())
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(crud, "get_session_manager", lambda: {})
    monkeypatch.setattr(
        crud,
        "_apply_current_catgirl_switch_side_effects",
        side_effects,
    )

    result = await crud.restore_managed_overlay_original(
        _DummyRequest(_restore_payload())
    )

    assert result == {
        "success": True,
        "switched": False,
        "preserved_user_choice": True,
        "current_catgirl": THIRD_NAME,
        "original_name": ORIGINAL_NAME,
        "overlay_name": OVERLAY_NAME,
    }
    assert config_manager.save_calls == 0
    assert config_manager.characters["当前猫娘"] == THIRD_NAME
    side_effects.assert_not_awaited()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_restore_rejects_provenance_mismatch(monkeypatch):
    characters = _characters()
    characters["猫娘"][OVERLAY_NAME]["_reserved"]["auto_prompt_harness"][
        "original_name"
    ] = THIRD_NAME
    config_manager = _FakeConfigManager(characters)
    side_effects = AsyncMock()
    monkeypatch.setattr(crud, "_current_catgirl_switch_lock", asyncio.Lock())
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(crud, "get_session_manager", lambda: {})
    monkeypatch.setattr(
        crud,
        "_apply_current_catgirl_switch_side_effects",
        side_effects,
    )

    response = await crud.restore_managed_overlay_original(
        _DummyRequest(_restore_payload())
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 409
    assert _response_payload(response)["code"] == (
        "MANAGED_OVERLAY_PROVENANCE_MISMATCH"
    )
    assert config_manager.save_calls == 0
    side_effects.assert_not_awaited()


class _CoordinatedConfigManager:
    def __init__(self, characters):
        self.characters = copy.deepcopy(characters)
        self.first_load_started = asyncio.Event()
        self.allow_first_load = asyncio.Event()
        self.load_calls = 0
        self.save_calls = 0

    async def aload_characters(self):
        self.load_calls += 1
        if self.load_calls == 1:
            self.first_load_started.set()
            await self.allow_first_load.wait()
        return copy.deepcopy(self.characters)

    async def asave_characters(self, characters):
        self.save_calls += 1
        self.characters = copy.deepcopy(characters)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_normal_switch_serializes_before_restore_and_user_choice_wins(
    monkeypatch,
):
    config_manager = _CoordinatedConfigManager(_characters())
    side_effects = AsyncMock()
    monkeypatch.setattr(crud, "_current_catgirl_switch_lock", asyncio.Lock())
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(crud, "get_session_manager", lambda: {})
    monkeypatch.setattr(
        crud,
        "_apply_current_catgirl_switch_side_effects",
        side_effects,
    )

    normal_switch = asyncio.create_task(
        crud.set_current_catgirl(_DummyRequest({"catgirl_name": THIRD_NAME}))
    )
    await config_manager.first_load_started.wait()
    restore = asyncio.create_task(
        crud.restore_managed_overlay_original(_DummyRequest(_restore_payload()))
    )
    await asyncio.sleep(0)
    config_manager.allow_first_load.set()

    normal_result, restore_result = await asyncio.gather(normal_switch, restore)

    assert normal_result == {"success": True}
    assert restore_result["success"] is True
    assert restore_result["switched"] is False
    assert restore_result["preserved_user_choice"] is True
    assert restore_result["current_catgirl"] == THIRD_NAME
    assert config_manager.characters["当前猫娘"] == THIRD_NAME
    assert config_manager.load_calls == 2
    assert config_manager.save_calls == 1
    side_effects.assert_awaited_once_with(OVERLAY_NAME, THIRD_NAME, {})


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_refresh_rejects_stale_prompt_fingerprint(monkeypatch):
    characters = _characters("已经由其他写入者修改")
    config_manager = _FakeConfigManager(characters)
    refresh = AsyncMock()
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    monkeypatch.setattr(
        crud,
        "_refresh_catgirl_context_after_profile_change",
        refresh,
    )

    response = await crud.refresh_managed_overlay_prompt(
        _DummyRequest(_request_payload("旧提示词"))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 409
    assert _response_payload(response) == {
        "success": False,
        "code": "MANAGED_OVERLAY_PROMPT_MISMATCH",
        "error": "system_prompt 已变化，拒绝刷新过期版本",
    }
    refresh.assert_not_awaited()
    assert config_manager.save_calls == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_delete_verifies_and_reuses_host_delete_transaction(
    monkeypatch,
    tmp_path,
):
    characters = _characters()
    characters["当前猫娘"] = THIRD_NAME
    overlay = copy.deepcopy(characters["猫娘"][OVERLAY_NAME])
    config_manager = _FakeConfigManager(characters, allow_save=True)
    effects = _install_delete_runtime(monkeypatch, config_manager, tmp_path)

    result = await crud.delete_managed_overlay(
        _DummyRequest(_delete_payload(overlay))
    )

    assert result == {
        "success": True,
        "memory_server_reloaded": True,
    }
    assert OVERLAY_NAME not in config_manager.characters["猫娘"]
    assert config_manager.characters["当前猫娘"] == THIRD_NAME
    assert config_manager.load_calls == 1
    assert config_manager.save_calls == 1
    effects["release"].assert_awaited_once()
    effects["remove_one"].assert_awaited_once_with(OVERLAY_NAME)
    effects["notify_reload"].assert_awaited_once()
    effects["remove_pending"].assert_awaited_once()
    effects["delete_storage"].assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_delete_rejects_same_name_replacement_by_full_fingerprint(
    monkeypatch,
    tmp_path,
):
    characters = _characters()
    characters["当前猫娘"] = THIRD_NAME
    original_overlay = copy.deepcopy(characters["猫娘"][OVERLAY_NAME])
    replacement = copy.deepcopy(original_overlay)
    replacement["昵称"] = "用户刚替换的同名角色"
    characters["猫娘"][OVERLAY_NAME] = replacement
    snapshot = copy.deepcopy(characters)
    config_manager = _FakeConfigManager(characters)
    effects = _install_delete_runtime(monkeypatch, config_manager, tmp_path)

    response = await crud.delete_managed_overlay(
        _DummyRequest(_delete_payload(original_overlay))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 409
    assert _response_payload(response) == {
        "success": False,
        "code": "MANAGED_OVERLAY_CARD_MISMATCH",
        "error": "角色卡内容已变化，拒绝删除过期版本",
    }
    assert config_manager.characters == snapshot
    assert config_manager.save_calls == 0
    effects["release"].assert_not_awaited()
    effects["delete_storage"].assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_delete_rejects_current_card_without_side_effects(
    monkeypatch,
    tmp_path,
):
    characters = _characters()
    overlay = copy.deepcopy(characters["猫娘"][OVERLAY_NAME])
    snapshot = copy.deepcopy(characters)
    config_manager = _FakeConfigManager(characters)
    effects = _install_delete_runtime(monkeypatch, config_manager, tmp_path)

    response = await crud.delete_managed_overlay(
        _DummyRequest(_delete_payload(overlay))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 409
    assert _response_payload(response) == {
        "success": False,
        "code": "MANAGED_OVERLAY_CURRENT_CHARACTER",
        "error": "自适应副本当前正在使用，未执行删除",
    }
    assert config_manager.characters == snapshot
    assert config_manager.save_calls == 0
    effects["release"].assert_not_awaited()
    effects["delete_storage"].assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_managed_overlay_delete_rejects_provenance_before_side_effects(
    monkeypatch,
    tmp_path,
):
    characters = _characters()
    characters["当前猫娘"] = THIRD_NAME
    overlay = characters["猫娘"][OVERLAY_NAME]
    overlay["_reserved"]["auto_prompt_harness"]["kind"] = "unmanaged"
    snapshot = copy.deepcopy(characters)
    config_manager = _FakeConfigManager(characters)
    effects = _install_delete_runtime(monkeypatch, config_manager, tmp_path)

    response = await crud.delete_managed_overlay(
        _DummyRequest(_delete_payload(overlay))
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 409
    assert _response_payload(response) == {
        "success": False,
        "code": "MANAGED_OVERLAY_PROVENANCE_MISMATCH",
        "error": "角色卡不是该绑定拥有的自适应副本",
    }
    assert config_manager.characters == snapshot
    assert config_manager.save_calls == 0
    effects["release"].assert_not_awaited()
    effects["delete_storage"].assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload_update", "expected_code"),
    [
        ({"unexpected": True}, "MANAGED_OVERLAY_INVALID_REQUEST"),
        ({"plugin_id": "another_plugin"}, "MANAGED_OVERLAY_INVALID_PLUGIN"),
        (
            {"expected_card_fingerprint": "not-a-sha256"},
            "MANAGED_OVERLAY_INVALID_FINGERPRINT",
        ),
    ],
)
async def test_managed_overlay_delete_rejects_invalid_request_fields(
    monkeypatch,
    payload_update,
    expected_code,
):
    characters = _characters()
    overlay = characters["猫娘"][OVERLAY_NAME]
    config_manager = _FakeConfigManager(characters)
    monkeypatch.setattr(crud, "get_config_manager", lambda: config_manager)
    payload = _delete_payload(overlay)
    payload.update(payload_update)

    response = await crud.delete_managed_overlay(_DummyRequest(payload))

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert _response_payload(response)["code"] == expected_code
    assert config_manager.load_calls == 0
    assert config_manager.save_calls == 0
