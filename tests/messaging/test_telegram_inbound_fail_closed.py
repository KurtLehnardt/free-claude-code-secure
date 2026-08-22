"""Regression tests: Telegram inbound authorization must be fail-CLOSED.

Covers the fix for the HIGH finding where an unset ALLOWED_TELEGRAM_USER_ID
caused telegram_inbound.py to accept messages from *any* Telegram user
(fail-open), letting an unauthenticated attacker drive the managed Claude
Code subprocess. The gate must now mirror Discord's fail-closed semantics:
no allowlist configured => reject everything.
"""

from unittest.mock import MagicMock

import pytest

from free_claude_code.messaging.models import IncomingMessage
from free_claude_code.messaging.platforms.telegram_inbound import (
    telegram_text_message_from_update,
    telegram_voice_request_from_update,
)
from free_claude_code.messaging.platforms.voice_flow import VoiceNoteRequest


def _text_update(*, user_id: int = 12345, chat_id: int = 6789) -> MagicMock:
    update = MagicMock()
    update.message.text = "run rm -rf /"
    update.message.message_id = 1
    update.message.reply_to_message = None
    update.message.message_thread_id = None
    update.effective_user.id = user_id
    update.effective_chat.id = chat_id
    return update


def _voice_update(*, user_id: int = 12345, chat_id: int = 6789) -> MagicMock:
    update = MagicMock()
    update.message.voice.mime_type = "audio/ogg"
    update.message.voice.file_id = "file-1"
    update.message.message_id = 2
    update.message.reply_to_message = None
    update.message.message_thread_id = None
    update.effective_user.id = user_id
    update.effective_chat.id = chat_id
    return update


class TestTextMessageFailClosed:
    def test_no_allowlist_configured_rejects_any_user(self):
        """No ALLOWED_TELEGRAM_USER_ID configured => reject, not accept."""
        update = _text_update(user_id=99999)

        result = telegram_text_message_from_update(
            update,
            allowed_user_id=None,
            log_raw_messaging_content=False,
        )

        assert result is None

    def test_empty_string_allowlist_rejects_any_user(self):
        """An empty-string allowlist is falsy and must also fail closed."""
        update = _text_update(user_id=99999)

        result = telegram_text_message_from_update(
            update,
            allowed_user_id="",
            log_raw_messaging_content=False,
        )

        assert result is None

    def test_no_allowlist_configured_logs_disabled_warning(self, caplog):
        update = _text_update(user_id=99999)

        telegram_text_message_from_update(
            update,
            allowed_user_id=None,
            log_raw_messaging_content=False,
        )

        assert "ALLOWED_TELEGRAM_USER_ID is not set" in caplog.text

    def test_mismatched_user_rejected_with_unauthorized_warning(self, caplog):
        update = _text_update(user_id=99999)

        result = telegram_text_message_from_update(
            update,
            allowed_user_id="12345",
            log_raw_messaging_content=False,
        )

        assert result is None
        assert "Unauthorized access attempt" in caplog.text

    def test_matching_user_is_accepted(self):
        update = _text_update(user_id=12345)

        result = telegram_text_message_from_update(
            update,
            allowed_user_id="12345",
            log_raw_messaging_content=False,
        )

        assert isinstance(result, IncomingMessage)
        assert result.user_id == "12345"
        assert result.text == "run rm -rf /"

    def test_allowlist_value_is_whitespace_trimmed(self):
        """Matches existing str(allowed_user_id).strip() comparison semantics."""
        update = _text_update(user_id=12345)

        result = telegram_text_message_from_update(
            update,
            allowed_user_id=" 12345 ",
            log_raw_messaging_content=False,
        )

        assert isinstance(result, IncomingMessage)


class TestVoiceMessageFailClosed:
    def test_no_allowlist_configured_rejects_any_user(self):
        update = _voice_update(user_id=99999)

        result = telegram_voice_request_from_update(
            update,
            MagicMock(),
            allowed_user_id=None,
        )

        assert result is None

    def test_no_allowlist_configured_logs_disabled_warning(self, caplog):
        update = _voice_update(user_id=99999)

        telegram_voice_request_from_update(
            update,
            MagicMock(),
            allowed_user_id=None,
        )

        assert "ALLOWED_TELEGRAM_USER_ID is not set" in caplog.text

    def test_mismatched_user_rejected_with_unauthorized_warning(self, caplog):
        update = _voice_update(user_id=99999)

        result = telegram_voice_request_from_update(
            update,
            MagicMock(),
            allowed_user_id="12345",
        )

        assert result is None
        assert "Unauthorized voice access attempt" in caplog.text

    def test_matching_user_is_accepted(self):
        update = _voice_update(user_id=12345)

        result = telegram_voice_request_from_update(
            update,
            MagicMock(),
            allowed_user_id="12345",
        )

        assert isinstance(result, VoiceNoteRequest)
        assert result.user_id == "12345"


@pytest.mark.parametrize("allowed_user_id", [None, "", "   "])
def test_never_accepts_when_allowlist_effectively_unset(allowed_user_id):
    """Belt-and-suspenders: any falsy-after-strip allowlist value fails closed."""
    update = _text_update(user_id=1)

    result = telegram_text_message_from_update(
        update,
        allowed_user_id=allowed_user_id,
        log_raw_messaging_content=False,
    )

    assert result is None
