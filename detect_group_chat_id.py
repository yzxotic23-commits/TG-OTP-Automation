from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


def project_root() -> Path:
    return Path(__file__).resolve().parent


logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_chat:
        return
    msg = update.effective_message
    if not msg:
        return
    chat = update.effective_chat
    user = update.effective_user
    who = (user.full_name if user else "-") if user else "-"
    username = f"@{user.username}" if user and user.username else "-"
    title = getattr(chat, "title", None) or "-"
    text = (
        "GROUP CHAT DETECTED\n"
        "-------------------\n"
        f"chat_id    : {chat.id}\n"
        f"chat_type  : {chat.type}\n"
        f"group_name : {title}\n"
        f"from_user  : {who}\n"
        f"username   : {username}"
    )
    logger.info("Detected chat_id=%s type=%s title=%s", chat.id, chat.type, title)
    await msg.reply_text(text)


def main() -> None:
    load_dotenv(project_root() / ".env")
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN is empty in .env")
        sys.exit(1)

    if sys.platform == "win32" and sys.version_info < (3, 14):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", cmd_start))
    logger.info("Detector active. Send /start from a group to see chat_id.")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()

