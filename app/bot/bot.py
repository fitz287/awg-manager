import logging
from typing import Optional
from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from app.core.config import settings
from app.bot.handlers import router

logger = logging.getLogger(__name__)

bot: Optional[Bot] = None
dp: Optional[Dispatcher] = None

def init_bot() -> Optional[Bot]:
    global bot, dp
    token = settings.BOT_TOKEN.strip()
    if not token or token.startswith("1234567890:"):
        logger.warning("Telegram BOT_TOKEN is not configured in .env. Bot will remain idle.")
        return None

    try:
        bot = Bot(
            token=token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML)
        )
        dp = Dispatcher()
        dp.include_router(router)
        logger.info("Telegram Bot initialized successfully.")
        return bot
    except Exception as e:
        logger.error(f"Failed to initialize Telegram Bot: {e}")
        return None
