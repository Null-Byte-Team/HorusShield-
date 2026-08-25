"""
HorusShield Horus Assistant
━━━━━━━━━━━━━━━━━━━━━━━━━━
Wraps AdvancedHorusAssistant — provides backwards-compatible .ask() interface.
"""
from ai.conversation_engine import AdvancedHorusAssistant
from utils.logger import get_logger

logger = get_logger("horus_assistant", "horus")


class HorusAssistant:
    def __init__(self):
        self.engine = AdvancedHorusAssistant()
        logger.info("HorusAssistant ready")

    def ask(self, query: str, language: str = 'en', user_id: str = 'default') -> str:
        """Returns response string (backwards-compatible)."""
        resp, _ = self.ask_with_engine(query, language=language, user_id=user_id)
        return resp

    def ask_with_engine(self, query: str, language: str = 'en', user_id: str = 'default'):
        """Returns (response_str, engine_name)."""
        logger.info(f"Query [{language}] user={user_id}: {query[:60]}")
        try:
            return self.engine.ask_with_engine(query, user_id=user_id, language=language)
        except Exception as e:
            logger.error(f"Horus error: {e}")
            msg = ("عذراً، حدث خطأ مؤقت 🔧 حاول مرة أخرى"
                   if language == 'ar' else
                   "I encountered an error 🔧 Please try again")
            return msg, "rule_general"

    def get_history(self, user_id: str = 'default'):
        return self.engine.get_conversation_history(user_id)

    def clear_history(self, user_id: str = 'default'):
        return self.engine.clear_conversation(user_id)
