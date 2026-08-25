"""
HorusShield AI Configuration
Customize the Horus Assistant behavior, personality, and capabilities
"""

import json
import os
from utils.logger import get_logger

logger = get_logger("ai_config", "config")

class AIConfig:
    """
    Central configuration for Horus Assistant
    Easy to modify behavior without touching core code
    """
    
    # Default configuration
    DEFAULT_CONFIG = {
        # ========== PERSONALITY ==========
        "personality": {
            "name": "Horus",
            "emoji": "👁",
            "tone": "professional_helpful",  # professional_helpful, friendly, technical, casual
            "response_style": "detailed",  # brief, detailed, interactive
        },
        
        # ========== CONVERSATION BEHAVIOR ==========
        "conversation": {
            "enable_memory": True,
            "max_history": 20,
            "context_awareness": True,
            "remember_topics": True,
        },
        
        # ========== AI PARAMETERS ==========
        "ai_model": {
            "type": "hybrid",  # hybrid (security + general), security_only, general_only
            "temperature": 0.7,  # 0-1, higher = more creative/random
            "enable_reasoning": True,
            "reasoning_depth": "medium",  # shallow, medium, deep
            "creativity_level": 0.6,  # 0-1, affects response variation
        },
        
        # ========== SECURITY RESPONSE BEHAVIOR ==========
        "security": {
            "threat_level_display": True,
            "real_time_stats": True,
            "recommendations_enabled": True,
            "auto_explanations": True,  # Explain what threats mean
            "security_tone": "serious",  # serious, reassuring, technical
        },
        
        # ========== GENERAL CONVERSATION ==========
        "general_conversation": {
            "enable_jokes": True,
            "enable_small_talk": True,
            "enable_learning": True,  # Can learn from interactions
            "personality_consistency": True,
        },
        
        # ========== LANGUAGES ==========
        "languages": {
            "default": "en",
            "supported": ["en", "ar"],
            "auto_detect": False,
        },
        
        # ========== RESPONSE GENERATION ==========
        "responses": {
            "use_emojis": True,
            "formatting": "markdown",  # markdown, plain, html
            "max_response_length": 500,  # characters
            "include_timestamps": False,
            "include_confidence_scores": False,
        },
        
        # ========== ADVANCED FEATURES ==========
        "advanced": {
            "enable_sentiment_analysis": True,
            "user_emotion_tracking": True,
            "context_learning": True,
            "threat_prediction": True,
            "anomaly_detection": True,
        },
    }
    
    def __init__(self, config_file=None):
        self.config_file = config_file or "config/ai_config.json"
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file or use defaults"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    logger.info(f"Loaded AI config from {self.config_file}")
                    return loaded_config
            else:
                logger.info("Using default AI configuration")
                return self.DEFAULT_CONFIG.copy()
        except Exception as e:
            logger.error(f"Error loading config: {e}, using defaults")
            return self.DEFAULT_CONFIG.copy()
    
    def save_config(self, config=None):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            config_to_save = config or self.config
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_to_save, f, indent=2, ensure_ascii=False)
            logger.info(f"AI configuration saved to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def get(self, key_path, default=None):
        """
        Get config value using dot notation
        Example: config.get("personality.tone")
        """
        keys = key_path.split('.')
        value = self.config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path, value):
        """
        Set config value using dot notation
        Example: config.set("personality.tone", "friendly")
        """
        keys = key_path.split('.')
        config = self.config
        try:
            for key in keys[:-1]:
                if key not in config:
                    config[key] = {}
                config = config[key]
            config[keys[-1]] = value
            logger.info(f"Set {key_path} = {value}")
            return True
        except Exception as e:
            logger.error(f"Error setting config: {e}")
            return False
    
    def reset_to_defaults(self):
        """Reset all configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        logger.warning("AI configuration reset to defaults")
        return True
    
    def get_full_config(self):
        """Get full configuration"""
        return self.config
    
    def update_config(self, updates):
        """Update configuration with a dictionary"""
        try:
            def deep_update(d, u):
                for k, v in u.items():
                    if isinstance(v, dict):
                        d[k] = deep_update(d.get(k, {}), v)
                    else:
                        d[k] = v
                return d
            
            self.config = deep_update(self.config, updates)
            logger.info("Configuration updated successfully")
            return True
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return False


# Singleton instance
_ai_config = None

def get_ai_config():
    """Get or create the AI configuration singleton"""
    global _ai_config
    if _ai_config is None:
        _ai_config = AIConfig()
    return _ai_config


# Example usage in conversation_engine.py:
"""
from ai.ai_config import get_ai_config

config_manager = get_ai_config()
tone = config_manager.get("personality.tone")
temperature = config_manager.get("ai_model.temperature")
enable_memory = config_manager.get("conversation.enable_memory")
"""
