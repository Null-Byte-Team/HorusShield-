"""
EXAMPLE: Using & Customizing HorusShield AI Assistant
=====================================================

This script demonstrates:
- How to interact with Horus
- How to customize behavior
- How to manage conversation history
- How to use different configuration options
"""

from services.horus_assistant import HorusAssistant
from ai.ai_config import get_ai_config
from utils.logger import get_logger

logger = get_logger("horus_examples", "examples")

def example_1_basic_conversation():
    """EXAMPLE 1: Basic Conversation with Horus"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Conversation")
    print("="*60)
    
    assistant = HorusAssistant()
    
    # English
    response = assistant.ask("What's my security score?", language="en", user_id="user1")
    print(f"Q: What's my security score?\nA: {response}\n")
    
    # Arabic
    response = assistant.ask("كيف هي درجة الأمان؟", language="ar", user_id="user1")
    print(f"Q: كيف هي درجة الأمان؟\nA: {response}\n")


def example_2_general_conversation():
    """EXAMPLE 2: General Conversation (Non-Security Topics)"""
    print("\n" + "="*60)
    print("EXAMPLE 2: General Conversation")
    print("="*60)
    
    assistant = HorusAssistant()
    
    # Greeting
    response = assistant.ask("Hello! How are you?", user_id="user2")
    print(f"Q: Hello! How are you?\nA: {response}\n")
    
    # Joke request
    response = assistant.ask("Tell me a joke", user_id="user2")
    print(f"Q: Tell me a joke\nA: {response}\n")
    
    # Thank you
    response = assistant.ask("Thanks for your help!", user_id="user2")
    print(f"Q: Thanks for your help!\nA: {response}\n")


def example_3_conversation_memory():
    """EXAMPLE 3: Conversation Memory - Context Awareness"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Conversation Memory & Context")
    print("="*60)
    
    assistant = HorusAssistant()
    user_id = "user3"
    
    # First message
    q1 = "Hello Horus!"
    r1 = assistant.ask(q1, user_id=user_id)
    print(f"Q1: {q1}\nA1: {r1}\n")
    
    # Second message (related)
    q2 = "I'm worried about my network security"
    r2 = assistant.ask(q2, user_id=user_id)
    print(f"Q2: {q2}\nA2: {r2}\n")
    
    # Third message (build on previous context)
    q3 = "Should I activate emergency mode?"
    r3 = assistant.ask(q3, user_id=user_id)
    print(f"Q3: {q3}\nA3: {r3}\n")
    
    # Get conversation history
    history = assistant.get_history(user_id)
    print(f"Total messages in history: {len(history)}\n")


def example_4_customize_personality():
    """EXAMPLE 4: Customize AI Personality"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Customize Personality")
    print("="*60)
    
    config = get_ai_config()
    
    print("Current personality settings:")
    print(f"  Tone: {config.get('personality.tone')}")
    print(f"  Emoji: {config.get('personality.emoji')}")
    print(f"  Response Style: {config.get('personality.response_style')}\n")
    
    # Change personality to friendly
    config.set("personality.tone", "friendly")
    config.set("general_conversation.enable_jokes", True)
    
    print("After changing to 'friendly' mode:")
    print(f"  Tone: {config.get('personality.tone')}")
    print(f"  Jokes Enabled: {config.get('general_conversation.enable_jokes')}\n")
    
    # Reset to defaults
    config.reset_to_defaults()
    print("Reset to defaults ✓\n")


def example_5_customize_ai_model():
    """EXAMPLE 5: Customize AI Model Behavior"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Customize AI Model")
    print("="*60)
    
    config = get_ai_config()
    
    print("Current AI model settings:")
    print(f"  Type: {config.get('ai_model.type')}")
    print(f"  Temperature: {config.get('ai_model.temperature')}")
    print(f"  Reasoning Depth: {config.get('ai_model.reasoning_depth')}\n")
    
    # Make AI more creative
    config.set("ai_model.temperature", 0.9)
    config.set("ai_model.reasoning_depth", "deep")
    
    print("After increasing creativity:")
    print(f"  Temperature: {config.get('ai_model.temperature')}")
    print(f"  Reasoning Depth: {config.get('ai_model.reasoning_depth')}\n")
    
    # Tip: Save configuration
    config.save_config()
    print("Configuration saved to file ✓\n")


def example_6_multilingual():
    """EXAMPLE 6: Multi-Language Support"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Multi-Language Support")
    print("="*60)
    
    assistant = HorusAssistant()
    
    # English
    print("ENGLISH:")
    r_en = assistant.ask("Show me your security status", language="en", user_id="multi_user")
    print(f"  {r_en}\n")
    
    # Arabic
    print("ARABIC:")
    r_ar = assistant.ask("أخبرني عن حالة الأمان", language="ar", user_id="multi_user")
    print(f"  {r_ar}\n")


def example_7_conversation_history():
    """EXAMPLE 7: Manage Conversation History"""
    print("\n" + "="*60)
    print("EXAMPLE 7: Conversation History Management")
    print("="*60)
    
    assistant = HorusAssistant()
    user_id = "history_user"
    
    # Build up conversation
    assistant.ask("Hi there!", user_id=user_id)
    assistant.ask("How secure is my network?", user_id=user_id)
    assistant.ask("What about threats?", user_id=user_id)
    
    # Get history
    history = assistant.get_history(user_id)
    print(f"Conversation History ({len(history)} messages):")
    for i, msg in enumerate(history):
        role = "You" if msg["role"] == "user" else "Horus"
        content = msg["content"][:60] + "..." if len(msg["content"]) > 60 else msg["content"]
        print(f"  {i+1}. [{role}] {content}")
    
    # Clear history
    print("\nClearing history...")
    assistant.clear_history(user_id)
    
    # Verify
    history_after = assistant.get_history(user_id)
    print(f"History after clear: {len(history_after)} messages ✓\n")


def example_8_security_vs_general():
    """EXAMPLE 8: Security vs General Topic Detection"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Security vs General Topics")
    print("="*60)
    
    assistant = HorusAssistant()
    
    security_questions = [
        "What DDoS attacks are happening?",
        "Show me the threat map",
        "Block that suspicious device"
    ]
    
    general_questions = [
        "What's 2+2?",
        "Tell me a funny story",
        "How's your day going?"
    ]
    
    print("SECURITY TOPICS:")
    for q in security_questions:
        r = assistant.ask(q, user_id="detector_user")
        print(f"  Q: {q}")
        print(f"  A: {r[:80]}...\n")
    
    print("GENERAL TOPICS:")
    for q in general_questions:
        r = assistant.ask(q, user_id="detector_user")
        print(f"  Q: {q}")
        print(f"  A: {r[:80]}...\n")


def example_9_get_configuration():
    """EXAMPLE 9: Get Full Configuration"""
    print("\n" + "="*60)
    print("EXAMPLE 9: Get AI Configuration")
    print("="*60)
    
    config = get_ai_config()
    full_config = config.get_full_config()
    
    print("Full Configuration Structure:")
    for section, settings in full_config.items():
        print(f"\n[{section.upper()}]")
        if isinstance(settings, dict):
            for key, value in settings.items():
                value_str = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                print(f"  {key}: {value_str}")
        else:
            print(f"  {settings}")


def example_10_batch_customization():
    """EXAMPLE 10: Batch Configuration Updates"""
    print("\n" + "="*60)
    print("EXAMPLE 10: Batch Configuration Updates")
    print("="*60)
    
    config = get_ai_config()
    
    # Apply multiple settings at once
    updates = {
        "personality": {
            "tone": "casual",
            "response_style": "interactive"
        },
        "ai_model": {
            "temperature": 0.85,
            "creativity_level": 0.8
        },
        "security": {
            "threat_level_display": True,
            "auto_explanations": True
        }
    }
    
    config.update_config(updates)
    
    print("Applied batch updates:")
    print(f"  Tone: {config.get('personality.tone')}")
    print(f"  Temperature: {config.get('ai_model.temperature')}")
    print(f"  Threat Display: {config.get('security.threat_level_display')}\n")


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     HorusShield AI Assistant - Usage Examples             ║
    ║                                                            ║
    ║  Choose which example to run:                            ║
    ║  1. Basic Conversation                                   ║
    ║  2. General Conversation (Non-Security)                 ║
    ║  3. Conversation Memory & Context                        ║
    ║  4. Customize Personality                                ║
    ║  5. Customize AI Model                                   ║
    ║  6. Multi-Language Support                               ║
    ║  7. Conversation History Management                      ║
    ║  8. Security vs General Topic Detection                  ║
    ║  9. Get Configuration                                    ║
    ║  10. Batch Configuration Updates                         ║
    ║  0. Run All Examples                                     ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    choice = input("Enter your choice (0-10): ").strip()
    
    examples = {
        "1": example_1_basic_conversation,
        "2": example_2_general_conversation,
        "3": example_3_conversation_memory,
        "4": example_4_customize_personality,
        "5": example_5_customize_ai_model,
        "6": example_6_multilingual,
        "7": example_7_conversation_history,
        "8": example_8_security_vs_general,
        "9": example_9_get_configuration,
        "10": example_10_batch_customization,
    }
    
    if choice == "0":
        for example_func in examples.values():
            try:
                example_func()
            except Exception as e:
                print(f"Error running example: {e}")
    elif choice in examples:
        try:
            examples[choice]()
        except Exception as e:
            logger.error(f"Error: {e}")
            print(f"Error: {e}")
    else:
        print("Invalid choice!")
    
    print("\n" + "="*60)
    print("Examples completed!")
    print("="*60)
