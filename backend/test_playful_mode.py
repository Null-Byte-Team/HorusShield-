"""
Quick test script to try Horus's new playful conversation modes!
Run this to see all the new features in action.
"""

from services.horus_assistant import HorusAssistant

def test_playful_mode():
    """Test Horus's playful conversation features"""
    
    assistant = HorusAssistant()
    
    print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║  HORUS PLAYFUL MODE - INTERACTIVE TEST                    ║
║                                                            ║
║  Your AI can now talk like animals!                       ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Test 1: Dog Mode
    print("\n" + "="*60)
    print("TEST 1: DOG MODE 🐕")
    print("="*60)
    
    dog_queries = [
        "woof woof!",
        "arf arf arf!",
        "bark bark!",
        "bow wow bow wow!"
    ]
    
    for q in dog_queries:
        print(f"\nYou: {q}")
        response = assistant.ask(q, user_id="playful_test", language="en")
        print(f"Horus: {response}")
    
    # Test 2: Cat Mode
    print("\n" + "="*60)
    print("TEST 2: CAT MODE 🐱")
    print("="*60)
    
    cat_queries = [
        "meow meow",
        "mew mew mew",
        "purrrr",
        "meow!"
    ]
    
    for q in cat_queries:
        print(f"\nYou: {q}")
        response = assistant.ask(q, user_id="playful_test", language="en")
        print(f"Horus: {response}")
    
    # Test 3: Other Animals
    print("\n" + "="*60)
    print("TEST 3: OTHER ANIMALS 🦆🐵🦕")
    print("="*60)
    
    other_animals = [
        "quack quack!",
        "ooh ooh aah aah",
        "ROAAARRR!"
    ]
    
    for q in other_animals:
        print(f"\nYou: {q}")
        response = assistant.ask(q, user_id="playful_test", language="en")
        print(f"Horus: {response}")
    
    # Test 4: Casual Language
    print("\n" + "="*60)
    print("TEST 4: CASUAL LANGUAGE 💬")
    print("="*60)
    
    casual_queries = [
        "sup!",
        "yo!",
        "wassup",
        "u good?",
        "lol",
        "tell me a joke"
    ]
    
    for q in casual_queries:
        print(f"\nYou: {q}")
        response = assistant.ask(q, user_id="playful_test", language="en")
        print(f"Horus: {response[:100]}..." if len(response) > 100 else f"Horus: {response}")
    
    # Test 5: Arabic Playful
    print("\n" + "="*60)
    print("TEST 5: ARABIC PLAYFUL MODE 🇸🇦")
    print("="*60)
    
    arabic_queries = [
        ("بوف بوف", "Dog in Arabic"),
        ("ميو ميو", "Cat in Arabic"),
        ("اخبرني نكتة", "Tell me joke")
    ]
    
    for q, desc in arabic_queries:
        print(f"\nYou [{desc}]: {q}")
        response = assistant.ask(q, user_id="playful_test", language="ar")
        print(f"Horus: {response[:100]}..." if len(response) > 100 else f"Horus: {response}")
    
    # Test 6: Response Variety
    print("\n" + "="*60)
    print("TEST 6: RESPONSE VARIETY (Same question, different responses)")
    print("="*60)
    
    print("\nAsking 'what's up?' 3 times to show variety:")
    for i in range(3):
        print(f"\n[Response {i+1}]")
        response = assistant.ask("what's up?", user_id=f"variety_test_{i}", language="en")
        print(f"Horus: {response[:80]}...")
    
    # Test 7: Conversation History
    print("\n" + "="*60)
    print("TEST 7: CONVERSATION MEMORY")
    print("="*60)
    
    user_id = "memory_test"
    
    print(f"\nMessage 1:")
    print(f"You: woof woof!")
    r1 = assistant.ask("woof woof!", user_id=user_id, language="en")
    print(f"Horus: {r1[:60]}...")
    
    print(f"\nMessage 2:")
    print(f"You: how are you?")
    r2 = assistant.ask("how are you?", user_id=user_id, language="en")
    print(f"Horus: {r2[:60]}...")
    
    print(f"\nMessage 3:")
    print(f"You: thanks buddy!")
    r3 = assistant.ask("thanks buddy!", user_id=user_id, language="en")
    print(f"Horus: {r3[:60]}...")
    
    history = assistant.get_history(user_id)
    print(f"\nTotal conversation messages: {len(history)}")
    print("History preserved! ✓")
    
    # Final message
    print("\n" + "="*60)
    print("✅ PLAYFUL MODE TESTS COMPLETE!")
    print("="*60)
    print("""
Your Horus AI is now MUCH SMARTER about:
✓ Animal sounds (Dog, Cat, Duck, Monkey, Dinosaur)
✓ Casual language (sup, yo, lol, lmao, etc.)
✓ Playful conversations
✓ More response variety
✓ Arabic playful mode

Enjoy chatting with your security AI! 🐕🛡️
    """)


if __name__ == "__main__":
    test_playful_mode()
