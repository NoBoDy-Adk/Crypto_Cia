from cia import main
from unittest.mock import patch

def run_test(key, text):
    print(f"\n===== TEST: {text} =====")

    with patch("builtins.input", side_effect=[str(key), text]):
        main()


# ==============================
# TEST CASES
# ==============================

tests = [
    (9, "hello 123"),
    (7, "hello123"),
    (5, "HELLO"),
    (11, "@hello!"),
    (3, ""),
]

for key, text in tests:
    run_test(key, text)