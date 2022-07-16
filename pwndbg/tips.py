from random import choice

TIPS = [
    "Don't eat yellow snow",
    "With medium power comes medium responsibility"
]


def get_tip_of_the_day() -> str:
    return choice(TIPS)
