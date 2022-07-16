from datetime import datetime
from hashlib import md5

TIPS = [
    "Don't eat yellow snow",
    "With medium power comes medium responsibility"
]


def get_tip_of_the_day() -> str:
    day_since_epoch = (datetime.utcnow() - datetime(1970, 1, 1)).days
    hash_of_the_day = md5(day_since_epoch.to_bytes(8, 'big', )).hexdigest()
    tip_chosen = int(hash_of_the_day, 16) % len(TIPS)
    return TIPS[tip_chosen]

