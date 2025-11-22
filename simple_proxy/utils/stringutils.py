import random
import re
from .logutils import _get_logger

_TIME_DURATION_UNITS = (
    ('W', 60 * 60 * 24 * 7 * 1000),
    ('D', 60 * 60 * 24 * 1000),
    ('H', 60 * 60 * 1000),
    ('M', 60 * 1000),
    ('S', 1 * 1000),
    ('MS', 1)
)


def random_sentence() -> str:
    nouns = ("puppy", "car", "rabbit", "girl", "monkey")
    verbs = ("runs", "hits", "jumps", "drives", "barfs")
    adv = ("crazily.", "dutifully.", "foolishly.", "merrily.", "occasionally.")
    return nouns[random.randrange(0, 5)] + ' ' + \
        verbs[random.randrange(0, 5)] + ' ' + \
        adv[random.randrange(0, 5)] + '\n'


def _format_bytes(size: float, scale: int = 1) -> tuple[float, str]:
    power = 2**10
    n = 0
    power_labels = {0 : 'B', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        size = round(size, scale)
        n += 1
    if size == int(size):
        size = int(size)
    return size, power_labels[n]


def pretty_bytes(size: float) -> str:
    v, unit = _format_bytes(size)
    return f"{v}{unit}"


def pretty_speed(speed: float) -> str:
    return pretty_bytes(speed) + '/s'


def pattern_to_regex(pattern: str) -> str:
    regex_pattern = re.escape(pattern)
    regex_pattern = regex_pattern.replace(r'\*', r'.*')
    return regex_pattern


def pretty_duration(seconds: float) -> str:
    if seconds < 0.0001:
        return '0S'
    parts = []
    milliseconds = int(seconds * 1000)
    for unit, div in _TIME_DURATION_UNITS:
        amount, milliseconds = divmod(int(milliseconds), div)
        if amount > 0:
            parts.append('{}{}'.format(amount, unit))
    return ','.join(parts)

def check_ip_patterns(patterns: list[str], s: str) -> bool:
    for pattern in patterns:
        if re.search(pattern, s):
            _get_logger().debug(f"pattern {pattern} matched {s}")
            return True
    return False
