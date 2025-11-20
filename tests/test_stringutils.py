from simple_proxy.utils import (
    random_sentence, pretty_bytes, pretty_speed,
    pattern_to_regex,
    pretty_duration,
)


def test_random_string():
    sentence = random_sentence()
    assert isinstance(sentence, str)
    assert len(sentence) > 0
    words = sentence.split()
    assert len(words) == 3


def test_pretty_bytes():
    assert pretty_bytes(1) == '1B'
    assert pretty_bytes(1024) == '1024B'
    assert pretty_bytes(1025 * 1024) == '1M'
    assert pretty_bytes(60 * 1024 * 1024) == '60M'

    assert pretty_speed(1) == '1B/s'
    assert pretty_speed(1024) == '1024B/s'
    assert pretty_speed(1025 * 1024) == '1M/s'
    assert pretty_speed(60 * 1024 * 1024) == '60M/s'


def test_pattern_to_regex():
    assert pattern_to_regex('*.example.com') == r'.*\.example\.com'
    assert pattern_to_regex('example.com') == r'example\.com'
    assert pattern_to_regex('example.*.com') == r'example\..*\.com'
    assert pattern_to_regex('example.com.*') == r'example\.com\..*'


def test_pretty_duration():
    assert pretty_duration(60) == '1M'
    assert pretty_duration(3661) == '1H,1M,1S'
    assert pretty_duration(0) == '0S'
    assert pretty_duration(0.5) == '500MS'
    assert pretty_duration(90061.5) == '1D,1H,1M,1S,500MS'
