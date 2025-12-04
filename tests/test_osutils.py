from simple_proxy.utils import from_cwd, submit_daemon_thread
from functools import partial
import time
import logging
import threading


class TestOS:

    def test_os(self):
        print("test os")
        pass


def test_from_cwd():
    ts_str = str(int(time.time()))
    test_path = from_cwd('test_dir', ts_str, 'test_file.txt')
    assert test_path.exists() is False  # File should not exist yet
    assert test_path.parent.exists() is True  # Parent directory should be created


def test_submit_daemon_thread(caplog):
    result = []
    logger = logging.getLogger(__name__)

    def sample_function(x, y):
        time.sleep(0.1)
        result.append(x + y)
        logger.error(
            "[%s] Sample function executed with result: %d",
            threading.current_thread().name,
            x + y
        )

    thread = submit_daemon_thread(sample_function, 2, 3)
    thread.join(timeout=1)
    assert thread.is_alive() is False  # Thread should have finished
    assert result == [5]  # Result should contain the sum of 2 and 3
    assert 'sample_function-daemon-' in caplog.text

    # Test with partial function
    caplog.clear()
    sample_function_partial = submit_daemon_thread(partial(sample_function, 4), 5)
    sample_function_partial.join(timeout=1)
    assert sample_function_partial.is_alive() is False  # Thread should have finished
    assert result == [5, 9]  # Result should contain the sum of 4 and 5
    assert 'sample_function-daemon-' in caplog.text
