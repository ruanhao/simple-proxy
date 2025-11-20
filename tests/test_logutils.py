from simple_proxy.utils import setup_logging, pfatal, pstderr, enable_stderr, sneaky
import logging
import pytest

logger = logging.getLogger(__name__)

def test_setup_logging_case_without_logfile(mocker):
    basicConfig_mocker = mocker.patch('simple_proxy.utils.logutils.logging.basicConfig')  # noqa
    setup_logging(None)
    _, kwargs = basicConfig_mocker.call_args
    assert 'handlers' in kwargs
    assert len(kwargs['handlers']) == 1
    assert isinstance(kwargs['handlers'][0], logging.StreamHandler)


def test_setup_logging_case_with_logfile(mocker, tmp_path):
    basicConfig_mocker = mocker.patch('simple_proxy.utils.logutils.logging.basicConfig')  # noqa
    log_file = tmp_path / "test.log"
    setup_logging(log_file, logging.DEBUG)
    _, kwargs = basicConfig_mocker.call_args
    assert 'handlers' in kwargs
    assert len(kwargs['handlers']) == 1
    assert isinstance(kwargs['handlers'][0], logging.handlers.RotatingFileHandler)  # noqa
    assert kwargs['level'] == logging.DEBUG


def test_pstderr():
    from simple_proxy.utils import logutils
    logutils._stderr = True
    pstderr("test message")


def test_pfatal():
    with pytest.raises(SystemExit):
        pfatal("fatal error message")


def test_enable_stderr():
    from simple_proxy.utils import logutils
    logutils._stderr = False
    enable_stderr()
    assert logutils._stderr is True


def test_sneaky(caplog):

    @sneaky()
    def __dummy_function(x, b, y=2, z=None):
        logger.info("Inside dummy function, x: %s, b: %s, y: %s", x, b, y)
        raise ValueError("An error occurred in dummy function")

    __dummy_function(1, b'abc', y=3, z=b'abc')  # Should not raise an exception
    assert "sneaky call: __dummy_function(1, <3 bytes>, y=3, z=<3 bytes>)" in caplog.text
