from simple_proxy.utils import setup_logging, pfatal, pstderr, enable_stderr
import logging
import pytest


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
