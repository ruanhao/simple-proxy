from simple_proxy.utils import (
    getsockname, getpeername,
    free_port,
    set_keepalive,
)


def test_getsockname(mocker):
    sock_mocker = mocker.MagicMock()

    assert "?" == getsockname(None)
    assert "?" == getsockname("")

    sock_mocker.getsockname.return_value = ("1.2.3.4", 8080)
    assert "1.2.3.4:8080" == getsockname(sock_mocker)

    sock_mocker.getsockname.side_effect = OSError()
    assert "!" == getsockname(sock_mocker)


def test_getpeername(mocker):
    sock_mocker = mocker.MagicMock()

    assert "?" == getpeername(None)
    assert "?" == getpeername("")

    sock_mocker.getpeername.return_value = ("1.2.3.4", 8080)
    assert "1.2.3.4:8080" == getpeername(sock_mocker)

    sock_mocker.getpeername.side_effect = OSError()
    assert "!" == getpeername(sock_mocker)


def test_free_port():
    port = free_port()
    assert 1024 < port < 65536


def test_set_keepalive_case_linux(mocker):
    sock_mocker = mocker.MagicMock()
    mocker.patch('simple_proxy.utils.netutils.platform.system', return_value='Linux')
    mocker.patch('simple_proxy.utils.netutils.socket')
    set_keepalive(sock_mocker)
    assert sock_mocker.setsockopt.call_count == 4


def test_set_keepalive_case_windows(mocker):
    sock_mocker = mocker.MagicMock()
    mocker.patch('simple_proxy.utils.netutils.platform.system', return_value='Windows')
    mocker.patch('simple_proxy.utils.netutils.socket')
    set_keepalive(sock_mocker)
    assert sock_mocker.ioctl.call_count == 1


def test_set_keepalive_case_osx(mocker):
    sock_mocker = mocker.MagicMock()
    mocker.patch('simple_proxy.utils.netutils.platform.system', return_value='Darwin')
    mocker.patch('simple_proxy.utils.netutils.socket')
    set_keepalive(sock_mocker)
    assert sock_mocker.setsockopt.call_count == 2
