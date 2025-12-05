from simple_proxy.run import run_proxy
import pytest
from simple_proxy.handler.shell_channel_handler import ShellChannelHandler


def test_run_proxy_case_tls_mode_with_both_disguise_ip_and_server():
    with pytest.raises(SystemExit):
        run_proxy(
            tls=True,
            disguise_tls_ip='1.2.3.4',
            run_disguise_tls_server=True,
        )

    with pytest.raises(SystemExit):
        run_proxy(
            tls=False, ss=True,
            disguise_tls_ip='1.2.3.4',
            run_disguise_tls_server=True,
        )


def test_run_proxy_case_tcp_proxy(mocker):
    ServerBoostrapMocker = mocker.patch('simple_proxy.run.ServerBootstrap')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=True,
        content=True, to_file=True,
        tls=False, ss=False,
        key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=False,
        monitor_interval=3,
        disguise_tls_ip="1.2.3.4",
        disguise_tls_port=443,
        run_disguise_tls_server=False,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=2,
        white_list="1.2.3.4,5.6.7.8",
    )
    kwargs = ServerBoostrapMocker.call_args[1]
    assert kwargs['parant_group'].num == 1
    assert kwargs['child_group'].num == 2
    assert kwargs['certfile'] is None
    assert kwargs['keyfile'] is None
    assert kwargs['ssl_context_cb']

    proxy_channel_handler = kwargs['child_handler_initializer']()
    assert proxy_channel_handler._remote_host == "www.google.com"
    assert proxy_channel_handler._remote_port == 80
    assert proxy_channel_handler._tls is False
    assert proxy_channel_handler._content is True
    assert proxy_channel_handler._to_file is True
    assert proxy_channel_handler._disguise_tls_ip == "1.2.3.4"
    assert proxy_channel_handler._disguise_tls_port == 443
    assert len(proxy_channel_handler._white_list) == 2
    assert proxy_channel_handler._alpn is True
    assert proxy_channel_handler._read_delay_millis == 100
    assert proxy_channel_handler._write_delay_millis == 200
    assert proxy_channel_handler._client_eventloop_group.num == 1

    assert ServerBoostrapMocker.return_value.bind.call_args[1]['address'] == '0.0.0.0'
    assert ServerBoostrapMocker.return_value.bind.call_args[1]['port'] == 8081


def test_run_proxy_case_http_proxy(mocker):
    ServerBoostrapMocker = mocker.patch('simple_proxy.run.ServerBootstrap')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=True,
        content=True, to_file=True,
        tls=True, ss=True,
        key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=False,
        monitor_interval=3,
        disguise_tls_ip=None,
        disguise_tls_port=443,
        run_disguise_tls_server=False,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=4,
        http_proxy=True,
        proxy_transform=(('example.com', 80, 'transformed.com', 8080),),
        proxy_workers=2,
        proxy_username="cisco",
        proxy_password="juniper",
    )
    kwargs = ServerBoostrapMocker.call_args[1]
    assert kwargs['parant_group'].num == 1
    assert kwargs['child_group'].num == 4
    assert 'certfile' not in kwargs
    assert 'keyfile' not in kwargs
    assert 'ssl_context_cb' not in kwargs

    http_proxy_channel_handler = kwargs['child_handler_initializer']()
    assert http_proxy_channel_handler._client_eventloop_group.num == 2
    assert http_proxy_channel_handler._content is True
    assert http_proxy_channel_handler._to_file is True
    assert http_proxy_channel_handler._transform == (('example.com', 80, 'transformed.com', 8080),)
    assert http_proxy_channel_handler._proxy_username == "cisco"
    assert http_proxy_channel_handler._proxy_password == "juniper"


def test_run_proxy_case_socks5_proxy(mocker):
    ServerBoostrapMocker = mocker.patch('simple_proxy.run.ServerBootstrap')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=False,
        content=True, to_file=True,
        tls=True, ss=True,
        key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=False,
        monitor_interval=3,
        disguise_tls_ip=None,
        disguise_tls_port=443,
        run_disguise_tls_server=False,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=4,
        socks5_proxy=True,
        proxy_transform=(('example.com', 80, 'transformed.com', 8080),),
        proxy_workers=2,
        proxy_username="cisco",
        proxy_password="juniper",
    )
    kwargs = ServerBoostrapMocker.call_args[1]
    assert kwargs['parant_group'].num == 1
    assert kwargs['child_group'].num == 4
    assert 'certfile' not in kwargs
    assert 'keyfile' not in kwargs
    assert 'ssl_context_cb' not in kwargs

    socks5_proxy_channel_handler = kwargs['child_handler_initializer']()
    assert socks5_proxy_channel_handler._client_eventloop_group.num == 2
    assert socks5_proxy_channel_handler._content is True
    assert socks5_proxy_channel_handler._to_file is True
    assert socks5_proxy_channel_handler._transform == (('example.com', 80, 'transformed.com', 8080),)
    assert socks5_proxy_channel_handler._proxy_username == "cisco"
    assert socks5_proxy_channel_handler._proxy_password == "juniper"
    assert ServerBoostrapMocker.return_value.bind.call_args[1]['address'] == '127.0.0.2'
    assert ServerBoostrapMocker.return_value.bind.call_args[1]['port'] == 8081


def test_run_proxy_case_shell_proxy(mocker):
    ServerBoostrapMocker = mocker.patch('simple_proxy.run.ServerBootstrap')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=True,
        content=True, to_file=True,
        tls=True, ss=False,
        key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=False,
        monitor_interval=3,
        disguise_tls_ip=None,
        disguise_tls_port=443,
        run_disguise_tls_server=False,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=4,
        shell_proxy=True,
    )
    kwargs = ServerBoostrapMocker.call_args[1]
    assert kwargs['parant_group'].num == 1
    assert kwargs['child_group'].num == 4
    assert not kwargs['certfile']
    assert not kwargs['keyfile']
    assert 'ssl_context_cb' not in kwargs

    shell_channel_handler_cls = kwargs['child_handler_initializer']
    assert shell_channel_handler_cls == ShellChannelHandler


def test_run_proxy_case_echo_server(mocker):
    ServerBoostrapMocker = mocker.patch('simple_proxy.run.ServerBootstrap')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=True,
        content=True, to_file=True,
        tls=True, ss=True,
        # key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=False,
        monitor_interval=3,
        disguise_tls_ip=None,
        disguise_tls_port=443,
        run_disguise_tls_server=False,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=4,
        as_echo_server=True,
        proxy_workers=8,
    )
    kwargs = ServerBoostrapMocker.call_args[1]
    assert kwargs['parant_group'].num == 1
    assert kwargs['child_group'].num == 4
    assert kwargs['certfile']
    assert kwargs['keyfile']

    echo_channel_handler = kwargs['child_handler_initializer']()
    assert echo_channel_handler._client_eventloop_group.num == 8
    assert echo_channel_handler._tls is True


def test_run_disguise_tls_server(mocker):
    mocker.patch('simple_proxy.run.ServerBootstrap')
    submit_daemon_thread_mocker = mocker.patch('simple_proxy.run.submit_daemon_thread')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=True,
        content=True, to_file=True,
        tls=False, ss=False,
        key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=False,
        monitor_interval=3,
        disguise_tls_ip=None,
        disguise_tls_port=443,
        run_disguise_tls_server=True,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=4,
    )
    submit_daemon_thread_mocker.assert_called_once()


def test_run_monitor(mocker):
    mocker.patch('simple_proxy.run.ServerBootstrap')
    spawn_clients_monitor_mocker = mocker.patch('simple_proxy.run.spawn_clients_monitor')
    run_proxy(
        local_server='127.0.0.2', local_port=8081,
        remote_server="www.google.com", remote_port=80,
        using_global=True,
        content=True, to_file=True,
        tls=False, ss=True,
        key_file="/tmp/key.pem", cert_file="/tmp/cert.pem",
        monitor=True,
        monitor_interval=30,
        disguise_tls_ip=None,
        disguise_tls_port=443,
        run_disguise_tls_server=False,
        alpn=True,
        read_delay_millis=100,
        write_delay_millis=200,
        workers=4,
    )
    spawn_clients_monitor_mocker.assert_called_once_with(30)
