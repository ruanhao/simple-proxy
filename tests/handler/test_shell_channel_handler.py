import subprocess
import pytest

from simple_proxy.handler.shell_channel_handler import ShellChannelHandler
import simple_proxy.handler.shell_channel_handler as sch


@pytest.fixture(scope='function')
def ctx_mocker(mocker):
    return mocker.MagicMock()


class TestHandleReadOutput:

    def test_reads_and_updates_client_then_closes_on_eof(self, mocker, ctx_mocker):
        handler = ShellChannelHandler()
        handler.raddr = ('1.1.1.1', 1111)

        os_read_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.os.read',
            side_effect=[b'hello', b'']
        )
        client_mocker = mocker.MagicMock()
        get_client_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.get_client_or_none',
            return_value=client_mocker
        )

        handler.handle_read_output(ctx_mocker, 10)

        assert os_read_mock.call_count == 2
        ctx_mocker.write.assert_called_once_with(b'hello')
        get_client_mock.assert_called_once_with(handler.raddr)
        client_mocker.write.assert_called_once_with(5)
        ctx_mocker.close.assert_called_once()

    def test_closes_on_exception(self, mocker, ctx_mocker):
        handler = ShellChannelHandler()
        handler.raddr = ('1.1.1.1', 1111)

        mocker.patch(
            'simple_proxy.handler.shell_channel_handler.os.read',
            side_effect=Exception("boom")
        )

        handler.handle_read_output(ctx_mocker, 10)

        ctx_mocker.close.assert_called_once()
        ctx_mocker.write.assert_not_called()


class TestWindowsShellArgs:

    def test_returns_cmd_args(self, mocker):
        mocker.patch('simple_proxy.handler.shell_channel_handler.shutil.which', return_value='/bin/cmd')
        handler = ShellChannelHandler()

        assert handler._windows_shell_args() == ['/bin/cmd', '/Q', '/K']

    def test_raises_when_no_shell(self, mocker):
        mocker.patch('simple_proxy.handler.shell_channel_handler.shutil.which', return_value=None)
        handler = ShellChannelHandler()

        with pytest.raises(Exception):
            handler._windows_shell_args()


class TestSetupShell:

    def test_setup_windows_shell(self, mocker, ctx_mocker):
        handler = ShellChannelHandler()
        mocker.patch('simple_proxy.handler.shell_channel_handler.shutil.which', return_value='/bin/cmd')
        process_mocker = mocker.MagicMock()
        process_mocker.stdin.fileno.return_value = 1
        process_mocker.stdout.fileno.return_value = 2
        process_mocker.stderr.fileno.return_value = 3
        popen_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.subprocess.Popen',
            return_value=process_mocker
        )
        submit_mock = mocker.patch('simple_proxy.handler.shell_channel_handler.submit_daemon_thread')

        handler._setup_windows_shell(ctx_mocker)

        popen_args, popen_kwargs = popen_mock.call_args
        assert popen_args[0] == ['/bin/cmd', '/Q', '/K']
        assert popen_kwargs['stdin'] == subprocess.PIPE
        assert popen_kwargs['stdout'] == subprocess.PIPE
        assert popen_kwargs['stderr'] == subprocess.PIPE
        assert popen_kwargs['start_new_session'] is True
        assert handler._shell_stdin_fd == 1
        submit_mock.assert_any_call(handler.handle_read_output, ctx_mocker, 2)
        submit_mock.assert_any_call(handler.handle_read_output, ctx_mocker, 3)

    def test_setup_linux_shell(self, mocker, ctx_mocker):
        handler = ShellChannelHandler()
        mocker.patch('simple_proxy.handler.shell_channel_handler.shutil.which', return_value='/bin/bash')
        openpty_mock = mocker.patch('simple_proxy.handler.shell_channel_handler.os.openpty', return_value=(10, 11))
        popen_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.subprocess.Popen',
            return_value=mocker.MagicMock()
        )
        submit_mock = mocker.patch('simple_proxy.handler.shell_channel_handler.submit_daemon_thread')
        close_mock = mocker.patch('simple_proxy.handler.shell_channel_handler.os.close')

        handler._setup_linux_shell(ctx_mocker)

        openpty_mock.assert_called_once()
        popen_args, popen_kwargs = popen_mock.call_args
        assert popen_args[0] == ['/bin/bash', '-li']
        assert popen_kwargs['stdin'] == 11
        assert popen_kwargs['stdout'] == 11
        assert popen_kwargs['stderr'] == 11
        assert popen_kwargs['start_new_session'] is True
        assert handler._shell_stdin_fd == 10
        close_mock.assert_called_once_with(11)
        submit_mock.assert_called_once_with(handler.handle_read_output, ctx_mocker, 10)


class TestChannelLifecycle:

    def test_channel_active_linux(self, mocker, ctx_mocker, monkeypatch):
        monkeypatch.setattr(sch.os, 'name', 'posix')
        handler = ShellChannelHandler()
        handler._process = mocker.MagicMock(pid=1000)
        local_socket = mocker.MagicMock()
        ctx_mocker.channel.return_value.socket.return_value = local_socket
        local_socket.getpeername.return_value = ('1.2.3.4', 1234)
        client_mocker = mocker.MagicMock()
        get_client_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.get_client_or_create',
            return_value=client_mocker
        )
        setup_linux_mock = mocker.patch.object(handler, '_setup_linux_shell')

        handler.channel_active(ctx_mocker)

        assert handler.raddr == ('1.2.3.4', 1234)
        get_client_mock.assert_called_once_with(('1.2.3.4', 1234))
        assert client_mocker.local_socket is local_socket
        setup_linux_mock.assert_called_once_with(ctx_mocker)

    def test_channel_active_windows(self, mocker, ctx_mocker, monkeypatch):
        monkeypatch.setattr(sch.os, 'name', 'nt')
        handler = ShellChannelHandler()
        handler._process = mocker.MagicMock(pid=1000)
        local_socket = mocker.MagicMock()
        ctx_mocker.channel.return_value.socket.return_value = local_socket
        local_socket.getpeername.return_value = ('5.6.7.8', 5678)
        client_mocker = mocker.MagicMock()
        get_client_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.get_client_or_create',
            return_value=client_mocker
        )
        setup_windows_mock = mocker.patch.object(handler, '_setup_windows_shell')

        handler.channel_active(ctx_mocker)

        assert handler.raddr == ('5.6.7.8', 5678)
        get_client_mock.assert_called_once_with(('5.6.7.8', 5678))
        assert client_mocker.local_socket is local_socket
        setup_windows_mock.assert_called_once_with(ctx_mocker)

    def test_channel_read(self, mocker, ctx_mocker):
        handler = ShellChannelHandler()
        handler.raddr = ('1.1.1.1', 1111)
        handler._shell_stdin_fd = 20
        client_mocker = mocker.MagicMock()
        get_client_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.get_client_or_create',
            return_value=client_mocker
        )
        os_write_mock = mocker.patch('simple_proxy.handler.shell_channel_handler.os.write')

        handler.channel_read(ctx_mocker, b'cmd')

        get_client_mock.assert_called_once_with(('1.1.1.1', 1111))
        client_mocker.read.assert_called_once_with(3)
        os_write_mock.assert_called_once_with(20, b'cmd')

    def test_channel_inactive(self, mocker, ctx_mocker):
        handler = ShellChannelHandler()
        handler.raddr = ('1.1.1.1', 1111)
        handler._shell_stdin_fd = 30
        handler._process = mocker.MagicMock()
        client_mocker = mocker.MagicMock()
        client_mocker.pretty_rx_total.return_value = '1B'
        client_mocker.pretty_tx_total.return_value = '2B'
        client_mocker.pretty_born_time.return_value = '1s'
        pop_client_mock = mocker.patch(
            'simple_proxy.handler.shell_channel_handler.pop_client',
            return_value=client_mocker
        )
        os_close_mock = mocker.patch('simple_proxy.handler.shell_channel_handler.os.close')

        handler.channel_inactive(ctx_mocker)

        pop_client_mock.assert_called_once_with(('1.1.1.1', 1111))
        handler._process.kill.assert_called_once()
        os_close_mock.assert_called_once_with(30)
