from click.testing import CliRunner

from simple_proxy.__main__ import _cli


def test_help_includes_http_stub():
    result = CliRunner().invoke(_cli, ['--help'])

    assert result.exit_code == 0
    assert '--http-stub' in result.output
    assert 'Run as HTTP stub server' in result.output


def test_help_includes_file_server_options():
    result = CliRunner().invoke(_cli, ['--help'])

    assert result.exit_code == 0
    assert '--file-server' in result.output
    assert 'Run as file server' in result.output
    assert '-d, --directory' in result.output


def test_http_stub_is_forwarded_to_run_proxy(mocker):
    run_proxy = mocker.patch('simple_proxy.__main__.run_proxy')

    result = CliRunner().invoke(_cli, ['--http-stub', '-c'])

    assert result.exit_code == 0
    assert run_proxy.call_args.kwargs['http_stub'] is True
    assert run_proxy.call_args.kwargs['content'] is True


def test_http_stub_conflicts_with_other_server_modes(mocker):
    run_proxy = mocker.patch('simple_proxy.__main__.run_proxy')

    for option in (
        '--echo-proxy',
        '--shell-proxy',
        '--http-proxy',
        '--socks5-proxy',
    ):
        result = CliRunner().invoke(_cli, ['--http-stub', option])
        assert result.exit_code == 2
        assert f"'--http-stub' cannot be used with '{option}'" in result.output
    run_proxy.assert_not_called()


def test_file_server_options_are_forwarded(mocker, tmp_path):
    run_proxy = mocker.patch('simple_proxy.__main__.run_proxy')

    result = CliRunner().invoke(_cli, [
        '--file-server',
        '--directory', str(tmp_path),
        '-p', '9000',
        '-g',
        '--workers', '3',
        '-ss',
    ])

    assert result.exit_code == 0
    assert run_proxy.call_args.kwargs['file_server'] is True
    assert run_proxy.call_args.kwargs['directory'] == str(tmp_path)
    assert run_proxy.call_args.kwargs['local_port'] == 9000
    assert run_proxy.call_args.kwargs['using_global'] is True
    assert run_proxy.call_args.kwargs['workers'] == 3
    assert run_proxy.call_args.kwargs['ss'] is True


def test_file_server_conflicts_with_other_server_modes(mocker):
    run_proxy = mocker.patch('simple_proxy.__main__.run_proxy')

    for option in (
        '--echo-proxy',
        '--shell-proxy',
        '--http-proxy',
        '--http-stub',
        '--socks5-proxy',
    ):
        result = CliRunner().invoke(_cli, ['--file-server', option])
        assert result.exit_code == 2
        assert f"'--file-server' cannot be used with '{option}'" in result.output
    run_proxy.assert_not_called()


def test_file_server_rejects_remote_tls_option(mocker):
    run_proxy = mocker.patch('simple_proxy.__main__.run_proxy')

    result = CliRunner().invoke(_cli, ['--file-server', '-s'])

    assert result.exit_code == 2
    assert "use '-ss' for HTTPS" in result.output
    run_proxy.assert_not_called()


def test_file_server_validates_cert_pair_and_workers(mocker, tmp_path):
    run_proxy = mocker.patch('simple_proxy.__main__.run_proxy')
    certfile = tmp_path / 'cert.pem'
    certfile.write_text('cert')

    result = CliRunner().invoke(_cli, [
        '--file-server', '-ss', '-cf', str(certfile),
    ])
    assert result.exit_code == 2
    assert 'must be provided together' in result.output

    result = CliRunner().invoke(_cli, [
        '--file-server', '--workers', '0',
    ])
    assert result.exit_code == 2
    assert "'--workers' must be at least 1" in result.output
    run_proxy.assert_not_called()
