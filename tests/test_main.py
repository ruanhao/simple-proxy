from click.testing import CliRunner

from simple_proxy.__main__ import _cli


def test_help_includes_http_stub():
    result = CliRunner().invoke(_cli, ['--help'])

    assert result.exit_code == 0
    assert '--http-stub' in result.output
    assert 'Run as HTTP stub server' in result.output


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
