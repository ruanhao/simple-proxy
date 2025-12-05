import click
from click_option_group import optgroup
import logging
import shutil

from .run import run_proxy
from .utils.logutils import setup_logging, enable_stderr
from .version import __version__

logger = logging.getLogger(__name__)


@click.command(short_help="Simple proxy", context_settings=dict(
    help_option_names=['-h', '--help'],
    max_content_width=shutil.get_terminal_size().columns - 10,
))
@optgroup.group('Common configuration', help='Configuration for local/remote endpoints')
@optgroup.option('--listening-host', '-l', 'local_server', default='localhost', help='Listening server address', show_default=True)
@optgroup.option('--listening-port', '-lp', 'local_port', type=int, default=8080, help='Listening port', show_default=True)
@optgroup.option('--global', '-g', 'using_global', is_flag=True, help='Listening on all interfaces')
@optgroup.option('--remote-host', '-r', 'remote_server', default='localhost', help='Remote host', show_default=True)
@optgroup.option('--remote-port', '-rp', type=int, default=80, help='Remote port', show_default=True)
@optgroup.option('--tls', '-s', is_flag=True, help='Denote remote is listening on secure port')
@optgroup.option('-ss', is_flag=True, help='Listening on secure port')
@optgroup.group('TCP proxy configuration', help='Configuration for TCP proxy mode')
@optgroup.option('--read-delay-millis', type=int, help='Read delay(ms)', default=0, show_default=True)
@optgroup.option('--write-delay-millis', type=int, help='Write delay(ms)', default=0, show_default=True)
#
@optgroup.group('Thread configuration', help='Configuration for thread')
@optgroup.option('--workers', type=int, default=1, help='Number of worker threads', show_default=True)
@optgroup.option('--proxy-workers', type=int, default=1, help='Number of proxy threads', show_default=True)
#
@optgroup.group('Traffic dump configuration', help='Configuration for traffic dump')
@optgroup.option('--tcp-flow', '-c', 'content', is_flag=True, help='Dump tcp flow on to console')
@optgroup.option('--save-tcp-flow', '-f', 'to_file', is_flag=True, help='Save tcp flow to file')
#
@optgroup.group('TLS certificate configuration', help='Configuration for TLS certificate')
@optgroup.option('--key-file', '-kf', help='Key file for local server', type=click.Path(exists=True))
@optgroup.option('--cert-file', '-cf', help='Certificate file for local server', type=click.Path(exists=True))
@optgroup.option('--alpn', is_flag=True, help='Set ALPN protocol as [h2, http/1.1]')
#
@optgroup.group('Traffic monitor configuration', help='Configuration for traffic monitor')
@optgroup.option('--monitor', '-m', is_flag=True, help='Print speed info to console for established connection')
@optgroup.option('--monitor-interval', '-mi', type=int, default=3, help='Speed monitor interval(seconds)', show_default=True)
#
@optgroup.group('TLS Disguise configuration', help='Configuration for protection against unwanted inspection')
@optgroup.option('--disguise-tls-ip', '-dti', help='Disguised upstream TLS IP')
@optgroup.option('--disguise-tls-port', '-dtp', type=int, help='Disguised upstream TLS port', default=443, show_default=True)
@optgroup.option('--run-disguise-tls-server', is_flag=True, help='Run builtin disguise TLS server without specifying external one')
@optgroup.option('--white-list', '-wl', help='IP White list for legal incoming TLS connections (comma separated)')
#
@optgroup.group('Proxy configuration', help='Configuration for application proxies')
@optgroup.option('--echo-proxy', '-e', 'as_echo_server', is_flag=True, help='Run as Echo server')
@optgroup.option('--shell-proxy', is_flag=True, help='Run as shell proxy server')
@optgroup.option('--http-proxy', is_flag=True, help='Run as HTTP proxy server')
@optgroup.option('--socks5-proxy', is_flag=True, help='Run as SOCKS5 proxy server')
@optgroup.option('--proxy-username', help='Proxy username for HTTP/SOCKS5 proxy')
@optgroup.option('--proxy-password', help='Proxy password for HTTP/SOCKS5 proxy')
@optgroup.option('--proxy-transform', '-t', type=(str, int, str, int), multiple=True, help='List of target transformations(origin_host, origin_port, transformed_host, transformed_port) for HTTP/SOCKS5 proxy')
#
@optgroup.group('Misc configuration')
@optgroup.option('-v', '--verbose', count=True)
@optgroup.option('--log-file', help='Log file', type=click.Path())
@click.version_option(prog_name='Simple Proxy', version=__version__)
def _cli(verbose, log_file: click.Path, **kwargs):
    setup_logging(log_file, logging.INFO if verbose == 0 else logging.DEBUG)
    if verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger('simple_proxy.utils').setLevel(logging.DEBUG)
    run_proxy(**kwargs)


# for setup.py entry point
def _run():
    enable_stderr()
    _cli()


if __name__ == '__main__':
    _run()
