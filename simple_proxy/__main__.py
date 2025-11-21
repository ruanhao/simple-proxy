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
@optgroup.option('--local-server', '-l', default='localhost', help='Local server address', show_default=True)
@optgroup.option('--local-port', '-lp', type=int, default=8080, help='Local port', show_default=True)
@optgroup.option('--global', '-g', 'using_global', is_flag=True, help='Local port listening on all interfaces')
@optgroup.option('--remote-server', '-r', default='localhost', help='Remote server address', show_default=True)
@optgroup.option('--remote-port', '-rp', type=int, default=80, help='Remote port', show_default=True)
@optgroup.option('--tls', '-s', is_flag=True, help='Denote remote is listening on secure port')
@optgroup.option('-ss', is_flag=True, help='Make local listen on secure port')
@optgroup.group('TCP proxy configuration', help='Configuration for TCP proxy mode')
@optgroup.option('--read-delay-millis', type=int, help='Read delay in milliseconds', default=0, show_default=True)
@optgroup.option('--write-delay-millis', type=int, help='Write delay in milliseconds', default=0, show_default=True)
#
@optgroup.group('Thread configuration', help='Configuration for thread pool')
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
@optgroup.option('--monitor-interval', '-mi', type=int, default=3, help='Speed monitor interval', show_default=True)
#
@optgroup.group('TLS Disguise configuration', help='Configuration for protection against unwanted inspection')
@optgroup.option('--disguise-tls-ip', '-dti', help='Disguised upstream TLS IP')
@optgroup.option('--disguise-tls-port', '-dtp', type=int, help='Disguised upstream TLS port', default=443, show_default=True)
@optgroup.option('--run-disguise-tls-server', is_flag=True, help='Run builtin disguise TLS server without specifying external one')
@optgroup.option('--white-list', '-wl', help='IP White list for legal incoming TLS connections (comma separated)')
#
@optgroup.group('Proxy configuration', help='Configuration for proxy')
@optgroup.option('--as-echo-server', '-e', is_flag=True, help='Run as Echo server')
@optgroup.option('--shell-proxy', is_flag=True, help='Run as shell proxy server')
@optgroup.option('--http-proxy', is_flag=True, help='Run as HTTP proxy server')
@optgroup.option('--socks5-proxy', is_flag=True, help='Run as SOCKS5 proxy server')
@optgroup.option('--proxy-username', help='Proxy username')
@optgroup.option('--proxy-password', help='Proxy password')
@optgroup.option('--proxy-transform', '-t', type=(str, int, str, int), multiple=True, help='List of target transformations(origin_host, origin_port, transformed_host, transformed_port)')
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
