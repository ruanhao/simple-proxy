import os
import shutil
import subprocess
from py_netty.handler import LoggingChannelHandler
import logging
from ..utils.logutils import pstderr
from ..clients import get_client_or_none, get_client_or_create, pop_client
from ..utils.osutils import submit_daemon_thread


logger = logging.getLogger(__name__)

class ShellChannelHandler(LoggingChannelHandler):

    def __init__(self):
        self.raddr: tuple[str, int] = None  # noqa

    def handle_read_output(self, ctx, fd):
        pstderr(f"{ctx.channel()} Start reading output from fd {fd} ...")
        while True:
            try:
                data = os.read(fd, 1024)
                if not data:
                    pstderr(f"{ctx.channel()} EOF reached on fd {fd}")
                    ctx.close()
                    return
                logger.debug(f"{ctx.channel()} Read {len(data)} bytes from fd {fd}")
                ctx.write(data)
                c = get_client_or_none(self.raddr)
                if c:
                    c.write(len(data))
            except Exception as e:
                pstderr(f"{ctx.channel()} Exception reading output from fd {fd}: {e}")
                ctx.close()
                return

    @staticmethod
    def _windows_shell_args():
        if shutil.which('cmd'):
            return [shutil.which('cmd'), '/Q', '/K']
        else:
            raise Exception("No shell found")

    def _setup_windows_shell(self, ctx):
        my_env = os.environ.copy()
        args = self._windows_shell_args()
        pstderr(f"{ctx.channel()} Starting shell with args: {args}")
        self._process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=-1,
            env=my_env
        )
        submit_daemon_thread(self.handle_read_output, ctx, self._process.stdout.fileno())
        submit_daemon_thread(self.handle_read_output, ctx, self._process.stderr.fileno())
        self._shell_stdin_fd = self._process.stdin.fileno()

    def _setup_linux_shell(self, ctx):
        bash = shutil.which('bash')
        master_fd, slave_fd = os.openpty()
        my_env = os.environ.copy()
        args = [bash, '-li']
        pstderr(f"{ctx.channel()} Starting shell with args: {args}")
        self._process = subprocess.Popen(
            args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            bufsize=-1,
            start_new_session=True,
            env=my_env
        )
        os.close(slave_fd)
        self._shell_stdin_fd = master_fd
        submit_daemon_thread(self.handle_read_output, ctx, master_fd)

    def _setup_linux_shell0(self, ctx):
        my_env = os.environ.copy()
        i_r, i_w = os.pipe()
        o_r, o_w = os.pipe()
        self._process = subprocess.Popen(
            [shutil.which('bash'), '-li'],
            stdin=i_r,
            stdout=o_w,
            stderr=o_w,
            bufsize=-1,
            start_new_session=True,
            env=my_env
        )
        self._shell_stdin_fd = i_w
        submit_daemon_thread(self.handle_read_output, ctx, o_r)

    def channel_active(self, ctx):
        super().channel_active(ctx)
        local_socket = ctx.channel().socket()
        self.raddr = local_socket.getpeername()
        get_client_or_create(self.raddr).local_socket = local_socket

        if os.name == 'nt':
            self._setup_windows_shell(ctx)
        else:
            self._setup_linux_shell(ctx)

        pstderr(f"{ctx.channel()} Shell started: {self._process.pid}")

    def channel_read(self, ctx, bytebuf):
        super().channel_read(ctx, bytebuf)
        if hasattr(self, 'raddr'):
            get_client_or_create(self.raddr).read(len(bytebuf))
        os.write(self._shell_stdin_fd, bytebuf)

    def channel_inactive(self, ctx):
        super().channel_inactive(ctx)

        c = pop_client(self.raddr)
        pstderr(f"{ctx.channel()} Connection closed, rx: {c.pretty_rx_total()}, tx: {c.pretty_tx_total()}, duration: {c.pretty_born_time().lower()}")

        self._process.kill()
        os.close(self._shell_stdin_fd)
        pstderr(f"{ctx.channel()} Shell terminated: {self._process.pid}")
