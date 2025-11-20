import inspect
import logging
import sys
from pathlib import Path
import os
import traceback
from functools import wraps

_logger = logging.getLogger(__name__)
_stderr = False


def enable_stderr():
    global _stderr
    _stderr = True


def _get_logger(max_depth=8):
    stacks = inspect.stack()
    for i in range(1, min(len(stacks), max_depth)):
        frm = stacks[i]
        mod = inspect.getmodule(frm[0])
        for k, v in mod.__dict__.items():
            if isinstance(v, logging.Logger) and v is not _logger:
                return v
    return _logger


def pstderr(msg):
    _get_logger().debug(msg)
    if _stderr:
        print(msg, file=sys.stderr, flush=True)


def pfatal(msg):
    _get_logger().critical(msg)
    # print(msg, file=sys.stderr, flush=True)
    exit(1)


def setup_logging(log_file: Path | None, level=logging.INFO):
    handler = logging.StreamHandler()
    if log_file:
        from logging.handlers import RotatingFileHandler
        pstderr(f"Save log at {log_file}")
        handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=10 * 1024 * 1024,  # 10M
            backupCount=5
        )
    logging.basicConfig(
        handlers=[handler],
        level=level,
        format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def _all_args_repr(args, kw):
    try:
        args_repr = [f"<{len(arg)} bytes>" if isinstance(arg, (bytes, bytearray)) else repr(arg) for arg in args]
        kws = []
        for k, v in kw.items():
            if isinstance(v, (bytes, bytearray)):
                kws.append(f"{k}=<{len(v)} bytes>")
            else:
                kws.append(f"{k}={repr(v)}")
        return ', '.join(args_repr + kws)
    except (Exception,):
        return "(?)"

def sneaky():

    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kw):
            all_args = _all_args_repr(args, kw)
            try:
                return func(*args, **kw)
            except Exception as e:
                emsg = f"[{e}] sneaky call: {func.__name__}({all_args})"
                _get_logger().exception(emsg)
                print(emsg, traceback.format_exc(), file=sys.stderr, sep=os.linesep, flush=True)
        return wrapper
    return decorate