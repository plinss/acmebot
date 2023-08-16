"""ACMEbot module."""

from .acmebot import AcmeError, AcmeManager, ErrorCode, PrivateKeyError

__all__ = ['AcmeManager', 'AcmeError', 'ErrorCode', 'PrivateKeyError']

def run() -> int:
    exit_code = ErrorCode.EXCEPTION
    manager = None
    try:
        manager = AcmeManager()
        manager.run()
    except AcmeError:
        pass
    if (manager):
        exit_code = manager.exit_code
        try:
            del manager
        except Exception:
            pass
    return exit_code

if __name__ == '__main__':      # called from the command line
    sys.exit(run())
