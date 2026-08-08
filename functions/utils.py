import os
import select
import sys


class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    GRAY = "\033[90m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


if os.name == "nt":  # Windows
    import msvcrt

    def get_key():
        return msvcrt.getch().decode("utf-8", errors="ignore")

    def clear_buffer():
        while msvcrt.kbhit():
            msvcrt.getch()

else:  # Linux / macOS
    import termios
    import tty

    def get_key():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)

        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch

    def clear_buffer():
        while select.select([sys.stdin], [], [], 0)[0]:
            sys.stdin.read(1)
