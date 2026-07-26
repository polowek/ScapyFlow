import os
import select
import sys

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
