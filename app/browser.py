import threading
import time
import webbrowser


def open_browser(url: str = "http://localhost:8000", delay: float = 1.5) -> None:
    def _open() -> None:
        time.sleep(delay)
        webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()
