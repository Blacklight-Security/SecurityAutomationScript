import sys

class logger:
    @staticmethod
    def change_color(text, color):
        colors = {
            "red": "\033[31m",
            "green": "\033[32m",
            "blue": "\033[34m",
            "white": "\033[0m"
        }
        return f"{colors[color]}{text}{colors["white"]}"

    @staticmethod
    def debug(message):
        print(f"{logger.change_color("[DEBUG]", "blue")} {message}")

    @staticmethod
    def info(message):
        print(f"{logger.change_color("[INFO]", "green")} {message}")

    @staticmethod
    def error(message):
        print(f"{logger.change_color("[ERROR]", "red")} {message}", file=sys.stderr)