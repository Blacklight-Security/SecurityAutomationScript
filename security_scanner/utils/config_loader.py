import configparser

class ConfigLoader:
    @staticmethod
    def load():
        config = configparser.ConfigParser()
        config.read('security_scanner/config.ini')
        return config