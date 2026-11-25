import subprocess


def run(cmd):
    """Выполняет команду, собранную из недоверенной строки."""
    return subprocess.call(cmd, shell=True)
