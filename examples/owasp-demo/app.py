import hashlib
import subprocess


def run(cmd):
    return subprocess.call(cmd, shell=True)


def digest(value):
    return hashlib.md5(value.encode()).hexdigest()
