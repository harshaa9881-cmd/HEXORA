# core/utils.py
import hashlib
import time

def sha256(s: str):
    return hashlib.sha256(s.encode()).hexdigest()

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")