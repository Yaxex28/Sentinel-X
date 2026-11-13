import pytest
from src.collectors.process_monitor import is_masquerading

def test_genuine_process():
    # svchost.exe in System32 should be genuine
    assert not is_masquerading("svchost.exe", r"C:\Windows\System32\svchost.exe")

def test_masquerading_in_temp():
    # svchost.exe in Temp should be masquerading
    assert is_masquerading("svchost.exe", r"C:\Users\Admin\AppData\Local\Temp\svchost.exe")

def test_genuine_non_system_process():
    # chrome.exe anywhere is not masquerading because it's not a critical system binary
    assert not is_masquerading("chrome.exe", r"C:\Users\Admin\AppData\Local\Google\Chrome\Application\chrome.exe")

def test_lookalike_in_desktop():
    # lsass.exe in Desktop should be masquerading
    assert is_masquerading("lsass.exe", r"C:\Users\Admin\Desktop\lsass.exe")
