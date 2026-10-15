"""The window's command line re-entry and a hidden verify through it."""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUI = os.path.join(ROOT, "ewfprobe_gui.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
E01 = os.path.join(FIXTURES, "encase5-fast.E01")
L01 = os.path.join(FIXTURES, "tracy-phone-2012-07-05-1640.L01")


def run(*args, env=None):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env,
                          stdin=subprocess.DEVNULL, timeout=300, check=False)


def tk_display_available():
    """Ask a separate process, so this one never creates a Tk root of its own."""
    return run("-c", "import tkinter; tkinter.Tk().destroy()").returncode == 0


@pytest.mark.parametrize("command,image", [("info", E01), ("verify", E01), ("files", L01)])
def test_cli_reentry_prints_what_the_command_line_prints(command, image):
    direct = run(os.path.join(ROOT, "ewfprobe.py"), command, image)
    through = run(GUI, "--cli", command, image)
    assert direct.returncode == through.returncode == 0, through.stderr
    assert through.stdout == direct.stdout


def test_password_reaches_the_tool_through_the_environment():
    with open(os.path.join(FIXTURES, "manifest.json"), encoding="utf-8") as handle:
        password = json.load(handle)["encrypted_aff"]["password"]
    image = os.path.join(FIXTURES, "aff-enc-pass.aff")
    probe = run("-c", "import sys; sys.path.insert(0, sys.argv[1]); import ewfprobe; "
                "sys.exit(0 if ewfprobe._AES else 1)", ROOT)
    if probe.returncode:
        pytest.skip("encrypted AFF needs the optional pycryptodome package")
    env = dict(os.environ, EWFPROBE_GUI_PASSWORD=password)
    result = run(GUI, "--cli", "verify", "-q", "--password-env", "EWFPROBE_GUI_PASSWORD", image, env=env)
    assert result.returncode == 0, result.stderr
    assert "matches the stored hash" in result.stdout


def test_hidden_window_verifies():
    if not tk_display_available():
        pytest.skip("Tk cannot open a display here")
    result = run(GUI, "--smoke", E01)
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome["exit"] == 0
    assert "MD5" in outcome["output"] and "matches the stored hash" in outcome["output"]
