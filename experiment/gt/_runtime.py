"""Execution plumbing shared by the public runners, without changing their predicates.

Paths in TL_* variables refer to the Bash environment (Linux or the selected WSL
distribution); Windows drive paths are also mapped to WSL's default /mnt mounts.
JAVA_HOME defaults to ~/jdk/jdk21. No credential is embedded in this module.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

if os.name == "nt":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")

EXPERIMENT_ROOT = Path(os.environ.get("TL_EVAL_ROOT", Path(__file__).resolve().parent.parent)).expanduser().resolve()
ROOT = str(EXPERIMENT_ROOT)


def bash_path(path):
    """Map a controller path to Bash; native POSIX paths are left intact."""
    value = os.fspath(path)
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return "/mnt/" + value[0].lower() + value[2:].replace("\\", "/")
    if value.startswith("\\\\"):
        raise ValueError("Use a Linux path or Windows drive path, not a UNC checkout")
    return value


def host_path(path):
    """Resolve analyzer paths for the Python controller's filesystem."""
    value = os.fspath(path)
    if os.name == "nt" and re.match(r"^/mnt/[A-Za-z]/", value):
        return value[5].upper() + ":/" + value[7:]
    if os.path.isabs(value):
        return value
    return os.path.join(ROOT, value)


BASH_ROOT = bash_path(EXPERIMENT_ROOT)


def shell_path(value):
    """Quote one path argument, preserving expansion of a leading ~/ in Bash."""
    value = bash_path(value)
    if value == "~":
        return '"$HOME"'
    if value.startswith("~/"):
        return '"$HOME"/' + shlex.quote(value[2:])
    return shlex.quote(value)


def tool_command(variable, default):
    return shell_path(os.environ.get(variable, default))


def java_home():
    return os.environ.get("JAVA_HOME", "~/jdk/jdk21")


def java_command():
    return tool_command("TL_JAVA", java_home().rstrip("/\\") + "/bin/java")


def shell_environment():
    return "export JAVA_HOME=" + shell_path(java_home()) + '; export PATH="$JAVA_HOME/bin:$PATH"'


def bash_argv(command):
    if os.name == "nt":
        # WSL does not inherit arbitrary Windows environment variables. Forward
        # configuration paths explicitly; credentials remain in token files.
        paths = ("JAVA_HOME", "TL_SONAR_HOME", "TL_SONAR_SCANNER",
                 "TL_SONAR_RUNTIME_DIR", "TL_SONAR_TOKEN_FILE", "TL_SONAR_INSTALL_DIR",
                 "TL_PMD_HOME")
        exports = ["export " + key + "=" + shell_path(os.environ[key])
                   for key in paths if key in os.environ]
        if "TL_SONAR_URL" in os.environ:
            exports.append("export TL_SONAR_URL=" + shlex.quote(os.environ["TL_SONAR_URL"]))
        if exports:
            command = "; ".join(exports) + "; " + command
        prefix = ["wsl.exe"]
        if os.environ.get("TL_WSL_DISTRO"):
            prefix += ["--distribution", os.environ["TL_WSL_DISTRO"]]
        return prefix + ["--exec", "bash", "-lc", command]
    return ["bash", "-lc", command]


def run_bash(command, **kwargs):
    """subprocess.run with the platform-appropriate Bash invocation."""
    return subprocess.run(bash_argv(command), **kwargs)


def require_positive(value, name):
    if value < 1:
        raise ValueError(name + " must be positive")
    return value
