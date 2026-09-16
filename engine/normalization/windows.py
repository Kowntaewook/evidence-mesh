import ntpath
import re


def path_key(value: str | None) -> str:
    """Windows lexical comparison only; never resolve against the analyst's disk."""
    if not value:
        return ""
    return ntpath.normpath(value.strip('"').replace("/", "\\")).casefold()


def basename(value: str | None) -> str:
    return ntpath.basename(path_key(value))


def command_tokens(command: str | None) -> set[str]:
    # Conservative quoted/unquoted token extraction, not a shell or PowerShell interpreter.
    return {
        path_key(a or b or c) for a, b, c in re.findall(r'"([^"\n]+)"|\'([^\'\n]+)\'|([^\s]+)', command or "")
    }
