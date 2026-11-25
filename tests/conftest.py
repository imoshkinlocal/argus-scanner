"""Shared fixtures for the argus test suite."""

from __future__ import annotations

import os
import textwrap

import pytest

JAVA_PREAMBLE = """\
import javax.servlet.http.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import org.owasp.esapi.ESAPI;

public class Sample extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
"""

JAVA_EPILOGUE = """
    }
}
"""


@pytest.fixture()
def java_source(tmp_path):
    """Write a Java snippet inside a servlet method and return its path."""

    def write(body: str, name: str = "Sample") -> str:
        path = tmp_path / f"{name}.java"
        source = JAVA_PREAMBLE + textwrap.indent(textwrap.dedent(body), " " * 8) + JAVA_EPILOGUE
        path.write_text(source)
        return str(path)

    return write


@pytest.fixture()
def rulecheck_dir(tmp_path):
    """A small multi-language tree with obvious vulnerabilities."""
    files = {
        "app.py": "import os\nos.system(input())\n",
        "app.js": "const cp = require('child_process');\ncp.exec(process.argv[2]);\n",
        "app.go": (
            'package main\n\nimport (\n\t"os"\n\t"os/exec"\n)\n\n'
            'func main() {\n\tcmd := os.Args[1]\n\texec.Command("sh", "-c", cmd).Run()\n}\n'
        ),
        "app.php": "<?php\nsystem($_GET['cmd']);\n?>\n",
        "app.rb": "system(params[:cmd])\nMarshal.load(params[:blob])\n",
        "app.c": "#include <string.h>\nvoid f(char *s) { char b[8]; strcpy(b, s); }\n",
    }
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    return str(tmp_path)
