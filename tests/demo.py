"""See what the report looks like for a visited server, without one: python3 -m tests.demo

Starts the stand-in Ollama (tests/helpers.py) with the model list modelled on Rapid7's published
sample, signed in to an account, and a copy of a server's files that binds to every interface and
keeps an API key in a world-readable unit file. Nothing here touches your real Ollama.
"""
import os
import sys
import tempfile

from guestcheck import cli
from tests.helpers import StandIn, build_host_root, load_fixture


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp, \
            StandIn(models=load_fixture("rapid7_sample.json")["models"]) as server:
        root = build_host_root(os.path.join(tmp, "server"))
        return cli.main(["--url", server.url, "--root", root, "--listen-port", "11434"] + sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
