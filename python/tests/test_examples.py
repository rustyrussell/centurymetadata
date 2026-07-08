#! /usr/bin/env python3
"""Verify examples/EXAMPLES.md's derived values and run its commands for real.

test_examples_md_live() below walks every fenced code block in the doc in
order and actually executes each `$ ...`/bare shell command against a fresh
local server (see centurymetadata.server.devserver), substituting the local
server's URL for testapi.centurymetadata.org and a scratch directory for
/tmp/, then asserting the output matches what the doc shows. Non-command
blocks (the python snippet, the bare `--reader=...` fragment) are skipped.

If you change the keys/titles used in EXAMPLES.md, update the constants
below to match (and vice versa).
"""
import re
import shlex
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Tuple

import centurymetadata
import secp256k1

from centurymetadata.server.devserver import CenturyHTTPServer

REPO_ROOT = Path(__file__).parent.parent.parent
TOOL_PY = REPO_ROOT / "examples" / "centurytool.py"
EXAMPLES_MD = REPO_ROOT / "examples" / "EXAMPLES.md"

WRITER_SECRET = "01" * 32
READER_SECP_SECRET = "02" * 32
READER_MLKEM_SEED = "02" * 32
READER_SECRET = f"{READER_SECP_SECRET}/{READER_MLKEM_SEED}"

EXPECTED_WRITER_PUBKEY = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
EXPECTED_READER_SECP_PUBKEY = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"
EXPECTED_READER_MLKEM_PUBKEY = (
    "60e56b72c5821af22a359880ed38c94b828c8eb74609a6c845f1be5f244e8d9"
    "9890c5609087778b48b6d0f7693a5e80da8490c20c9367d6110a31507c126bf"
    "15374a74e460d13188cf0b1885b3c884a042fe253a6b487a9597c3c1f0c674f"
    "c2358c7b7712c77ce676907905dc0e8363d6461c41aa8d0d47cae478dcda321"
    "f3b0c2b7008d86a97e1613678109bdcdb7327a58cdf312c0512910946a9df23"
    "08585810443932d46e8b93b9511a9161e79c749f3812b34bacb6c77c745a5a3"
    "3a4a230c9330b5f5bc185147d426c86313b1eaa21fd54a15a3635ab0405dfe3"
    "0025b49369262b5d88a051e7c62a9473172c52c45d50784dc4f28008483b31e"
    "81d68075ea782e368773f80cc777aad8540c8203000cd57c5b45a322b3134e2"
    "5088ff7116592cb7b236849935426062d8c0acd0c34314b939df64a794fe0aa"
    "e14ba778e18bc7324d9d0a6f82980e1052a08a29af6ba392b4e23ccee2cddbf"
    "7905ca1ae1d086878d6044d911c0f56c4a41a337c3644e2120f672181f49049"
    "143c3da7fac725c97c0d5a4d0df10789935684b88b22c65769ecaf5df34a32d"
    "7c3d05449b725ba758c9f0fbcb326a6a6d48a8d81881bfcf6694db88bdfdb22"
    "18d4a0b55b8ddaf8077f181a60dacd3d456d65f2a01bd87b654355189656cc3"
    "98e2f1a2312484427017cd53b56879c172a4558f26aa415b2ce2e3382946b5e"
    "da3320f6d8760fb8131ad88d4493028424b1ed73a8cfdc9644fcb5ade912696"
    "271ea57606e008eb1ec9be8e2a25d145984f37a158b08563c60b9668cd07790"
    "05c3ae39e400744953ffba3dc56ac8303b2f51a50c85a19106d8cff0114b8ac"
    "c652218750775903dc372501c0f277990450b0883db30dd93b49ce1be2bb7af"
    "fed88135d99c5d964874642156220025e9839d7472b1c3b775802dc2329dd34"
    "c0e656669c45b851c496e8fa43f9024b593210bf4886b910438875363173256"
    "d088a34e5bb1deb70e2a9c52d4639b51a0ccecfb68fc9194952113eb2730a06"
    "1788f4989f6f0bf657c0a614060d480a6d5494059598c51b50bd898b8ddf7b5"
    "fc7633206c81301c44c58a6c05131e2f8aa7491b68a8679e5b705fc68b8d9c7"
    "6185f60340f300a3375a108190ba3993cb6d0ca07fb68156601c097b293c75e"
    "b080b56eb075d6ba8db6132b988a103fc36898274f9a7668893b6711200bb71"
    "cc16362ba3c19cec30549a6c6a64ef503bd53527f47852846cc8af42dc949ba"
    "79866f6e52a6c9c081ddc456fc2b239fb405abe61056ac859253b9b39685f3d"
    "36fc0a6472554cfd800bfb373458fbc43a661b25e1332970c9fcfa4bf50b289"
    "ecb319e7f59443563e5309a5d0c75be0587ce5f9aa1ca6bcb4aa671083ae535"
    "a4ac94210cb6c1f60675035359429aa943794bf482b56f8f696542871d67477"
    "60396140d92304a37efad84307492a5f0292a9fc08d7a5cf69082084c04d261"
    "22efb46ca02725b7bd9a9839b5fcb91b6833586f623c5a1a48d088533acb92a"
    "f2b40ee1d784d137ab49714e0a3a77e8fa8084e80987870afd29c5aaa04e7af"
    "95fb58b0ed78a2b5b1526058ba6728b70d311002fdb7ec93755ac8a48fa7923"
    "d8b747ee105022d075eda89dce362366c11cb41294c07008d5d77546fb603da"
    "c8cbf61b9895ab1ed45744f78c734b26be1cc8017b15d736253324a7965969a"
    "00408258fc2dfc5933c4199891465871120e1848cc55dc698bb636ccb383154"
    "00f2528150a329ef0fa3da5318dc0889a40979c57dc939c046c73201ef4ecca"
    "629348f37164da52a085b0661b03c82454ba5005c83d750ebf2812df1189081"
    "297ded189e4c248f4b85e3111b96c70996c4052c46b2b5a5a5612ec1d022a9f"
    "b6ab617ecb9749227c80f23d63014cf2ea34c6521e30ab96d38345ce1583bf0"
    "28b1099763d5321c177298fea52bf5b556afac9d1b430fb215bc6b469c85946"
    "1cc49b6a9cb3748606542cb5575057587167ddf04290800938c83a16256a194"
    "8135b76af771485818b39195486f7bc557dabbc0c675a60997e08c9b2f8ab19"
    "c47499198033f0139b01e00b68b68896c2718cec2c8e0b38dd3b172345a53b0"
    "2a38e6b890a990cc3ebaae6c82a961cb4ec47981616c97a3a39a3c5a3d36ac8"
    "515119f17352b7a1039703a59e620b5ad73ad1253c586259693bc2dd63f8ab9"
    "2be14256a97f95088abb66af28f7c99d9587c3f0961b864b6"
)
EXPECTED_READER_ID = "86bc303b5a3a42d81319561bab832beb13bbcc66951893398db1150a5da26b9b"


def test_derived_keys_match_examples_doc() -> None:
    """The keys/reader_id quoted throughout EXAMPLES.md for these secrets."""
    writer_privkey = secp256k1.PrivateKey(bytes.fromhex(WRITER_SECRET))
    assert writer_privkey.pubkey.serialize().hex() == EXPECTED_WRITER_PUBKEY

    reader_secp_privkey = secp256k1.PrivateKey(bytes.fromhex(READER_SECP_SECRET))
    assert reader_secp_privkey.pubkey.serialize().hex() == EXPECTED_READER_SECP_PUBKEY

    reader_mlkem_pubkey, _ = centurymetadata.derive_mlkem_keypair(bytes.fromhex(READER_MLKEM_SEED))
    assert reader_mlkem_pubkey.hex() == EXPECTED_READER_MLKEM_PUBKEY

    reader_id = centurymetadata.get_reader_id(reader_secp_privkey.pubkey, reader_mlkem_pubkey)
    assert reader_id.hex() == EXPECTED_READER_ID


# ── Live doc runner ───────────────────────────────────────────────────────────

def _code_blocks(markdown: str) -> List[str]:
    return re.findall(r"```[^\n]*\n(.*?)```", markdown, re.DOTALL)


def _is_command_start(line: str) -> bool:
    return (line.startswith("$ ")
            or line.startswith("./examples/centurytool.py")
            or line.startswith("curl ")
            or line.startswith("printf "))


def _parse_transcript(block: str) -> List[Tuple[str, str]]:
    """Split a fenced block into (command, expected_output) pairs.

    A command may span multiple backslash-continued lines; everything
    up to the next command (or the end of the block) is its expected
    output. Blocks with no command-looking line (the python snippet,
    the bare `--reader=...` fragment) yield no pairs.
    """
    lines = block.splitlines()
    pairs = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if _is_command_start(line):
            cmd_lines = [line[2:] if line.startswith("$ ") else line]
            while cmd_lines[-1].rstrip().endswith("\\"):
                i += 1
                cmd_lines.append(lines[i])
            i += 1
            out_lines = []
            while i < n and not _is_command_start(lines[i]):
                out_lines.append(lines[i])
                i += 1
            pairs.append(("\n".join(cmd_lines), "\n".join(out_lines)))
        else:
            i += 1
    return pairs


def test_examples_md_live(tmp_path: Path) -> None:
    """Actually run EXAMPLES.md's commands, in order, against a fresh local server."""
    basedir = tmp_path / "basedir"
    (basedir / "00-ff" / "00-ff").mkdir(parents=True)
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    httpd = CenturyHTTPServer(basedir)
    port = httpd.server_address[1]
    base_url = f"http://localhost:{port}"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        tool_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(TOOL_PY))} --server={base_url}"
        markdown = EXAMPLES_MD.read_text()
        for block in _code_blocks(markdown):
            for cmd, expected in _parse_transcript(block):
                cmd = cmd.replace("http://testapi.centurymetadata.org", base_url)
                cmd = cmd.replace("/tmp/", f"{work_dir}/")
                cmd = cmd.replace("./examples/centurytool.py", tool_cmd, 1)

                result = subprocess.run(
                    cmd, shell=True, executable="/bin/bash", cwd=REPO_ROOT,
                    capture_output=True, text=True,
                )
                assert result.returncode == 0, (
                    f"command failed (rc={result.returncode}):\n{cmd}\n"
                    f"stdout: {result.stdout}\nstderr: {result.stderr}"
                )
                if expected.strip():
                    # Redirected stdout (`--raw > file`) means the doc's
                    # shown output is actually the informational stderr.
                    actual = result.stderr if " > " in cmd else result.stdout
                    assert actual.strip() == expected.strip(), (
                        f"output mismatch for:\n{cmd}\n"
                        f"expected:\n{expected}\ngot:\n{actual}"
                    )
    finally:
        httpd.shutdown()
