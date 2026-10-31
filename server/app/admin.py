"""Operator commands, run inside the api container:

    docker compose exec api python -m app.admin prune

prune   Run the prune job now (it also runs on its own every hour): delete
        events and media every active device has acked, and anything older
        than SIDETRAY_RETENTION_DAYS. Prints what it deleted as JSON.
"""

import json
import sys

from . import main


def run(argv: list[str]) -> int:
    if argv[:1] == ["prune"]:
        main.init_db()
        print(json.dumps(main.prune()))
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
