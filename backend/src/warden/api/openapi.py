"""`python -m warden.api.openapi`: print the dashboard API's OpenAPI schema (for web/src/api-types.ts)."""

from __future__ import annotations

import json
import sys

from warden.api.app import create_api
from warden.api.events import EventBus


def main() -> None:
    app = create_api(None, EventBus(None))  # type: ignore[arg-type]  # the schema needs no live context
    json.dump(app.openapi(), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
