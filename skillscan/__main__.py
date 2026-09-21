"""Entry point for the skillscan package."""

import sys
from .cli import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)