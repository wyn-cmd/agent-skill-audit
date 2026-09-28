# Entry point for the skillscan package.
# Handles execution when run as a module via python -m skillscan.

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main())