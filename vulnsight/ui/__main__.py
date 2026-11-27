"""``python -m vulnsight.ui``: start the local dashboard."""

import argparse
import sys
import webbrowser

from vulnsight.ui.server import DEFAULT_PORT, HOST, create_server

EXIT_OK = 0
EXIT_COULD_NOT_START = 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m vulnsight.ui",
        description=(
            "Start the local VulnSight dashboard. It listens on "
            f"{HOST} only and cannot be reached from other computers."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port on {HOST} (default: {DEFAULT_PORT}; 0 picks a free port)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the dashboard in a browser",
    )

    return parser


def main(argv=None):
    """Run the dashboard until interrupted. Returns the process exit code."""

    parser = build_parser()

    try:
        arguments = parser.parse_args(argv)
    except SystemExit as stop:
        code = stop.code

        return code if isinstance(code, int) else 2

    try:
        server = create_server(arguments.port)
    except ValueError as error:
        print(f"vulnsight ui: error: {error}", file=sys.stderr)

        return 2
    except OSError as error:
        print(
            f"vulnsight ui: error: cannot listen on {HOST}:{arguments.port}: "
            f"{error.strerror or type(error).__name__}",
            file=sys.stderr,
        )

        return EXIT_COULD_NOT_START

    print(f"VulnSight dashboard: {server.url}")
    print("Press Ctrl+C to stop.")

    if not arguments.no_browser:
        try:
            webbrowser.open(server.url)
        except Exception:  # a missing browser must not stop the server
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
