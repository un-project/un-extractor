import sys
import argparse
import logging

from un_extractor.extractor import Extractor
from un_extractor.version import __version__

VERSION = __version__
logger = logging.getLogger("un-extractor")


def main():
    parser = argparse.ArgumentParser(
        description="Extract UN General Assembly records from XML to JSON.",
        epilog="Examples:\n"
        "  un_extractor meeting.xml output.json\n"
        "  pdftohtml -xml meeting.pdf - | un_extractor > output.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile",
        nargs="?",
        type=argparse.FileType("r"),
        default=sys.stdin,
        help="XML input file (defaults to stdin)",
    )
    parser.add_argument(
        "outfile",
        nargs="?",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="JSON output file (defaults to stdout)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose output (debug logging)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress status messages",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate XML structure without extracting",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
        help="show program's version number and exit",
    )

    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger("un-extractor").setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger("un-extractor").setLevel(logging.ERROR)
    else:
        logging.getLogger("un-extractor").setLevel(logging.INFO)

    # Print status messages unless quiet mode
    if not args.quiet:
        print(f"un_extractor v{VERSION}")
        print("-" * 23)

    extractor = Extractor()
    try:
        infile_name = getattr(args.infile, "name", "<stdin>")

        if args.validate_only:
            # Validation only mode
            if not args.quiet:
                print(f"Validating '{infile_name}'...")
            is_valid = extractor.validate(args.infile)
            if is_valid:
                if not args.quiet:
                    print("✓ XML structure is valid")
                sys.exit(0)
            else:
                print(
                    "✗ XML structure validation failed (see details above)",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            # Full extraction mode
            extractor.extract(args.infile, args.outfile)
            if not args.quiet:
                outfile_name = getattr(args.outfile, "name", "<stdout>")
                print(f"✓ Done. Output written to '{outfile_name}'")

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except IOError as exc:
        print(f"Error reading/writing file: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc(file=sys.stderr)
        sys.exit(1)


# old usage() helper removed in favour of argparse's built-in help


# -------------------------------
if __name__ == "__main__":
    main()
