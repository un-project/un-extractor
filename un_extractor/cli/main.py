import sys
import argparse

from un_extractor.extractor import Extractor
from un_extractor.version import __version__

VERSION = __version__


def main():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]")
    parser.add_argument(
        "infile", nargs="?", type=argparse.FileType("r"), default=sys.stdin
    )
    parser.add_argument(
        "outfile", nargs="?", type=argparse.FileType("w"), default=sys.stdout
    )

    parser.add_argument(
        "--version",
        dest="version",
        action="store_true",
        help="Display version information",
        default=False,
    )

    args = parser.parse_args()

    if args.version:
        usage()

    print("un_extractor - an extractor for general assembly records (v. %s)" % VERSION)
    print("-----------------------")
    extractor = Extractor()
    extractor.extract(args.infile, args.outfile)
    print("...done")


def usage(error=None):
    print(" -------------------------------------------------------------------")
    print(
        " un_extractor - extract data from general assembly records (v. %s)" % VERSION
    )
    print(" ")
    print(" un_extractor <xml> <json> [options]")
    print(" use -h to see options")
    print(" -------------------------------------------------------------------")
    if error:
        print("ERROR: %s" % error)
    sys.exit(" ")


# -------------------------------
if __name__ == "__main__":
    main()
