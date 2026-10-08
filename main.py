"""Command-line entry point for SOC Log Triage."""

import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Turn Suricata and auth.log events into a prioritised triage report."
    )
    parser.add_argument("--suricata", metavar="PATH", help="path to a Suricata eve.json file")
    parser.add_argument("--auth", metavar="PATH", help="path to a Linux auth.log file")
    parser.add_argument("--out", metavar="PATH", help="where to write the Markdown report")
    return parser.parse_args()


def main():
    parse_args()
    print("not implemented yet")


if __name__ == "__main__":
    main()
