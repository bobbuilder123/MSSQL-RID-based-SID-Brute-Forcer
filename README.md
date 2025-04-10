# MSSQL-RID-based-SID-Brute-Forcer

mssql-sid-brute: Identify MSSQL users and groups via SID brute-force enumeration

This tool connects to a Microsoft SQL Server using Impacket's TDS module and brute-forces RIDs based on a resolved domain SID to identify valid users and groups. It works similarly to Impacket tools and supports output to file, configurable ranges, delays, and auto-parsing of standard `domain/user:pass@host` formats.

## Installation

```
git clone https://github.com/bobbuilder123/MSSQL-RID-based-SID-Brute-Forcer.git
cd MSSQL-RID-based-SID-Brute-Forcer
python3 -m pip install -r requirements.txt
```

If you encounter issues with Impacket, try:

```
sudo apt install python3-impacket
```

Or install directly from the official GitHub:

```
pip install git+https://github.com/fortra/impacket.git
```

## Usage

```
python3 mssql-sid-brute.py domain/user:password@host [options]
```

### Required
- `domain/user:pass@host` - authentication string (Windows auth only)
- `-target-ip` - optional if IP is same as hostname

### Options

```
-target-ip       IP address of the MSSQL server (default: hostname)
--known-user     Known domain user to extract base SID from (default: Administrator)
--start-rid      Starting RID to brute-force (default: 500)
--end-rid        Ending RID to brute-force (default: 10001)
--delay          Delay (in seconds) between RID queries (default: 0.0)
--output         File to write discovered usernames/groups (appends if file exists)
```

## Example

Brute-force RIDs 500–550 on host `domain1.local`, saving results to `output.txt`:

```
python3 mssql-sid-brute.py DC/SQLGuest:'password123'@domain1.local -target-ip 10.10.10.10 --start-rid 500 --end-rid 2000 --output output.txt
```

Output:
```
[*] Domain SID: 010500000000000515000000a185deefb22433798d8e847af40
[+] RID 500 → WIN-Q13O90G\Administrator
[+] RID 512 → DOMAIN1\Domain Admins
```

## Output File Format

The `--output` option stores results line by line. Each line contains:

```
<username or groupname>
```

## Notes
- This tool uses `SUSER_SID()` and `SUSER_SNAME()` to resolve principals.
- Only accounts visible to the SQL Server context are resolvable.
- Domain SID is inferred from a known user such as `Administrator` or `SQLGuest`.

## License

This tool is released under the Apache2 License.

## Credits

Built with Impacket by Fortra (https://github.com/fortra/impacket)