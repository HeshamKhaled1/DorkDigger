# DorkDigger

DorkDigger is a Linux-friendly CLI tool for monitoring sensitive exposures via search dorks using DuckDuckGo or SerpAPI. It supports custom dorks, site scoping, simple result filtering, lightweight content checks for sensitive keywords, and saves alerts to TXT/JSON/CSV.

## Features
- Automated Google Dorking via SerpAPI  
- Passive reconnaissance without direct target interaction  
- Clean CLI interface with colors and banners  
- Lightweight and easy to run in a virtual environment  

## Quick install

Clone github repository:

```bash
git clone https://github.com/heshamkhaled1/DorkDigger.git
cd DorkDigger
```

Create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel (optional)
python -m pip install -r requirements.txt
```

Requirements: Python 3.8+ and the dependencies in requirements.txt.

## Run

Once installed, use the console command

### Get familiar with DorkDigger:
```bash
python3 DorkDigger.py --help
```

### Example quick run with DuckDuckGo and built‑in dorks:

```bash
python3 DorkDigger.py --max-results 10 --sleep 1 --out-prefix myalerts
```

Outputs:

- myalerts.txt: all found links
- myalerts.json: structured alerts
- myalerts.csv: alerts in CSV


## SerpAPI usage and key persistence

DorkDigger supports SerpAPI for Google or Bing engines. Provide the key one time, and DorkDigger will store it in a user-level config so future runs don’t need the flag again.

First run (saves the key for future runs):

```bash
python3 DorkDigger.py --serpapi-key <your-key>
```

Subsequent runs (no key flag required):

```bash
DorkDigger --engine serpapi --intext "password" --filetype sql --max-results 10 --sleep 1.5 --out-prefix test_alerts
```

Key resolution priority:

1) Command-line flag --serpapi-key (also saved for future runs)
2) Environment variable SERPAPI_KEY
3) Local SERPAPI_KEY.env file in the project directory
4) Previously saved user config (created automatically on first run with --serpapi-key)

Notes:

- To change the saved key, pass --serpapi-key again; it will overwrite the stored value.
- If only SERPAPI_KEY.env or SERPAPI_KEY environment variable is set, DorkDigger will use them without changing the saved config.
- For higher security, consider using an OS keyring; by default, the key is stored in a user config file.


## Useful options

Short Form    | Long Form         | Description
------------- | -------------     |-------------
-F            | --dorks-file      | File with one dork per line (falls back to dorks.txt if present)
-s            | --site            | Restrict to a site domain, e.g. --site example.com
-u            | --inurl           | Comma-separated URL substrings to require, e.g. --inurl "/admin,ssh"
-i            | --intext          | Add intext:… to every query, e.g. --intext "\"password\""
-I            | --intitle         | Add intitle:… to every query, e.g. --intitle "\"index of\""
-f            | --filetype        | Filetype filter, e.g. --filetype sql or --filetype "filetype:sql"
-S            | --sleep           | Throttle between queries (seconds)
-o            | --out-prefix      | Output prefix for TXT/JSON/CSV (default alerts)
-e            | --engine          | duckduckgo (default) or serpapi
-k            | --serpapi-key     | google (default) or bing (SerpAPI engine selector)
-E            | --serpapi-engine  | File with one dork per line (falls back to dorks.txt if present)


Examples:

- DuckDuckGo with a custom dorks file:

```bash
DorkDigger --dorks-file mydorks.txt --max-results 50 --sleep 1.2 --out-prefix dd_out
```

- SerpAPI Google engine with scoping and filters:

```bash
DorkDigger --engine serpapi --site example.com --inurl ".bak" --filetype "sql" --max-results 10 --sleep 1 --out-prefix ex_alerts
```

## Files and configuration

- dorks.txt: Optional list of dorks (one per line); comments start with \#.
- hide_keywords.txt: Domains/keywords to suppress from results.
- sensitive_config.py: Configure keywords, severity colors, and custom severity mapping.
- SERPAPI_KEY.env: Optional local file in KEY=VALUE format; example:

SERPAPI_KEY=YOUR_ACTUAL_KEY
- User config: The SerpAPI key provided via --serpapi-key is saved in a user-level config file so future runs don’t require the flag.


## Output format

- alerts.txt: All discovered links (unique list).
- alerts.json: Array of alert objects:
    - timestamp
    - dork
    - query
    - link
    - keyword
    - type
    - severity
- alerts.csv: Same fields in CSV header order.


## Tips

- Use --sleep to avoid throttling and to be polite to endpoints.
- The tool attempts a lightweight content fetch to identify sensitive keywords; increase coverage by adding custom terms to sensitive_config.py.
- Use --site and --inurl to constrain scope and reduce noise.


## License and credits
- [SerpAPI](https://serpapi.com/) for search automation  
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for parsing
- CLI with colorful output ([termcolor](https://github.com/ikalnytskyi/termcolor), [pyfiglet](https://github.com/pwaller/pyfiglet))
- Inspiration from OSINT & Reconnaissance methodologies  
- Inspired from [Sublist3r](https://github.com/aboul3la/Sublist3r)
- Author: Hesham Khaled
- GitHub: HeshamKhaled1
- LinkedIn: linkedin.com/in/deebo000
