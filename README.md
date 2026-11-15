# orangetheory-export

Provides ability to extract personal historical data from your Orange Theory account for offline analysis.

List your Orangetheory classes and export per-class performance data: heart rate, treadmill speed, incline and distance, rower data, calories and splats over time. Export your benchmark results (1-mile, 2000 m row, Marathon Month and more) with their full history. You get CSV, JSON and an offline HTML chart, ready for a spreadsheet or an AI assistant.

This is a single Python file that uses only the standard library, so there is nothing to install beyond Python 3.9 or newer. It talks to the same unofficial endpoints the Orangetheory app uses, so it may break if OTF changes them.

> **Unofficial.** Not affiliated with or endorsed by Orangetheory Fitness. It uses your own account to access your own data.

## Quick start (no programming needed)

You'll type a few commands into a terminal window. You don't need to know anything else. Tip: you can copy and paste each command.

### 1. Install Python (one time)

- **Windows:** install Python from [python.org/downloads](https://www.python.org/downloads/) (or the Microsoft Store). In the python.org installer, tick **"Add python.exe to PATH"** on the first screen.
- **Mac:** install Python from [python.org/downloads](https://www.python.org/downloads/). Afterwards, open the **Python** folder in Applications and double-click **Install Certificates.command** (without this, logging in fails with `CERTIFICATE_VERIFY_FAILED`).
- **Android:** see [On Android (Termux)](#on-android-termux) below.

### 2. Download this tool (one time)

On this project's GitHub page, click the green **Code** button, then **Download ZIP**. Unzip it somewhere easy to find, such as your Documents folder. You'll get a folder named something like `orangetheory-export-main`.

### 3. Open a terminal in that folder

- **Windows 11:** open the folder in File Explorer, right-click an empty space and choose **Open in Terminal**. (Windows 10: click the address bar at the top of the folder window, type `powershell` and press Enter.)
- **Mac:** in Finder, right-click the folder and choose **New Terminal at Folder**. If you don't see it, open Terminal, type `cd ` (with a space), drag the folder into the Terminal window and press Enter.

### 4. Run it

Type the command and press Enter. On **Windows** commands start with `py`; on a **Mac** they start with `python3`. The examples below use `py`, so swap in `python3` on a Mac.

```
py otf_export.py list
```

The first time, it asks for your Orangetheory email and password (the same ones you use in the app). **The password doesn't appear as you type. That's normal.** Type it and press Enter. You stay logged in for about an hour, so later commands won't ask again.

You'll see a numbered list of your recent classes:

```
#  When              Class             Coach  Studio    Cal  Splat  Min
1  2026-11-14T07:15  Orange 60 Min 2G  Alex   Downtown  626  4      58
2  2026-11-12T18:00  Tread 50          Sam    Downtown  540  9      48
```

Then export what you want:

```
py otf_export.py export 1
```

Your files go into a new **`otf_exports`** folder inside the tool's folder. Double-click the `.html` file to see your report in your web browser: your stats, time in each zone, splat-point goal, heart-rate and speed charts, rower power, and a breakdown of each treadmill and rower block.

### What each command does

| Command | What it does |
|---|---|
| `py otf_export.py list` | Shows your classes from the last 60 days, numbered, newest first |
| `py otf_export.py list --days 120` | Same, but goes back 120 days |
| `py otf_export.py export 1` | Exports class number 1 from the list |
| `py otf_export.py export 1 2 5` | Exports classes 1, 2 and 5 |
| `py otf_export.py export latest` | Exports your most recent class (no need to run `list` first) |
| `py otf_export.py export all --days 30` | Exports every class from the last 30 days |
| `py otf_export.py export all --since 2023-03-01` | Exports every class since a date (write it as year-month-day) |
| `py otf_export.py benchmarks` | Exports your benchmark results (1-mile, 2000 m row, Marathon Month...) and every attempt |
| `py otf_export.py logout` | Logs you out (deletes the saved login) |
| `py otf_export.py --help` | Shows all the options |

Handy extras you can add to any export:

- `--out "C:\Users\you\Desktop\OTF"` saves the files somewhere else (keep the quotes if the path has spaces). On a Mac: `--out ~/Desktop/OTF`.
- `--format html` writes only the HTML reports (or `csv`, or `csv,html`).

A full-history export can take a while. If it stops partway (internet drops, laptop sleeps), just run the same command again: it skips classes it already downloaded.

### If something goes wrong

| You see | What to do |
|---|---|
| `'py' is not recognized` (Windows) or `command not found` (Mac) | Python isn't installed, or on Windows "Add python.exe to PATH" wasn't ticked. Re-run the Python installer and tick it. You can also try `python` instead of `py` |
| `can't open file ... otf_export.py` | The terminal isn't in the tool's folder. Go back to step 3 |
| `Incorrect username or password` | Check your Orangetheory email and password. They're the ones you use in the app |
| `CERTIFICATE_VERIFY_FAILED` (Mac) | Run **Install Certificates.command** from the Python folder in Applications |
| `no telemetry - HR monitor probably not connected` | That class has no heart-rate data, usually because your monitor wasn't paired. Nothing to fix |
| Some classes `FAILED` | Run the same command again: it only retries the failed ones |

### Opening the files

- **`.html`**: your class report. Double-click to open it in your browser. It works offline.
- **`.csv`**: opens in Excel, Numbers or Google Sheets. One row every few seconds of the class.
- **`classes_summary.csv`** (written when you export more than one class): one row per class. This is the best file to open in a spreadsheet, or to give to an AI assistant like Claude to ask questions about your training.

## Platforms

| Platform | Notes |
|---|---|
| Windows | Tested on Windows 11 with Python 3.14: `py otf_export.py list` |
| macOS | Should work (not yet tested): `python3 otf_export.py list`. With the python.org installer, run its "Install Certificates" step if you see `CERTIFICATE_VERIFY_FAILED` |
| Linux | `python3 otf_export.py list`, including a Raspberry Pi |
| Android | Via [Termux](https://f-droid.org/packages/com.termux/), see below |

Tested on Linux with Python 3.9, 3.11, 3.12 and 3.13, on Windows 11 with Python 3.14, and on Android in Termux.

## On Android (Termux)

1. Install **Termux** from F-Droid (the Play Store build is outdated).
2. In Termux:
   ```sh
   pkg install python git
   termux-setup-storage            # lets Termux write to your Downloads folder
   git clone https://github.com/matosconsulting/orangetheory-export.git
   cd orangetheory-export
   ```
3. Run it:
   ```sh
   python otf_export.py list                    # last 60 days (--days 120 for more)
   python otf_export.py export 1                # numbers from the list
   python otf_export.py export 1 2 5 --out ~/storage/downloads/otf
   python otf_export.py export latest
   python otf_export.py export all --days 30
   python otf_export.py export all --since 2023-03-01 --points 150   # full history
   termux-open ~/storage/downloads/otf/<file>.html   # view the chart
   python otf_export.py benchmarks --out ~/storage/downloads/otf   # 1-mile, 2k row, DriTri... + every attempt
   ```
   You'll be asked for your OTF email and password, or you can set `OTF_EMAIL` and `OTF_PASSWORD`. Only the 1-hour login token is cached, in `~/.otf_export/token.json`. `python otf_export.py logout` deletes it.

## Output per class

| File  | Contents |
|-------|----------|
| `.csv`  | One row per sample: `seconds, time, hr, hr_zone, tread_speed_mps, tread_incline_pct, tread_distance_m, row_speed_mps, row_spm, row_watts, row_pace_s_per_500m, row_distance_m, calories, splats`. Telemetry is always metric (m/s, metres), whatever units your app shows. Multiply m/s by 2.237 for mph, or by 3.6 for km/h. |
| `.json` | Raw API responses (class info, performance summary, telemetry) |
| `.html` | Stats cards, splat-goal progress and time in each zone (with your bpm ranges), a chart of HR (with zone bands) against treadmill and rower speed, rower power with HR, and a table of each treadmill/rower block |

When you export more than one class, two combined files are also written. These are the ones to hand to Claude or a spreadsheet:

| File | Contents |
|------|----------|
| `classes_summary.csv` | One row per class: date, class, coach, calories, splats, avg/peak HR, minutes in each zone, treadmill and rower totals |
| `all_telemetry.csv` | Every sample from every class, with `class_id, class_start, class` columns added |

`--combined` forces these files for a single class; `--no-combined` turns them off.

**Interrupted runs resume.** Each class is saved to `<out>/.otf_cache/` as soon as it downloads, so re-running the same command (same `--out` and `--points`) skips classes already fetched and only downloads the rest. Dropped connections and server errors are retried automatically, with waits of up to a minute. `--refresh` forces a full re-download.

`--points N` sets the sample count. The app uses 150; the default here is 600 for finer detail. `--format csv` limits which files are written. `--debug` saves every raw API response to `~/.otf_export/raw/`, which is useful if a field comes back empty.

## Benchmarks

`benchmarks` writes four files:

| File | Contents |
|------|----------|
| `benchmarks_summary.csv` | One row per benchmark: best, last and previous result, unit, number of attempts, first and last attempt dates |
| `benchmarks_history.csv` | One row per attempt: date, result, unit, class, coach, studio |
| `challenge_totals.csv` | One row per multi-session challenge (Marathon Month, Hell Week...): sessions, total distance, goal |
| `benchmarks_raw.json` | Raw benchmark and challenge-tracker responses |

## Testing

The test suite runs offline against a local mock server: no Orangetheory account and nothing to install.

```sh
python tests/test_otf_export.py        # Windows: py tests\test_otf_export.py
```

It ends with `ALL TESTS PASSED`, or stops with an error at the first failure.

## How it works

It signs in with your own Orangetheory account and reads the same data the Orangetheory app shows you. For the technical details of the API, see [otf-api](https://github.com/NodeJSmith/otf-api).

## Credits

- **[otf-api](https://github.com/NodeJSmith/otf-api)** by Jessica Smith (MIT licence) is the full-featured Python client for the Orangetheory API, and the inspiration for this tool. Everything here about the endpoints, the Cognito login setup and the shape of the responses was learned from reading its source. If you want a library rather than a single-file exporter, use otf-api.
- **[pycognito](https://github.com/pvizeli/pycognito)** by Pascal Vizeli and contributors, based on **[warrant](https://github.com/capless/warrant)** (both Apache License 2.0). The Cognito SRP login code is adapted from pycognito's `aws_srp.py`; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

MIT; see [LICENSE](LICENSE). The Cognito login code is adapted from Apache-2.0 licensed code; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
