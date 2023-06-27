# GreenButton-Reliant

Command-line tool to export GreenButton data from Reliant's website.

* Please open an issue or pull request if you encounter issues.

## Usage

Usage: `main.py [OPTIONS] [FILE_PATH]`

* `[FILE_PATH]` - Output file save path [default: GreenButtonData.csv]

Options

|\* = required|Description|
|-|-|
|\* `--email` TEXT|Reliant account email `[required]`|
|`--password` TEXT|Reliant account password|
|`-sz`, `--save-zip`|Export a ZIP archive instead of a CSV|
|`--help`|Show this message and exit.|
