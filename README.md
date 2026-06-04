# SQLiHunter

A fast and lightweight SQL injection vulnerability scanner built in Go that uses [Katana](https://github.com/projectdiscovery/katana) for crawling and detecting parameterized endpoints.

## Features

- **Automated crawling** using Katana to discover parameterized endpoints
- **Multi-threaded scanning** for faster testing
- **Database error detection** for MySQL, PostgreSQL, Oracle, SQLite, and MSSQL
- **Configurable options** for timeout and thread count
- **Output to file** for reporting and further analysis

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) 1.21+
- [Katana](https://github.com/projectdiscovery/katana)

### Install Katana

```bash
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

### Build SQLiHunter

```bash
git clone https://github.com/yourusername/SQLiHunter.git
cd SQLiHunter
go build -o sqliscanner .
```

## Usage

```bash
./sqliscanner -u <target_url> [-o output_file] [-t threads] [-timeout seconds] [-d depth] [-v]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL to scan (required) | - |
| `-o` | Output file for results (optional) | - |
| `-t` | Number of concurrent threads | 10 |
| `-timeout` | Request timeout in seconds | 10 |
| `-d` | Crawling depth (0 = no depth limit) | 3 |
| `-v` | Verbose output - show all discovered endpoints | false |

### Examples

```bash
# Basic scan with default depth
./sqliscanner -u https://example.com

# Verbose scan to see all endpoints found
./sqliscanner -u https://example.com -v

# Unlimited depth crawling
./sqliscanner -u https://example.com -d 0

# Scan with output file and more threads
./sqliscanner -u https://example.com -o results.txt -t 50 -timeout 30
```

## How It Works

1. **Crawling Phase**: The tool uses Katana to crawl the target website and extract all URLs containing query parameters
2. **Parameter Extraction**: Identifies all unique parameters from discovered endpoints
3. **Injection Testing**: Tests each parameter with SQL injection payloads
4. **Vulnerability Detection**: Analyzes responses for database error messages indicating potential SQL injection

## Detection Patterns

The scanner detects errors from:
- MySQL (`sql syntax`, `mysql`, `Warning.*mysql`)
- PostgreSQL (`pg::`, `postgresql`)
- Oracle (`ora-\d{5}`, `plsql`)
- SQLite (`sqlite`, `sqlite3::`)
- Microsoft SQL Server (`sqlstate\[HY\d{3}\]`, `Microsoft SQL Server`)

## Warning

**Use this tool responsibly and only on systems you own or have explicit permission to test.** Unauthorized scanning may violate laws and regulations.

## License

MIT License
