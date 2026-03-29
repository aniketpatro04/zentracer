# 🌐 Domain Network Diagnostic Tool

A lightweight Python CLI tool for inspecting domain network information — including IP resolution, response time, and HTTP headers.

---

## Features

- **DNS Resolution** — Resolves a domain to its IPv4 and IPv6 addresses
- **Response Time Measurement** — Measures how long the server takes to respond to an HTTP GET request
- **HTTP Header Inspection** — Displays all response headers returned by the server

---

## Requirements

- Python 3.x
- [`uv`](https://docs.astral.sh/uv/) — fast Python package and project manager

---

## Setup

This project uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency management.

**1. Install uv** (if you haven't already):

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**2. Create a virtual environment and install dependencies:**

```bash
uv venv
uv pip install requests
```

**3. Activate the virtual environment:**

```bash
# macOS / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

---

## Usage

Run the script from your terminal:

```bash
python main.py
```

You will be prompted to enter a domain name:

```
Enter the Domain name to Trace: https://example.com
```

The tool accepts URLs in any of these formats:

- `https://example.com`
- `http://example.com`
- `example.com`

---

## Sample Output

```
Enter the Domain name to Trace: https://example.com

########## IP Address Info ##########
{'IPv4': '93.184.216.34', 'IPv6': '2606:2800:21f:cb07:6820:80da:af6b:8b2c', 'Port_v4': 0, 'Port_v6': 0}


########## Response Time ##########
0.342 seconds


########## Header Info ##########
Content-Type : text/html; charset=UTF-8
Date : Sun, 29 Mar 2026 10:00:00 GMT
...
```

---

## Functions

| Function | Description |
|---|---|
| `get_domain_user_input()` | Prompts the user for a domain and sanitizes the input, returning both the clean hostname and the original URL |
| `get_ip_info(domain)` | Resolves the domain using `socket.getaddrinfo` and returns the first available IPv4 and IPv6 addresses along with their port numbers |
| `get_response_time(url)` | Sends an HTTP GET request and returns the elapsed time in seconds |
| `print_header_info(url)` | Sends an HTTP GET request and prints all response headers as key-value pairs |

---

## Known Limitations

- **Port number always returns `0`** — `socket.getaddrinfo` is called without a specific port or service, so the port defaults to `0` (null). This means no actual port/service information is resolved. A separate TCP ping (e.g. using `curl` or `socket.connect`) is needed to check whether a specific port is open.
- **No timeout handling** — HTTP requests in `get_response_time` and `print_header_info` have no timeout set, which may cause the script to hang on unresponsive servers.
- **HTTP only** — The tool does not validate SSL certificates or handle redirects explicitly.

---

## Planned Improvements (V2)

- [ ] TCP ping to check if specific ports are open (e.g. 80, 443)
- [ ] Return usable ports and active services per IP address
- [ ] Add request timeout handling
- [ ] Support for WHOIS and traceroute integration

---

## License

This project is open source and available under the [MIT License](LICENSE).