# Azure IP Range Extractor

This project extracts and consolidates Azure Service Tag IP ranges for use in WireGuard or other network configurations.

## Features
- Downloads the latest Azure Service Tags JSON if not present
- Extracts all IPv4 subnets
- Consolidates overlapping/adjacent subnets
- Outputs a minimized list for use in WireGuard AllowedIPs

## Usage

1. Ensure you have Python 3.7+ installed.
2. (Recommended) Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Run the script:
   ```bash
   python extract_azure_ips.py
   ```
   Or with custom output:
   ```bash
   python extract_azure_ips.py -o tmp/azure_ips.txt
   ```

## Docker
You can also run the script in a container:
```bash
docker-compose run --rm azure-ip-extractor
```

## Output
- The consolidated list will be saved in `tmp/azure_ips.txt` by default.

## License
This project is licensed under the MIT License.

