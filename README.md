# F5 BIG-IQ AS3 Export

This repository contains scripts for exporting AS3 configurations from an F5 BIG-IQ system. The configurations can be output to either a CSV or JSON file, and include Role-Based Access Control (RBAC) considerations.

## Prerequisites

- Python 3.x
- Required Python packages are listed in `requirements.txt`. Install them using:

  ```bash
  pip install -r requirements.txt
  ```

## Usage

1. Clone the repository:

   ```bash
   git clone <repository-url>
   ```

2. Navigate to the repository directory:

   ```bash
   cd <repository-directory>
   ```

3. Run the script with the required arguments:

   ```bash
   python __main__.py --username <BIG-IQ-username> --password <BIG-IQ-password> --hostname <BIG-IQ-host>
   ```

   If any arguments are omitted, the script will prompt you to input them.

## Logging

Logs are stored in the `logs/f5_as3.log` file. Console output is also configured for logging important information.

## Disabling SSL Warnings

SSL warnings are disabled using the `urllib3` library to prevent clutter in the logs.

## Functions

- **`parse_command_line_arguments()`**: Parses and handles command line arguments.
- **`global_token_auth()`**: Manages authentication token retrieval and caching.
- **`bigiq_http_get(uri, params)`**: Performs HTTP GET requests to the BIG-IQ API.
- **`main()`**: Orchestrates the export process, including retrieving and parsing application data.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
