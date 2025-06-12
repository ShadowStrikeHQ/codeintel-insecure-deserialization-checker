# codeintel-Insecure-Deserialization-Checker
Detects potential insecure deserialization vulnerabilities by analyzing code for usage of pickle or similar libraries without proper input validation. Focuses on identifying deserialization calls on untrusted data. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-insecure-deserialization-checker`

## Usage
`./codeintel-insecure-deserialization-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-e`: List of files or directories to exclude from analysis.
- `-o`: Path to output file for scan results.  If omitted, results will be printed to the console.

## License
Copyright (c) ShadowStrikeHQ
