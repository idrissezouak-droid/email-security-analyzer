# Email Security Analyzer

## Description

Email Security Analyzer is a Python tool that analyzes raw emails and detects suspicious security indicators.

The program analyzes email headers and the email body, calculates a heuristic risk score, and generates a security report.

## Features

* Parses raw email data
* Analyzes email headers
* Checks SPF, DKIM, and DMARC results
* Detects differences between the sender and Reply-To address
* Detects suspicious or urgent language
* Extracts the sender domain
* Extracts URLs from the email body
* Calculates a heuristic risk score
* Classifies the email as LOW, MEDIUM, or HIGH risk
* Generates a security report

## How to Run

Make sure you are inside the project directory:

```bash
cd email-security-analyzer
```

Run the program:

```bash
python project.py
```

The program analyzes the email stored in `email.txt`.

After the analysis, you can choose whether to generate a security report.

## Testing

The project uses `pytest` for testing.

Run:

```bash
pytest
```

The tests cover the main functions used by the email analyzer.

## Project Structure

```text
email-security-analyzer/
│
├── project.py
├── test_project.py
├── email.txt
├── requirements.txt
└── README.md
```

## Risk Score

The risk score is based on detected security indicators such as:

* SPF failure
* DKIM failure
* DMARC failure
* Different Reply-To address
* Urgent or suspicious language

The score is a **heuristic indicator** and does not prove that an email is malicious.

## Technologies

* Python
* Regular Expressions (`re`)
* Python Email Package
* pytest

## CS50P

This project was developed as the final project for **CS50's Introduction to Programming with Python**.
