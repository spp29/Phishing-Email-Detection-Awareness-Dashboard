# Phishing Email Detection & Awareness Dashboard

## Overview

The **Phishing Email Detection & Awareness Dashboard** is a defensive cybersecurity project designed to analyze email information and identify indicators commonly associated with phishing.

The application provides an explainable risk assessment instead of relying on a single indicator. It analyzes information such as the sender, email content, URLs, and attachments and presents the detected security indicators to the user.

The project is designed for cybersecurity education and defensive analysis using synthetic or authorized data.

---

## Problem Statement

Phishing emails use social-engineering techniques to manipulate users into clicking suspicious links, opening unsafe attachments, or providing sensitive information.

Traditional users may have difficulty identifying these indicators manually.

This project provides a simple dashboard that helps users analyze email characteristics and understand why an email may be suspicious.

---

## Objectives

The main objectives of this project are:

- Analyze email sender information
- Analyze email subject and body content
- Detect urgency and manipulation language
- Identify credential and personal-information requests
- Analyze URLs using static inspection
- Identify suspicious URL characteristics
- Analyze attachment filenames safely
- Generate an explainable phishing risk score
- Classify analyzed emails according to their risk
- Provide security recommendations
- Demonstrate defensive cybersecurity concepts
- Provide a user-friendly web interface
- Provide an API for email analysis

---

## Key Features

### Email Analysis

The system analyzes:

- Sender information
- Subject
- Email body
- URLs
- Attachment filenames

### Phishing Indicators

The application can identify indicators such as:

- Urgent language
- Account verification requests
- Credential-related requests
- Suspicious sender patterns
- Suspicious URL structures
- Non-HTTPS URLs
- Raw IP-address URLs
- Account or verification-related URL terms
- Potentially risky attachment extensions

### Explainable Detection

Instead of displaying only a classification, the system provides explanations for the detected indicators.

For example:

```text
Risk Score: 100/100

Classification: Likely Phishing

Risk Level: High

Findings:
- Suspicious sender pattern
- Urgency detected
- Credential request detected
- Suspicious URL detected
- Risky attachment extension detected