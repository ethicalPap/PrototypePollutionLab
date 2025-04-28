# JavaScript Prototype Pollution Lab

An interactive educational lab for learning about prototype pollution vulnerabilities in JavaScript applications.

![JavaScript Security](https://img.shields.io/badge/Security-Prototype%20Pollution-red)
![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-ff4b4b)
![Educational](https://img.shields.io/badge/Purpose-Educational-blue)

## Overview

This Streamlit-based lab provides a hands-on environment for developers to learn about and practice identifying JavaScript prototype pollution vulnerabilities. Prototype pollution is a security vulnerability that occurs when an attacker is able to manipulate the prototype of JavaScript objects, potentially leading to security issues like privilege escalation, remote code execution, and application crashes.

## Features

- **Interactive Playground:** Experiment with different JSON payloads to see how they can pollute objects
- **Real-world Examples:** Examine vulnerabilities that have affected popular libraries like lodash and jQuery
- **Prevention Techniques:** Learn different methods to protect against prototype pollution
- **Challenge Lab:** Practice identifying and fixing vulnerabilities in realistic code samples
- **Comprehensive Answer Key:** Solutions for all challenges with detailed explanations

## Installation

1. Clone this repository:
```bash
git clone https://github.com/ethicalPap/PrototypePollutionLab.git
cd prototype-pollution-lab
```

2. Install required dependencies (its recommended to run this in python venv):
```bash
python -m venv venv
./venv/Scripts/activate
pip install -r ./requirements.txt
```

3. Run the application:
```bash
streamlit run app.py
```

## Lab Sections

### 1. Introduction to Prototype Pollution

Learn the fundamentals of JavaScript's prototype-based inheritance and how prototype pollution occurs.

### 2. Interactive Playground

Experiment with different payloads to see prototype pollution in action. Test your own JSON inputs and see how they affect the application state.

### 3. Real-world Examples

Study actual vulnerabilities that have affected popular JavaScript libraries:
- lodash (CVE-2019-10744)
- jQuery $.extend()
- Express applications

### 4. Prevention Techniques

Learn secure coding practices to prevent prototype pollution:
- Using `Object.create(null)`
- Checking for dangerous property names
- Using `Object.hasOwnProperty.call()`
- JSON Schema validation
- Safe alternatives to deep merging

### 5. Challenge Lab

Test your understanding with practical coding challenges:
- Identify vulnerabilities in sample code
- Write secure implementations
- Explore interactive demonstrations of successful attacks

## Security Principles Covered

- **Input Validation:** Properly validate and sanitize user input
- **Secure Object Creation:** Create objects without prototype chains
- **Safe Property Access:** Use proper methods to check property ownership
- **Immutability:** Prevent modifications to sensitive objects
- **Defense in Depth:** Apply multiple protective techniques

## Answer Key

An answer key is provided for all challenges, including:
- Detailed vulnerability analysis
- Multiple secure implementation approaches
- Common vulnerability patterns to watch for
- Protection checklists
- Real-world examples with CVE references

## Educational Purpose

This lab is intended for educational purposes to help developers understand and prevent prototype pollution vulnerabilities. All code examples and challenges are designed to demonstrate security concepts in a safe environment.

## Acknowledgments

- OWASP for their Prototype Pollution Prevention Cheat Sheet
- Security researchers who have identified and responsibly disclosed prototype pollution vulnerabilities