APK Analyzer 🛡️

APK Analyzer is a Python-based tool for static analysis of Android APKs. It extracts metadata, checks permissions, and identifies security risks.
🚀 Features

    Extracts permissions, activities, services, and receivers.
    Detects exported components for security assessment.
    Performs static code analysis using Bandit & Semgrep.
    Generates detailed reports in TXT/JSON format.

🔧 Installation

    Clone the repository:

git clone https://github.com/yourusername/apk-analyzer.git  
cd apk-analyzer  

Install dependencies:

    pip install -r requirements.txt  

📄 Analysis Reports

This repository includes two JSON and TXT reports, which are the outputs of running APK Analyzer on two different APKs:

    zarchiver_analysis.json & zarchiver_analysis.txt
    simple_calculator_analysis.json & simple_calculator_analysis.txt

These reports provide detailed insights into permissions, security risks, and exported components found in each analyzed APK
