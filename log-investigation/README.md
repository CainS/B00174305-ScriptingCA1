CA1 - Security Log Investigation

Scenario: Build a small SOC-style analysis tool that turns the supplied firewall and authentication logs into a clear investigation summary. 

Features: 
Interactive Menu - Using a while loop will allow the user to step through the script manually or silently run the whole script for a saved output.

Each Option does the following:
Log Parsing - Loads the data
Analysis - Calculates the statistics
Correlation - Checks ahainst the threat list
Risk Assessment - Generates the findings
Reporting - saves information to file types .json & .txt

Folder Structure: 
data/           Supplied data for tool
output/         Saved reports
index.py        Source code
README.md       Project instructions
