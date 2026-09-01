# Windows Process Investigation Using Splunk and Sysmon

## Overview

This project demonstrates a basic Windows process investigation using Sysmon and Splunk.

The purpose was to understand how process creation activity can be collected, searched, and investigated using endpoint telemetry.

---

## Objective

The objective of this project was to investigate Windows process execution and understand how a SOC analyst can use Sysmon and Splunk to examine:

- Process creation
- PowerShell activity
- Parent-child process relationships
- Command-line activity
- User activity

---

## Tools Used

- Windows
- Sysmon
- Splunk
- PowerShell

---

## Investigation Architecture

Windows
↓
Sysmon
↓
Splunk
↓
SPL Queries
↓
Process Investigation

---

## Sysmon Event ID 1 — Process Creation

Sysmon Event ID 1 records information about newly created processes.

Important fields investigated during this project included:

- Image
- CommandLine
- ParentImage
- User
- ProcessId
- ParentProcessId
- UtcTime

---

# Investigation

## 1. Identifying a Specific Process

A `notepad.exe` process was manually executed on the Windows machine.

The following SPL query was used to locate the process:
```spl
index=* "notepad.exe"
```
## 2. Extracting Process Information

The following query was used to extract important process information from the raw Sysmon event:
```spl
index=* "notepad.exe"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| table _time Image ParentImage CommandLine
```
This allowed the process, its parent process, and its command line to be viewed in a more readable format

## 3. PowerShell Investigation

PowerShell activity was generated manually and investigated using Sysmon process creation events.
```spl
index=*
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| search Image="*powershell.exe"
| table _time User Image ParentImage CommandLine
| sort - _time
```
This query provides visibility into:

When PowerShell executed
Which user executed it
Which process launched it
What command was executed
Screenshot

## 4. Parent-Child Process Analysis

Parent-child process relationships were analyzed to understand which processes were responsible for launching other processes.
```spl
index=*
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| stats count by ParentImage Image
| sort - count
```
## Conclusion

This project demonstrated that the process name alone is not enough to determine whether activity is malicious.

Process investigation requires examining context such as:

Parent process
Command line
User
Execution time
Process relationships

PowerShell itself is not inherently malicious. Its execution context and behavior must be investigated.
