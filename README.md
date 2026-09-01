# windows-process-investigation-splunk

# Windows Process Investigation Using Splunk and Sysmon

## Overview

This project demonstrates a basic Windows process investigation using Sysmon and Splunk.

The investigation focuses on process creation activity, PowerShell execution, parent-child process relationships, users, and command-line activity.

## Objective

The objective of this project was to learn how a SOC analyst can use endpoint telemetry to investigate process execution and identify activity that may require further investigation.

## Tools Used

- Windows
- Sysmon
- Splunk
- PowerShell

## Investigation Flow

Windows
↓
Sysmon
↓
Splunk
↓
SPL queries
↓
Process investigation

## Sysmon Event Used

### Event ID 1 - Process Creation

Sysmon Event ID 1 records information about newly created processes.

Important fields investigated in this project included:

- Image
- CommandLine
- ParentImage
- User
- ProcessId
- ParentProcessId
- UtcTime

## Investigation

### 1. Identifying a specific process

The first step was to search for the `notepad.exe` process that was manually executed on the Windows machine.

```spl
index=* "notepad.exe"
