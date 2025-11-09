<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/aycasanli8/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string ‘tor’ in it and discovered what looks like the user “Cyberlearner” (employee) downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and creation of a file called “tor-shopping-list.txt” on the desktop at 2025-11-07T20:04:54.817508Z. These events began at: 2025-11-07T19:19:24.4469712Z.

**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName == "threat-hunt-lab"
|where InitiatingProcessAccountName == "cyberlearner"
|where FileName contains "tor"
|where Timestamp >= datetime(2025-11-07T19:19:24.4469712Z)
|order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1407" height="442" alt="image" src="https://github.com/user-attachments/assets/a936add1-92a7-493d-9895-291827f25dbb" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-15.0.exe”. Based on the logs returned, at 2025-11-07T19:21:49.1665888Z, an employee on the “threat-hunt-lab” device ran the file tor-browser-windows-x86_64-portable-15.0.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
|where DeviceName == "threat-hunt-lab"
|where InitiatingProcessAccountName == "cyberlearner"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1473" height="330" alt="image" src="https://github.com/user-attachments/assets/468871e5-bdcd-4c2f-b118-ac729b4d6ada" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that “Cyberlearner” (employee) actually opened the tor browser. There was evidence that they did open it at 2025-11-07T19:22:19.0031004Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.
Query to locate events:

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName == "threat-hunt-lab"
|where InitiatingProcessAccountName == "cyberlearner"
|where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc
```
<img width="1452" height="495" alt="image" src="https://github.com/user-attachments/assets/276071b8-bbb2-4f6c-bce1-9b0384f6f8bf" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of known tor ports. At 2025-11-07T19:23:18.853709Z, an employee on the “threat-hunt-lab” device successfully established a connection to the remote IP address 152.53.34.99 on port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\cyberlearner\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName == "threat-hunt-lab"
|where InitiatingProcessAccountName == "cyberlearner"
|where InitiatingProcessAccountName != "system"
|where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
|where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
|project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc
```
<img width="1462" height="485" alt="image" src="https://github.com/user-attachments/assets/7139403c-d31a-45e5-8710-43226b856c87" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** 2025-11-07T19:19:24.4469712Z
- **Event:** The user “Cyberlearner” downloaded a file named tor-browser-windows-x86_64-portable-15.0.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:**  C:\Users\cyberlearner\Downloads\tor-browser-windows-x86_64-portable-15.0.exe

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** 2024-11-08T22:16:47.4484567Z
- **Event:** The user “Cyberlearner” executed the file tor-browser-windows-x86_64-portable-15.0.exe in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** tor-browser-windows-x86_64-portable-15.0.exe /S
- **File Path:**  C:\Users\cyberlearner\Downloads\tor-browser-windows-x86_64-portable-15.0.exe

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** 2025-11-07T19:22:19.0031004Z
- **Event:** User “Cyberlearner” opened the TOR browser. Subsequent processes associated with TOR browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** C:\Users\cyberlearner\Desktop\TorBrowser\Browser\TorBrowser\Tor\tor.exe

### 4. Network Connection - TOR Network

- **Timestamp:** 2025-11-07T19:23:18.853709Z
- **Event:** A network connection to IP 152.53.34.99 on port 9001 by user “Cyberlearner” was established using tor.exe, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** tor.exe
- **File Path:** C:\Users\cyberlearner\Desktop\TorBrowser\Browser\TorBrowser\Tor\tor.exe

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamp:**
2025-11-07T12:23:00Z - Connected to 64.65.62.101 on port 443.
2025-11-07T12:23:00Z - Local connection to 127.0.0.1 on port 9150.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user “Cyberlearner” through the TOR browser.
- **Action:** Multiple successful connections detected.


### 6. File Creation - TOR Shopping List

- **Timestamp:** 2025-11-07T13:04:00Z
- **Event:** The user “Cyberlearner” created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** C:\Users\cyberlearner\Desktop\tor-shopping-list.txt

---

## Summary

The user “Cyberlearner” on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on endpoint threat-hunt-lab by the user “Cyberlearner”. The device was isolated and the user's direct manager was notified.

---
