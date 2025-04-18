# Windows_Endpoint_Triage

**Purpose:** The PowerShell script automates the initial triage and log collection process on Windows-based devices during incident response investigations. This expedited data-gathering process is critical for:
- Identifying potential Indicators of Compromise (IOCs),
- Understanding the scope of an incident,
- Facilitating timely containment and remediation efforts

  
#### **Usage:** 

*Command*
  `powershell <Script>`

OR

  `iex ((iwr "https://raw.githubusercontent.com/Amadou808/Windows_Endpoint_Triage/refs/heads/main/Endpoint_triage.ps1" -UseBasicParsing).Content)`

#### **Analysis**
The script generates several CSV files for further analysis. Among them, the **Hayabusa** output is the most useful for quickly identifying relevant security events.

**Hayabusa** is a Windows Event Log forensics timeline generator and threat hunting tool. It includes:
- 4,000+ Sigma detection rules
- 170+ built-in Hayabusa rules
These rules analyze logs from `C:\Windows\System32\winevt\Logs` and produce CSV output with event criticality levels ranging from informational to critical.

#### **Tools**
[Timeline Explorer](https://www.sans.org/tools/timeline-explorer/): Recommended for analyzing CSV log files efficiently.

#### **Items collected**

  1. **File System Change History (USN Journal)**: Tracks changes to files and directories on NTFS volumes.
  2. **User Folder Interaction History (Shellbags)**: Records user interactions with folders, useful for tracking user activity.
  3. **User Account Information (SAM)**: Contains user account details and password hashes.
  4. **CertUtil Usage**: Can be used to download files or encode/decode data, often seen in malicious activities.
  5. **Jump Lists & LNK Files**: Track recently accessed files and applications.
  6. **Alternate Data Streams (ADS)**: Hidden data streams within files, often used by malware.
  7. **PowerShell Persistence Mechanisms**: Methods used to maintain persistence via PowerShell profiles and registry entries.
  8. **Event Log Analysis (Hayabusa)**: Analyzes Windows event logs for suspicious activities.
  9. **Browser History and Extensions**: Tracks user browsing activity and installed extensions.
  10. **IIS Logs**: Logs from Internet Information Services, useful for web server activity analysis.
  11. **Evidence of Execution and Download**: Tracks execution and download activities.
  12. **Binary Rename & Forwarded Imports**: Techniques used to evade detection.
  13. **Lateral Movement Indicators**: Signs of lateral movement within a network.
  14. **Startup Items**: Applications set to Registry Run Keys  & StartUP Folder Directories
  15. **Permanent WMI Events**: WMI-based persistence mechanisms.

#### **Additional Data**:
  - **PowerShell History**: Commands executed in PowerShell.
  - **BITS Jobs**: Background Intelligent Transfer Service jobs, often used for downloading files.
  - **Scheduled Tasks**: Tasks scheduled to run on the system.
  - **Downloaded Files Metadata**: Details of files in the download folder.
  - **Mark-of-the-Web Data**: Origin details for downloaded files.
  - **Authentication Logs**: Logs of user and network-based logins.
  - **Defender Logs**: Microsoft Defender events, including malware detections.
  - **IIS Logs**: Web server logs for potential web-based attacks. Files no older than 30 days.
