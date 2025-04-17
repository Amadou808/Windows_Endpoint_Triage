# Windows_Endpoint_Triage

**Purpose:** The PowerShell script automates the initial triage and log collection process on Windows-based devices during incident response investigations. This expedited data-gathering process is critical for:
- Identifying potential Indicators of Compromise (IOCs),
- Understanding the scope of an incident,
- Facilitating timely containment and remediation efforts

  
#### **Usage:** 

*Command*
`powershell <Script>`

`iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))`
`iex ((iwr 'https://example.com/cont/dir/dropper_script.txt' -UseBasicParsing).Content)`

#### **Analysis**
The script generates several CSV files for further analysis. Among them, the **Hayabusa** output is the most useful for quickly identifying relevant security events.

**Hayabusa** is a Windows Event Log forensics timeline generator and threat hunting tool. It includes:
- 4,000+ Sigma detection rules
- 170+ built-in Hayabusa rules
These rules analyze logs from `C:\Windows\System32\winevt\Logs` and produce CSV output with event criticality levels ranging from informational to critical.

#### **Tools**
[Timeline Explorer](https://www.sans.org/tools/timeline-explorer/): Recommended for analyzing CSV log files efficiently.

### Items collected
- **Custom Velociraptor Collection:** Gathers a comprehensive set of forensic artifacts including:
    - File system change history (USN Journal)
    - User folder interaction history (Shellbags)
    - User account information (SAM)
    - Application execution evidence (Prefetch)
    - `certutil.exe` usage
    - Recently accessed files (Jump Lists, LNK files)
    - Persistence Artifacts  (Autoruns)
    - Alternate Data Streams (C:\\)
    - PowerShell persistence mechanisms
    - Event log analysis (Hayabusa)
    - Browser history and extensions (Chrome, Edge, Firefox)
    - Evidence of execution and download
    - Binary renaming and forwarded imports
    - Lateral movement indicators
#### **Additional Data**
- **PowerShell History:** Copy of the PowerShell history file.
- **Active Connections:** Current network connections in 'Listen' or 'Established' states.
- **Downloaded Files Metadata:** Details of files in the user's download folder.
- **Mark-of-the-Web Data:** Origin details for downloaded files.
- **Windows Authentication Logs (30 Days):** User login security logs.
- **Network Authentication Logs (30 Days):** Security logs for network-based logins.
- **Defender Logs:** Microsoft Defender events, especially malware detections.
- **IIS Logs (30 Days, if available):** Web server logs for potential web-based attacks.
