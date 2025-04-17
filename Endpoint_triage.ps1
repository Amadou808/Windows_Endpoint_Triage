[string]$device_name  = $env:COMPUTERNAME 
[string]$date = (Get-Date -UFormat "D%Y-%m-%d T%H-%M-%S-UTC") 
[string]$log_dir_name = "$device_name-Log_Collection-$date" 
[string]$log_output_path= "C:\Users\Public\$log_dir_name" 
[array]$users = @((Get-ChildItem -Directory  "C:\Users\" | Select-Object -Property Name | Where-Object {$_.Name -ne 'public'}).Name) 


function Set-Log_folder {
    <#
    .SYNOPSIS
        This function checks if the Log collection folder exists or not. If it doesn't, it will create it.

    .DESCRIPTION
        Verifies if the Log collection folder exists or not. If the folder doesn't, it will create it.

    .EXAMPLE
        Set-Log_folder

    .PARAMETER None
        This function does not accept or require any parameters.
    #>

    # Error handling block
    try {
        # Checks if the Log Collection folder exists
        if (Test-Path -Path $log_output_path) {
            # Write the following message
            #Write-Host -ForegroundColor Green "The Log Collection Folder already exists here => $log_output_path"
        } else {
            # Write the following message and create the log collection folder if it doesn't exist
            #Write-Host -ForegroundColor Blue "Creating Log Collection Folder here => $log_output_path"
            New-Item -Path $log_output_path -ItemType Directory | Out-Null
        }
    } catch {
        # Display the Error Message
        Write-Error -Message $_.Exception.Message
    }
}
function Get-device_artifacts {

    <#
    .SYNOPSIS
            Captures and exports device-related artifacts to aid in device triage.

    .DESCRIPTION
        This function collects a some system information as well as user account data such as enabled local users and members of the local administrator group.
        
        The artifacts are combined and exported to a CSV file for further analysis.

    .EXAMPLE
        Get-device_artifacts

    .LINK 
        Reference for the security identifier of the default local administrator group:
    reference for the Security identifier of the Default local admin group
    .LINK https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    #>

    # Error Handling block
    try {
            # Creates a hashtable containing device details, including hostname, domain information, etc.
            $device_details = @{
                device_name = $env:COMPUTERNAME
                domain = [string]((Get-CimInstance -ClassName Win32_ComputerSystem).Domain -join ';')
                PartOfDomain = [string]((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain -join ';')
                Local_Ip = [string](((Get-NetIPConfiguration).IPv4Address.IpAddress) -join ';')
                Public_IP = ((Invoke-WebRequest -Uri 'https://api.ipify.org?format=json').Content | ConvertFrom-Json).ip
                Timezone = (Get-TimeZone).DisplayName
                Enabled_localUsers = [string]((Get-LocalUser | Where-Object {$_.Enabled -eq $TRUE}).Name -join ';')
            }
        
            # Retrieve the names of all local admin groups based on their security identifier (SID) and join them into a string.
            $admin_groups = @(Get-LocalGroup -SID 'S-1-5-32-544').Name -join ';'

            # Capture the names of all users in the default local admin groups.
            $local_admin_users = @(foreach ($group in $admin_groups) {
                (Get-LocalGroupMember -Name $group).Name -join ';'
            })
        
            # A hashtable to get all default local admin groups
            # Return all of the users/members in the local admin group 
            $groups = @{
                admin_groups = [string]$admin_groups
                local_admin_users = [string]$local_admin_users
            }
        
            # Combine the 2 hashtables results 
            $results = $device_details + $groups
        
            # Export the results to a csv file located in the log collection folder 
            $results | ConvertTo-Csv  | Out-File -LiteralPath "$log_output_path\device_and_user_details.csv"
    }
    catch {

        # Catch & Dispaly all errors
        Write-Error -Message $_.Exception.Message
        #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-device_artifacts"
    }

}
function Invoke-Triage {
    param(
        [Parameter(Mandatory=$False)] 
        [string]$Output = $log_output_path # Default value for $Output is set by the path variable.
    )

    <#
    .SYNOPSIS
        This function downloads a Velociraptor offline collector that leverages the Windows-event log fast forensics timeline generator and threat hunting tool called "Hayabusa" and other windows artifacts (e.g, Usn, ShellBags, Prefetch, JumpLists)

    .DESCRIPTION
        This Velociraptor offline collector runs the Windows-event log fast forensics timeline generator and threat hunting tool called "Hayabusa"

        This "Collector" runs on an endpoint against the default Windows-event log directory and returns a single CSV file for further analysis with excel, timeline explorer, etc.

        Hayabusa currently has over 4000 Sigma rules and over 170 Hayabusa built-in detection rules.

    .PARAMETER Output
        Specifies the path of the output directory

    .EXAMPLE
        Invoke-Triage -Output "C:\Windows\Temp"

    .EXAMPLE
        Invoke-Triage

    .LINK
        - https://github.com/Yamato-Security/hayabusa
        - https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/
    #>

    # The Url hosting the velociraptor offline collector
    $url = "https://drive.usercontent.google.com/download?id=1N1ElNj7m4KEX_MmsP70pDCNw4_YDpOIZ&export=download&confirm"

    # Get the current directory where the function is being executed.
    $current_dir = (Get-Location).Path

    Write-Host -ForegroundColor Green "Downloading the Velociraptor offline collector"
    # Download the Velociraptor binary to the current directory.
    
    Invoke-WebRequest -OutFile "$current_dir\Velo-Custom-Windows-Collector.exe" -Uri $url

    Write-Host -ForegroundColor Green "Running the Velociraptor offline collector"
    # Run the Velociraptor binary with administrator privileges in a hidden window and wait for it to complete.

    Start-Process -FilePath "$current_dir\Velo-Custom-Windows-Collector.exe" -Verb runas -WindowStyle Hidden -Wait
  
    Start-Sleep -Seconds 1

    # Extract the archive containing the collected results a new directory.

    try {
        Write-Host -ForegroundColor Green "Expanding the Archive collected results"

        Expand-Archive -Path "$current_dir\Velo-Custom-Windows-Collection-*.zip" -Destination "$current_dir\$device_name-Host-Triage_Collection"

        Start-Sleep -Seconds 1

        Write-Host -ForegroundColor Green "Copying the Files to => $Output"

        Get-ChildItem -Path "$current_dir\$device_name-Host-Triage_Collection\results" -Filter "*.csv" | Where-Object {$_.Length -gt 1} | Where-Object {$_.Name -ne "Windows.EventLogs.Hayabusa.Updated%2FUpload.csv" } | Move-Item -Destination $Output

        Start-Sleep -Seconds 3

        Write-Host -ForegroundColor Green "Deleting Un-Used files"

        Remove-Item -Recurse -Force -Path "$current_dir\Velo-Custom-Windows-Collection-*.zip", "$current_dir\Velo-Custom-Windows-Collector.exe.log", "$current_dir\$device_name-Host-Triage_Collection", "$current_dir\Velo-Custom-Windows-Collector.exe"
    }
    catch {
        Write-Error -Message $_.Exception.Message  
    }
 
}
function Get-WinAuthLogs {
    param(
        [Parameter(Mandatory=$False)] # This makes the parameter $d optional, because a default value or '30' is used
        [validateRange(1, 365)] # Ensures that the argument provided is only between 1 to 365 days
        [int]$d = 30 # Variable that sets a default value of 30 days if no input is provided.
        ) 

    <#

    .SYNOPSIS
        This function captures authentication related Event-ID from the Windows security logs
    
    .DESCRIPTION
        Collects authentication related Event-ID from the Windows security logs. Then enriches the Even-ID with a descriptions, to finally exporting the logs in a CSV file format.
    
    .PARAMETER d
        Number of days to look back for logs (default: 30)
        
    .EXAMPLE
        Get-WinAuthLogs -d 7 

    .EXAMPLE
        Get-WinAuthLogs
    
    .LINK 
        - https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j

        - https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-hashtable?view=powershell-7.5#custom-expressions-in-common-pipeline-commands 

    #>


    # The hashtable used to enrich the Event-IDs that will be caputred.
        $event_id_meaning = @{
            4624 = 'An account was successfully logged on'
            4625 = 'An account failed to log on'
            4648 = 'A logon was attempted using explicit credentials'
            4720 = 'A user account was created'
            4768 = 'A Kerberos authentication ticket (TGT) was requested'
            4769 = 'A Kerberos service ticket was requested'
            4770 = 'A Kerberos service ticket was renewed'
            4771 = 'Kerberos pre-authentication failed'
            4672 = 'Special privileges assigned to new logon (Assignment of Administrator Rights)'
            4776 = 'The domain controller attempted to validate the credentials for an account'
        }

    # Capture the authentication events from the Windows security logs while using some error-handling 
    try {

    # Captures Windows security logs and filter for authentication-related Event-IDs.
    # Further filter by specific Logon Type IDs and use the 'd' argument to search for logs up to X days back, then Select only the relevant properties for analysis.
        $auth_logs = get-WinEvent -LogName "Security" | Where-Object {$_.Id -in (4624,4625,4648,4720,4672,4771,4776,4768,4769,4770) -and $_.TimeCreated -ge (get-date).AddDays(-$d)} | Select-Object -Property TimeCreated,Id,MachineName,ProcessId,TaskDisplayName,Message

    # Enriched the authentication logs by adding a new property/field "ID_Description".
    # This field will cross-references the captured "Event-ID" from our query with the Hastable above.
    # The new field, "ID_Description," includes the corresponding "value" from the hashtable for the matched Event-ID.
        $Enriched_auth_logs = $auth_logs | Select-Object -Property TimeCreated,Id, @{Name='ID_Description'; Expression={$event_id_meaning[$_.Id]}},MachineName,ProcessId,TaskDisplayName,Message

    # Export the Enriched authetication logs in a CSV format to our log collection folder
        $Enriched_auth_logs | ConvertTo-Csv | Out-File -FilePath "$log_output_path\Auth_logs_last_$d`d.csv"
    }
    catch {

    # Catch & Dispaly all errors
        Write-Error -Message $_.Exception.Message
        #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-WinAuthLogs"
        
    }

        
}   
function Get-Network_auth_logs {
    param(
        [Parameter(Mandatory=$False)] # This makes the parameter $d optional, because a default value or '30' is used
        [validateRange(1, 365)] # Ensures that the argument provided is only between 1 to 365 days
        [int]$d = 30 # Variable that sets a default value of 30 days if no input is provided.
        ) 

    <#
    .SYNOPSIS
        This function captures remote authentication-related Event-IDs from the Windows security logs.
    
    .DESCRIPTION

        Collects authentication related Event-ID from the Windows security logs. Then enriches the Logon_type with a descriptions, to finally exporting the logs in a CSV file format.
    
    .PARAMETER d
        Number of days to look back for logs (default: 30)
        
    .EXAMPLE
        Get-Network_auth_logs -d 7 
        
    .EXAMPLE
        Get-Network_auth_logs

    .LINK 
        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j

    #>

    # The hashtable used to enrich the Logon-Type that will be caputred.
    $logon_id_meaning = @{
        3 = 'Logon Type: 3 - Network'
        4 = 'Logon Type: 4 - Batch (i.e.scheduled task)'
        5 = 'Logon Type: 5 - Service (Service startup)'
        8 = 'Logon Type: 8 - NetworkCleartext (Logon with credentials sent in the clear text.'
        10 = 'Logon Type: 10 - RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)'
    }

    # Capture the authentication events from the Windows security logs while using some error-handling 
    try {

    # Captures Windows security logs and filter for authentication-related Event-IDs.
    # Use regex to extract logs containing a valid Source IP address, excluding unwanted IPs.
    # Further filter by specific Logon Type IDs and use the 'd' argument to search for logs up to X days back, then Select only the relevant properties for analysis.
    $remote_logins = get-WinEvent -LogName "Security" | Where-Object {$_.Id -in (4624,4625,4648,4672,4771,4776,4768,4769,4770) -and $_.TimeCreated -ge (get-date).AddDays(-$d) -and $_.Message -match '(?i)(Source\sNetwork\sAddress\:\s*)((?!127|169|0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' -and $_.Message  -match '(Logon\sType\:\s+(3|4|5|8|10))'} | Select-Object -Property TimeCreated,Id,MachineName,ProcessId,TaskDisplayName,Message

    # Enriched the authentication logs by adding a new property/field "logon_type_id".
    # This field will cross-references the captured "Logon Type ID" from our query with the Hastable above.
    # The new field, "logon_type_id," includes the corresponding "value" from the hashtable for the matched "LogonType".
    $Enriched_network_auth_logs = $remote_logins | Select-Object -Property TimeCreated,Id,MachineName,ProcessId,TaskDisplayName,Message, @{Name='Logon_Type'; Expression={
        if ($_.'Message' -match 'Logon\sType\:\s+(3|4|5|8|10)')
        {
            $logon_type_id = [int]$matches[1]
            $logon_id_meaning[$logon_type_id]
        }
            }
    }
    
    # Export the Enriched authetication logs in a CSV format to our log collection folder
    $Enriched_network_auth_logs | ConvertTo-Csv | Out-File -FilePath "$log_output_path\Network_Auth_logs_last_$d`d.csv"
    }
    catch {
        # Catch & Dispaly all errors
        Write-Error -Message $_.Exception.Message
        #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-Network_auth_logs"    
        }
}
function Get-DefenderLogs {

    <#

    .SYNOPSIS
        This function captures the Windows Defender logs from a device
    
    .DESCRIPTION

        Collects Windows Defender logs from a device. Then enriches the Event-ID with a descriptions/meaning, to finally exporting the logs in a CSV file format.
    
    .EXAMPLE
        Get-DefenderLogs
    
    .LINK 
        https://graylog.org/post/critical-windows-event-ids-to-monitor/?
 
    #>

    # The hashtable used to enrich the Event-IDs that will be caputred.
    [hashtable]$event_id_mapping = @{
        1006 = 'malware or unwanted software detected'
        1116 = 'malware or unwanted software detected'
        1007 = 'action to protect system performed'
        1117 = 'action to protect system performed'
        1008 = 'action to protect system failed'
        1118 = 'action to protect system failed'
        1009 = 'item restored from quarantine'
        1012 = 'unable to delete item in quarantine'
        1015 = 'suspicious behavior detected'
        1119 = 'critical error occurred when taking action'
    }
    
    # Capture the Windows-Defender events from the Windows security logs while using some error-handling 
    try {

        # Captures Windows-Defender logs and filter for specific Event-IDs. Then Select only the relevant properties for analysis.
        $defenderLogs = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object {$_.Id -in @(1006,1116,1007,1117, 1008,1118, 1009,1012, 1015, 1119)} | Select-Object -Property TimeCreated, Id, ProcessId, MachineName, Message


        # Enriched the authentication logs by adding a new property/field "Event_Id_Description".
        # This field will cross-references the captured "ID" from our query with the Hastable above.
        # The new field, "Event_Id_Description," includes the corresponding "value" from the hashtable for the matched "Id".
        $Enriched_logs = $defenderLogs | Select-Object TimeCreated, Id, @{Name='Event_Id_Description'; Expression={ $event_id_mapping[$_.Id] }} ,ProcessId, MachineName, Message


        # Export the Enriched authetication logs in a CSV format to our log collection folder
        $Enriched_logs | ConvertTo-Csv | Out-File -FilePath "$log_output_path\DefenderLogs.csv" 
    }

    catch {
       # Catch & Dispaly all errors
       Write-Error -Message $_.Exception.Message
       #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-DefenderLogs"
    }
        
}
function Get-IIS_logs {

    <#
    
    .SYNOPSIS
        This function Collects the IIS logs from a server.
    
    .DESCRIPTION

        This function collects IIS log files from a server's log directory, filtering them for log files
        no older than 30 days. The logs are then copied to the Log collection folder.
    
    .EXAMPLE
        Get-IIS_logs
       
    #>


    # Error-handling Block
    try {

        # Variable  for the Default IIS logs path
        $iis_log_path = "C:\inetpub\logs\LogFiles"

        # Validate if the IIS log path exist then executed the commands between the {} brackets
        if (Test-Path -Path $iis_log_path){

            # Get all of the full path of the log files in the IIS logs folder.
            # Filter for only the log files that are no older than 30 days
            $log_files = (Get-ChildItem -Path $iis_log_path -Filter *.log | Where-Object { $_.CreationTime -ge (Get-Date).AddDays(-30) }).FullName
            
            # Loop trought all of the logs found and copy them to the Log collection folder
                foreach ($files in $log_files){Copy-Item -Path $files -Destination $log_output_path}
        }

        # If the IIS logs folder is not found show the error message. 
        else{
    
            Write-Error -Message $_.Exception.Message
            #Write-Host -ForegroundColor Yellow "No IIS logs were found"
        }
    }
    catch {
       # Catch & Dispaly all errors
       Write-Error -Message $_.Exception.Message
       #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-IIS_logs"
    }
    
}
function Get-listening_conn {

    <#
    
    .SYNOPSIS
        Retrieves active network connections that are in a 'Listen' or 'Established' state.
    
    .DESCRIPTION

        This function queries the device's active network connections, by filtering for those
        in the 'Listen' or 'Established' state. It excludes connections with a remote address of '0.0.0.0' or '::'. 
        Then exports the resutls to a CSV file for further analysis.
    
    .EXAMPLE
        Get-listening_conn

    #>

    # Error-handling Block
    try {

        # Query active network connections and filter for 'Listen' or 'Established' states
        # Exclude connections where the remote address is '0.0.0.0' or '::' and select relevant properties/fields
        # # Export the results to a CSV file in the Log collection folder
        Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' -and $_.RemoteAddress -notmatch ('(0.0.0.0|\:\:|127.0.0.1)') } | Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, OffloadState | ConvertTo-Csv | Out-File -FilePath "$log_output_path\Device_active_connections.csv"
    
    }
    catch {

    # Catch & Dispaly all errors that happened during the execution of the function
        Write-Error -Message $_.Exception.Message
        #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-listening_conn"
    }
    
}
function Get-ADS {

    <#
    .SYNOPSIS
        Scans user "Downloads" folders for files with ADS (Alternate Data Streams) and exports the Zone.Identifier stream information.

    .DESCRIPTION
        This function checks each file in the "Downloads" folders of all users on the system for the presence of the "Zone.Identifier" alternate data stream (ADS).
        The Zone.Identifier ADS contains information about the file's origin, such as whether it was downloaded from the internet, and it is often used by Windows to mark files as potentially unsafe.
        The function collects the Zone.Identifier data for each file and exports the results to a CSV file for further analysis.

    .LINK
        https://redcanary.com/threat-detection-report/techniques/mark-of-the-web-bypass/

    .EXAMPLE
        Get-ADS

    #>


    $files = foreach ($user in $users){(Get-ChildItem -Path "C:\Users\$user\Downloads\").FullName}


    # Check for Zone.Identifier data for each file in the users download folder 
    $output = foreach ($file in $files) {
        if ($file -and (Test-Path -Path $file)) {
            $stream = Get-Item -Path $file -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
            if ($stream) {
                $zoneContent = Get-Content -Path "${file}:Zone.Identifier" -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    File = [string]$file
                    ZoneInfo  = ($zoneContent -join "`n")
                }
            }
    }
    }

    # Export the results to a csv file
    $output | Export-Csv -Path "$log_output_path\ADS_ZoneIdentifiers.csv"
        
}
function Get-pwsh_history {

    <#
    .SYNOPSIS
        Captures PowerShell history files for all user profiles on a device.
    
    .DESCRIPTION
        This function iterates through all user profiles on the device and checks for PowerShell command history files located in the `PSReadLine` directory of each user's AppData folder. If history files are found, they are copied the log collections folder
        
    .EXAMPLE
        Get-pwsh_history

    #>

    # Error Handling Block
    try {
    # Iterate through all user profiles and look for PowerShell history files.
        foreach ($user in $users) {
            $historyPath = "C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*history*.txt"

            # Check if the history file exists for the current user.
            if (Test-Path -Path $historyPath) {
            
            # if the file is found, Copy the file the log collecitons folder
                Copy-Item -Path $historyPath -Destination $log_output_path
            }
        }
    }
    catch {
        # Catch & Dispaly all errors
        Write-Error -Message $_.Exception.Message
        #Write-Host -ForegroundColor Yellow "Something Went Wrong with the function Get-pwsh_history"
    }

}
function Get-downloaded_files {
    <#
    
    .SYNOPSIS
        Recursively Retrives info about files in the "Downloads" folder of all users on the device.
    
    .DESCRIPTION

        This function recursively scans the "Downloads" folder of each user on the device and collects information about the files within that folder. The results are then exported to a CSV file for further analysis.
    
    .EXAMPLE
        Get-downloaded_files

    #>
    
    # Error-handling Block
    try {

    # Loop thought each user's download folder and recursively caputure meta-data of each file. 
    $download_folder_file = foreach ( $user in $users){Get-ChildItem -Path "C:\Users\$user\Downloads" -Recurse | Select-Object  Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, IsReadOnly, Attributes, LinkType, LinkTarget, VersionInfo} 
    
    # Export the captured file details to a CSV file saved in the Log collection folder 
    $download_folder_file | ConvertTo-Csv | Out-File -FilePath "$log_output_path\Users_Download_folder.csv"
    }
    catch {
        # Catch and display any errors that occur during the execution of the function
        Write-Error -Message $_.Exception.Message
        #Write-Host -ForegroundColor Yellow "An error occurred while executing the Get-downloaded_files function."
    }

            
}
function Start-Compressions {

    <#
    .SYNOPSIS
        This function will Compress the Log collection folder.

    .DESCRIPTION
        The following function will Compress the Log collection folder, Delete the un-compressed folder 

    .PARAMETER None
        This function does not accept or require any parameters.
    
    .EXAMPLE
        Start-Compressions

    .LINK 
        - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.5
    #>

    # Error handling block
    try {
        # Hashtable with the arguments used by the "Compress-Archive" cmdlet
        $compress = @{
            Path = "$log_output_path"
            CompressionLevel = "Fastest"
            DestinationPath = "C:\Users\Public\$log_dir_name"
          }
          
        #Write-Host -ForegroundColor Yellow "Compressing the Directory"

        # Compress the log collection folder
        Compress-Archive @compress

        #Write-Host -ForegroundColor Yellow "Deleting the uncompress folder"

        # Deletes the un-compressed Log colleciton folder
        Remove-item -Recurse -Path $log_output_path
    }
    catch {
        # Display the Error Message
        #Write-Host -ForegroundColor Yellow "Unable to Compress the Directory"
        Write-Error -Message $_.Exception.Message
    }
}

try {
    Set-Log_folder
    Get-device_artifacts
    Get-pwsh_history
    Get-listening_conn
    Get-downloaded_files
    Get-ADS
    Get-WinAuthLogs
    Get-Network_auth_logs
    Get-DefenderLogs
    Get-IIS_logs
    Invoke-Triage
    Start-Compressions
}
catch {
    Write-Error -Message $_.Exception.Message  
}
