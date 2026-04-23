# THM_Windows-Security-Monitoring

## Table of Contents
1. [Windows Logging for SOC](#windows-logging-for-soc)

## Windows Logging for SOC
### What is Logged
1. Looking at the last screenshot, which event ID describes a successful login? (Answer format: LogSource / ID, e.g. Application / 8194)

    For the LogSource, we can see it in the left panel. The answer is `Security / 4624`.

### Security Log: Authentication
1. Open the "Practice-Security.evtx" file on the VM's Desktop. Which IP performed a brute force of the THM-PC?

    We can click `filter current log` in the right panel and filter by `Event ID` 4625, which describes a failed login. We can see that the IP address `10.10.53.248`.

2. Which user has been breached as a result of the attack?

    We can filter by `Event ID` 4624, which describes a successful login, and filter by the attacker ip address.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        *[System[(EventID=4624)]
        and
        EventData[Data[@Name='IpAddress']='10.10.53.248']]
        </Select>
    </Query>
    </QueryList>
    ```
    The user that has been breached is `Administrator`.

3. What was the Logon ID of the malicious RDP login? Note: The login you are looking for has a Logon Type 10.

    We can filter by `Event ID` 4624, which describes a successful login, and filter by the attacker ip address and logon type.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        *[System[(EventID=4624)]
        and
        EventData[Data[@Name='IpAddress']='10.10.53.248']
        and
        EventData[Data[@Name='LogonType']='10']
        </Select>
    </Query>
    </QueryList>
    ```
    The user that has been breached is `Administrator`.

3. What was the Logon ID of the malicious RDP login? Note: The login you are looking for has a Logon Type 10.

    We can filter by `Event ID` 4624, which describes a successful login, and filter by the attacker ip address and logon type.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        *[System[(EventID=4624)]
        and
        EventData[Data[@Name='IpAddress']='10.10.53.248']
        and
        EventData[Data[@Name='LogonType']='10']]
        </Select>
    </Query>
    </QueryList>    
    ```
    The user that has been breached is `0x183C36D`.

### Security Log: User Management
1. Continue with the "Practice-Security.evtx" file on the VM's Desktop.Which user was created by the attacker soon after the RDP login?

    We can filter by `Event ID` 4720, which describes a user account creation, and filter by the Logon ID of the malicious RDP login (SubjectLogonId).

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        *[System[(EventID=4720)]
        and
        EventData[Data[@Name='SubjectLogonId']='0x183C36D']]
        </Select>
    </Query>
    </QueryList>    
    ```
    The user that was created by the attacker is `svc_sysrestore`.

2. Which two privileged groups was the backdoor user added to? (Answer in alphabetical order, e.g. "Administrators, Power Users")

    We can filter by `Event ID` 4732, which describes a user being added to a group, and filter by the Logon ID of the malicious RDP login (SubjectLogonId).


    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Security.evtx">
            *[System[(EventID=4732)]
            and
            EventData[Data[@Name='SubjectLogonId']='0x183C36D']]
            </Select>
    </Query>
    </QueryList>
    ```
    The answer is `Backup Operators, Remote Desktop Users`.

3. Does the Logon ID field match what you saw in the previous task (Yea/Nay)?

    The answer is `Yea` since we have already applied the filter by Logon ID in the previous question.

### Sysmon: Process Monitoring
1. Open the "Practice-Sysmon.evtx" file on the VM's Desktop. Which web browser does Sarah use to browse the web?

    To find the answer, we can filter by `Event ID` 1, which describes a process creation, and filter by the user name `Sarah`.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
            *[System[(EventID=1)]
            and
            EventData[Data[@Name='User']='THM-PC\sarah.miller']]
        </Select>
    </Query>
    </QueryList>
    ```
    The web browser that Sarah uses is `Google Chrome`.

2. Which file did Sarah download from the browser?

    We can use the same filter as the previous question and analyze the `ParrentCommandLine` or `ParrentImage` and `CurrentDirectory` field to find the file that Sarah downloaded. The answer is `C:\Users\sarah.miller\Downloads\ckjg.exe`.

3. Which URL was the file downloaded from? Note: Use other Sysmon events to find out!

    We can filter by `Event ID` 15, which describes to track Alternate Data Streams (ADS).

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
            *[System[(EventID=15)]
            and
            EventData[Data[@Name='User']='THM-PC\sarah.miller']]
        </Select>
    </Query>
    </QueryList>
    ```
    The URL that the file was downloaded from is `http://gettsveriff.com/bgj3/ckjg.exe`.

### Sysmon: Files and Network
1. Continue with the "Practice-Sysmon.evtx" file on the VM's Desktop. Which file was created by the downloaded malware to persist on the host?

    We can filter by `Event ID` 11, which describes a file creation, and filter by the user name `Sarah`. 

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
            *[System[(EventID=11)]
            and
            EventData[Data[@Name='User']='THM-PC\sarah.miller']]
        </Select>
    </Query>
    </QueryList>
    ```
    Once we apply the filter, we can look at the `Image` field that have value `ckjg.exe` (We have found it in the previous question). Then, we can look at the `TargetFilename` field to find the file that was created by the downloaded malware. The answer is `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`. We also now the `ProcessId` of the malware that created the file, which is `1460`. We can use this `ProcessId` to find other events that are related to the malware, such as network connection events.

2. What is the Command & Control server malware connected to? (Answer in format IP:Port, e.g. 1.1.1.1:80)

    We can filter by `Event ID` 3, which describes a network connection, and filter by the user name `Sarah`.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
            *[System[(EventID=3)]
            and
            EventData[Data[@Name='User']='THM-PC\sarah.miller']]
        </Select>
    </Query>
    </QueryList>
    ```
    Once we apply the filter, we can look at the `Image` field that have value `ckjg.exe` (We have found it in the previous question). Then, we can look at the `DestinationIp` and `DestinationPort` fields to find the Command & Control server that the malware connected to. The answer is `193.46.217.4:7777`.

3. Finally, which domain does the malicious IP correspond to?

    We can filter by `Event ID` 22, which describes a DNS query, filter by the user name `Sarah`, and filter by the `ProcessId` of the malware that we found in the previous question.

    ```xml

    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice-Sysmon.evtx">
            *[System[(EventID=22)]
            and
            EventData[Data[@Name='User']='THM-PC\sarah.miller']
            and
            EventData[Data[@Name='ProcessId']='1460']
            ]
        </Select>
    </Query>
    </QueryList>
    ```

    Once we apply the filter, we can look at the `QueryName` field to find the domain that the malicious IP corresponds to. The answer is `hkfasfsafg.click`.

### Powershell: Logging Command
1. Review the Administrator's PS history on the attached VM. Which PowerShell command was executed first?

    We can use this command to read the PowerShell history file:

    ```powershell
    Get-Content C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
    ```

    The first PowerShell command that was executed is `Get-ComputerInfo`.

2. When did the Administrator run the first PS command? (Format: April 18, 2025). Note: You might need to right-click the history file and open "Properties" to get the answer!

    We can right-click the `ConsoleHost_history.txt` file and open "Properties" to find the creation date of the file, which is `May 18, 2025`.

3. Can you find the flag stored in the PowerShell history? (Format: THM{...}). Note: You might want to check the PS history of other local users!

    There are several users like `thm.alex` and `thm.bob`. We can examine each of their PowerShell history files to find the flag. 


    ```powershell
    Get-Content C:\Users\thm.bob\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
    ```
    The answer is `THM{it_was_me!}`.