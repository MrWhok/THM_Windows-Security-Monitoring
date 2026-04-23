# THM_Windows-Security-Monitoring

## Table of Contents
1. [Windows Logging for SOC](#windows-logging-for-soc)
2. [Windows Threat Detection 1](#windows-threat-detection-1)

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

## Windows Threat Detection 1
### Intro to Initial Access
1. Which MITRE technique ID describes Initial Access via a vulnerable mail server?

    The answer is `T1190`. This is `Exploit Public-Facing Application` technique.

2. Which Initial Access method relies on a user opening a malicious email attachment?

    The answer is `Phishing`.

### Initial Access via RDP
1. Which user seems to be most actively brute-forced by botnets?

    We can filter the Security log by `Event ID` 4625, which describes a failed login, and look at the `Account Name` field to find which user is most actively brute-forced by botnets. We need to look at same user that have many failed logins in the short period of time. The answer is `Administrator`.

2. Which IP managed to breach the host via RDP (Logon Type 10)?

    We can filter the Security log by `Event ID` 4624, which describes a successful login, and filter by `Logon Type` 10 to find which IP managed to breach the host via RDP. 

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice\RDP Case\RDP-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice\RDP Case\RDP-Security.evtx">
        *[
        System[(EventID=4624)]
        and
        EventData[Data[@Name='LogonType']='10']
        ]</Select>
    </Query>
    </QueryList>
    ```
    The IP that managed to breach the host via RDP is `203.205.34.107`.

3. Can you get the real Workstation Name (hostname) of the threat actor?

    We can filter the Security log by `Event ID` 4624, which describes a successful login, and filter by `Logon Type` 3 to find the real Workstation Name (hostname) of the threat actor.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice\RDP Case\RDP-Security.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice\RDP Case\RDP-Security.evtx">
        *[
        System[(EventID=4624)]
        and
        EventData[Data[@Name='LogonType']='3']
        ]</Select>
    </Query>
    </QueryList>
    ```
    The real Workstation Name (hostname) of the threat actor is `DESKTOP-QNBC4UU`.

### Initial Access via Phishing
1. Let's play the role of the untrained user and mindlessly open the COM file. Run the www.skype.com file from the Phishing Case 1 folder, which flag do you get?

    The flag that we get is `THM{misleading_extension}`.

2. Continue with the second attachment from the Phishing Case 2 folder. From which URL does the malicious LNK download the next stage malware?

    We can solve this by right-clicking the LNK file and click `properties`. Then, we can look at the `Target` field to find the URL that the malicious LNK download the next stage malware from. The answer is `http://wp16.hqywlqpa.thm:8000/cgi-bin/f`.

3. Finally, move on to the Phishing Case 3 folder and review its content. What is the name of the double-extension file you see there?

    The name of the double-extension file is `best-cat.jpg.exe`.

### Continuing Phising Topic
1. Which file did the user download via the web browser?

    We can filter the Sysmon log by `Event ID` 11, which describes a file creation. The answer is `C:\Users\Administrator\Downloads\top-cats.zip`.

2. In which folder did the user unarchive the suspicious file?

    We can continue with the same filter and look at the `TargetFilename` field to find the folder that the user unarchive the suspicious file. The answer is `C:\Users\Administrator\Pictures`. The suspicious file is `C:\Users\Administrator\Pictures\best-cat.jpg.exe`, since it uses a double extension.

3. What is the process ID of the launched phishing malware?

    We can filter the Sysmon log by `Event ID` 1, which describes a process creation, and look at the `Image` field to find the process ID of the launched phishing malware. The answer is `5484` for `best-cat.jpg.exe`.

4. Finally, which malicious domain did the malware try to connect to?

    We can filter the Sysmon log by `Event ID` 3, which describes a network connection, and filter by the process ID of the launched phishing malware.

    ```xml
    <QueryList>
    <Query Id="0" Path="file://C:\Users\Administrator\Desktop\Practice\Phishing Case 3\Phishing-Sysmon.evtx">
        <Select Path="file://C:\Users\Administrator\Desktop\Practice\Phishing Case 3\Phishing-Sysmon.evtx">
        *[
        System[(EventID=22)]
        and
        EventData[Data[@Name='ProcessId']='5484']
        ]</Select>
    </Query>
    </QueryList>
    ```
    The malicious domain that the malware try to connect to is `rjj.store`.

### Initial Access via USB
1. Which USB file was launched by the user?

    We can filter the Sysmon log by `Event ID` 1, which describes a process creation, and look at the `Image` field to find which USB file was launched by the user. The answer is `E:\Open Sandisk 4GB USB.exe`.

2. Which suspicious file did the malware drop to the disk?(Format: full path to the file, e.g. C:\file.txt)

    Based on the previous question, the USB process has `ProcessId` 1108. We can filter the Sysmon log by `Event ID` 11, which describes a file creation, and filter by the `ProcessId` of the USB process. The answer is `C:\Users\Public\Documents\winupdate.exe`.

3. To which other USB did the malware propagate?(Format: just the letter, e.g. X:)

    We can filter the Sysmon log by `Event ID` 11, which describes a file creation, and look at the `TargetFilename` field to find the USB drive to which the malware propagated. The answer is `F:`.

