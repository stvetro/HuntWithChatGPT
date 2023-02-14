<#
.Synopsis
   Extracts events with ID 7045 from System log and enriches data with OpenAI API (text-davinci-003)
.DESCRIPTION
   Extracts events with ID 7045 from System log and enriches data with OpenAI API (text-davinci-003)
.EXAMPLE
   Get-ChatGPTServiceIoC -apiKey XXX 
.EXAMPLE
   Get-ChatGPTServiceIoC -apiKey XXX -Verbose -SkipWarning
#>
function Get-ChatGPTServiceIoC
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential

    )

    Begin
    {

        if($ComputerName -and (-not $Credential)){
            $Credential = get-credential
        }

        if($ComputerName){
            Write-Warning "Checking Service installations on $($ComputerName)"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="system";id=7045}  -computername $ComputerName  -credential $Credential
        }
        else{
            Write-Warning "Checking Service installations"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="system";id=7045}
        }

        $user_mode_service_events = $events | Where-Object {$_.Properties[2].Value  -ne "kernel mode driver"} | Where-Object {$_.Properties[2].Value  -ne "драйвер режима ядра"}
        $events_count = $user_mode_service_events.Count
        "Found " + $events_count +" events to check" | Out-Host
    }
    Process
    {
        $i = 0
        foreach ($service in $user_mode_service_events) {

            try {
                    $i += 1
                    Write-Progress -Activity "Processing" -CurrentOperation $i -PercentComplete (($i / $events_count) * 100)
                     
                    $ServiceName = $service.Properties[0].Value
                    $Servicecmd = $service.Properties[1].Value
                    $service | Add-Member -MemberType NoteProperty -Name 'ServiceName' -Value $ServiceName
                    $service | Add-Member -MemberType NoteProperty -Name 'Servicecmd' -Value $Servicecmd

                    
                    if ($ServiceName -or $Servicecmd) {
                        $result = Get-ChatGPTResult -apiKey $apiKey -prompt "Is following Windows service name '$ServiceName' with following Launch String '$Servicecmd' - an indicator of compromise? Think about it step by step."
                    }
                    else {
                        $result = "Empty string"
                    }

                    
                    $service | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value $result

            }

            catch {
                Write-Warning "Error processing event $($service)" 
                $service | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value "Error"
            }
        }
    }

    End
    {
        Write-Warning "Following Indicators of compromise were identified in service installation logs:"
        $user_mode_service_events | Where-Object { $_.ChatGPT -match "Yes" } | ForEach-Object {
            "TimeCreated: " + $_.TimeCreated | Out-Host
            "Id: " + $_.Id | Out-Host
            "ServiceName: " + $_.ServiceName | Out-Host
            "Servicecmd: " + $_.Servicecmd | Out-Host 
            "ChatGPT Response:" + $_.ChatGPT | Out-Host 
            "" | Out-Host 
        }

        $user_mode_service_events

    }
}


<#
.Synopsis
   Get running processes and their corresponding commandlines and enriches data with OpenAI API (text-davinci-003)
.DESCRIPTION
   Get running processes and their corresponding commandlines and enriches data with OpenAI API (text-davinci-003)
.EXAMPLE
   Get-ChatGPTRunningProcessesIoC -apiKey XXX 
.EXAMPLE
   Get-ChatGPTRunningProcessesIoC -apiKey XXX -Verbose -SkipWarning
#>
function Get-ChatGPTRunningProcessesIoC
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential

    )

    Begin
    {

        if($ComputerName -and (-not $Credential)){
            $Credential = get-credential
        }

        if($ComputerName){
            Write-Warning "Checking Running Processes on $($ComputerName)"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $processes = Invoke-Command -Authentication Negotiate -computername $ComputerName  -credential $Credential {Get-WmiObject Win32_Process}  
        }
        else{
            Write-Warning "Checking Running Processes"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $processes = Get-WmiObject Win32_Process
        }

        $events_count = $processes.Count
        "Found " + $events_count +" events to check" | Out-Host
    }
    Process
    {
        $i = 0
        foreach ($process in $processes) {

            try {
                    $i += 1
                    Write-Progress -Activity "Processing" -CurrentOperation $i -PercentComplete (($i / $events_count) * 100)
                    
                    # Get the command line for the process
                    $commandLine = $process.CommandLine
                    $path = $process.Path

                    

                    if ($commandLine -or $path) {
                        $result = Get-ChatGPTResult -apiKey $apiKey -prompt "Is the combination of process '$path' and command line '$commandLine' is an indicator of compromise? Think about it step by step."
                    }
                    else {
                        $result = "Empty string"
                    }
                    
                    $process | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value $result

            }

            catch {
                Write-Warning "Error processing event $($process)" 
                $process | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value "Error"
            }
        }
    }

    End
    {
        Write-Warning "Following Indicators of compromise were identified in running processes:"
        $processes | Where-Object { $_.ChatGPT -match "Yes" } | ForEach-Object {
            "ProcessId: " + $_.ProcessId | Out-Host
            "Path: " + $_.Path | Out-Host
            "CommandLine: " + $_.CommandLine | Out-Host 
            "ChatGPT Response:" + $_.ChatGPT | Out-Host 
            "" | Out-Host 
        }


        $processes

    }
}

<#
.Synopsis
   Extracts events with ID 4688 from Security log and enriches data with OpenAI API (text-davinci-003)
.DESCRIPTION
   Extracts events with ID 4688 from Security log and enriches data with OpenAI API (text-davinci-003)
.EXAMPLE
   Get-ChatGPTProcessCreationIoC -apiKey XXX 
.EXAMPLE
   Get-ChatGPTProcessCreationIoC -apiKey XXX -Verbose -SkipWarning
#>
function Get-ChatGPTProcessCreationIoC
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential

    )

    Begin
    {
        if($ComputerName -and (-not $Credential)){
            $Credential = get-credential
        }

        if($ComputerName){
            Write-Warning "Checking Process Creations on $($ComputerName)"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="Security";id=4688}  -computername $ComputerName  -credential $Credential
        }
        else{
            Write-Warning "Checking Process Creations"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="Security";id=4688}
        }

        $events_count = $events.Count
        "Found " + $events_count +" events to check" | Out-Host
    }
    Process
    {
        $i = 0
        foreach ($event in $events) {

            try {
                    $i += 1
                    Write-Progress -Activity "Processing" -CurrentOperation $i -PercentComplete (($i / $events_count) * 100)

                    $xmlevent = [xml]$event.ToXML()

                    try {
                        $ProcessPath = $xmlevent.Event.SelectSingleNode("//*[@Name='NewProcessName']")."#text"
                    }
                    catch {
                        $ProcessPath = ""
                    }
                    try {
                        $Processcmdline = $xmlevent.Event.SelectSingleNode("//*[@Name='CommandLine']")."#text"
                    }
                    catch {
                        $Processcmdline = ""
                        
                    }
                    try {
                        $ParentProcess = $xmlevent.Event.SelectSingleNode("//*[@Name='ParentProcessName']")."#text"
                    }
                    catch {
                        $ParentProcess = ""
                    }


                    $event | Add-Member -MemberType NoteProperty -Name 'ProcessPath' -Value $ProcessPath
                    $event | Add-Member -MemberType NoteProperty -Name 'Processcmdline' -Value $Processcmdline
                    $event | Add-Member -MemberType NoteProperty -Name 'ParentProcess' -Value $ParentProcess

                    if ($ProcessPath -or $Processcmdline -or $ParentProcess) {
                        $result = Get-ChatGPTResult -apiKey $apiKey -prompt "Is following Windows process '$ProcessPath' launched with following commandline '$Processcmdline' by following parent process '$ParentProcess'  - an indicator of compromise? Think about it step by step."
                    }
                    else {
                        $result = "Empty string"
                    }
                     
                    $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value $result

            }

            catch {
                Write-Warning "Error processing event $($event)" 
                $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value "Error"
            }
        }
    }

    End
    {
        Write-Warning "Following Indicators of compromise were identified in process creation logs:"
        $events | Where-Object { $_.ChatGPT -match "Yes" } | ForEach-Object {
            "TimeCreated: " + $_.TimeCreated | Out-Host
            "Id: " + $_.Id | Out-Host
            "ProcessPath: " + $_.ProcessPath | Out-Host
            "ParentProcess: " + $_.ParentProcess | Out-Host
            "Processcmdline: " + $_.Processcmdline | Out-Host
            "ChatGPT Response:" + $_.ChatGPT | Out-Host 
            "" | Out-Host 
        }

        $events

    }
}


<#
.Synopsis
   Extracts events with ID 1 from Sysmon log and enriches data with OpenAI API (text-davinci-003)
.DESCRIPTION
   Extracts events with ID 1 from Sysmon log and enriches data with OpenAI API (text-davinci-003)
.EXAMPLE
   Get-ChatGPTSysmonProcessCreationIoC -apiKey XXX 
.EXAMPLE
   Get-ChatGPTSysmonProcessCreationIoC -apiKey XXX -Verbose -SkipWarning
#>
function Get-ChatGPTSysmonProcessCreationIoC
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential

    )

    Begin
    {

        if($ComputerName -and (-not $Credential)){
            $Credential = get-credential
        }

        if($ComputerName){
            Write-Warning "Checking Sysmon Process Creations on $($ComputerName)"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=1} -computername $ComputerName  -credential $Credential
        }
        else{
            Write-Warning "Checking Sysmon Process Creations"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=1}
        }

        $events_count = $events.Count
        "Found " + $events_count +" events to check" | Out-Host
    }
    Process
    {
        $i = 0
        foreach ($event in $events) {

            try {
                    $i += 1
                    Write-Progress -Activity "Processing" -CurrentOperation $i -PercentComplete (($i / $events_count) * 100)

                    $xmlevent = [xml]$event.ToXML()

                    try {
                        $ProcessPath = $xmlevent.Event.SelectSingleNode("//*[@Name='Image']")."#text"
                    }
                    catch {
                        $ProcessPath = ""
                    }
                    try {
                        $Processcmdline = $xmlevent.Event.SelectSingleNode("//*[@Name='CommandLine']")."#text"
                    }
                    catch {
                        $Processcmdline = ""
                        
                    }
                    try {
                        $ParentProcess = $xmlevent.Event.SelectSingleNode("//*[@Name='ParentImage']")."#text"
                    }
                    catch {
                        $ParentProcess = ""
                    }


                    $event | Add-Member -MemberType NoteProperty -Name 'ProcessPath' -Value $ProcessPath
                    $event | Add-Member -MemberType NoteProperty -Name 'Processcmdline' -Value $Processcmdline
                    $event | Add-Member -MemberType NoteProperty -Name 'ParentProcess' -Value $ParentProcess

                    if ($ProcessPath -or $Processcmdline -or $ParentProcess) {
                        $result = Get-ChatGPTResult -apiKey $apiKey -prompt "Is following Windows process '$ProcessPath' launched with following commandline '$Processcmdline' by following parent process '$ParentProcess'  - an indicator of compromise? Think about it step by step."
                    }
                    else {
                        $result = "Empty string"
                    }

                    $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value $result

            }

            catch {
                Write-Warning "Error processing event $($event)" 
                $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value "Error"
            }
        }
    }

    End
    {
        Write-Warning "Following Indicators of compromise were identified in process creation logs:"
        $events | Where-Object { $_.ChatGPT -match "Yes" } | ForEach-Object {
            "TimeCreated: " + $_.TimeCreated | Out-Host
            "Id: " + $_.Id | Out-Host
            "ProcessPath: " + $_.ProcessPath | Out-Host
            "Processcmdline: " + $_.Processcmdline  | Out-Host
            "ParentProcess: " + $_.ParentProcess | Out-Host 
            "ChatGPT Response:" + $_.ChatGPT | Out-Host 
            "" | Out-Host 
        }

        $events

    }
}



<#
.Synopsis
   Get Sysintenals Autoruns output and enriches data with OpenAI API (text-davinci-003)
.DESCRIPTION
   Get Sysintenals Autoruns output and enriches data with OpenAI API (text-davinci-003)
.EXAMPLE
   Get-ChatGPTAutorunsIoC -apiKey XXX 
.EXAMPLE
   Get-ChatGPTAutorunsIoC -apiKey XXX -Verbose -SkipWarning -ComputerName "webserver.domain.local" -Credential $PSCredential
#>
function Get-ChatGPTAutorunsIoC
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential

    )

    Begin
    {
        Write-Warning "Checking Autoruns"

        # Download the autoruns executable
        $url = "https://download.sysinternals.com/files/Autoruns.zip"
        $output = "$env:temp\autoruns.zip"
        $client = new-object System.Net.WebClient
        $client.DownloadFile($url, $output)

        # Unzip the downloaded file
        Expand-Archive -Path $output -DestinationPath "$env:temp\autoruns" -Force

        if($ComputerName){
             Write-Warning "Checking Autoruns on $ComputerName"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            
            $session = New-PSSession –ComputerName $ComputerName -Credential $Credential
            Copy-Item –Path $env:temp\autoruns\autorunsc.exe –Destination 'C:\' –ToSession $session

            $autoruns = Invoke-Command -Authentication Negotiate -computername $ComputerName  -credential $Credential {C:\autorunsc.exe /accepteula -a * -c -h -s -nobanner *   2> $null} | ConvertFrom-Csv

            Invoke-Command -Authentication Negotiate -computername $ComputerName  -credential $Credential { Remove-Item C:\autorunsc.exe} | Out-Host
            
            $session | Remove-PSSession
        }
        else {
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            
            # Execute autoruns
            $autoruns = & $env:temp\autoruns\autorunsc.exe /accepteula -a * -c -h -s -nobanner *   2> $null | ConvertFrom-Csv
        }

        Remove-Item -Recurse -Force "$env:temp\autoruns" | Out-Host
        Remove-Item -Recurse -Force "$output" | Out-Host

        $events_count = $autoruns.Count
        "Found " + $events_count +" events to check" | Out-Host
    }
    Process
    {
        $i = 0
        foreach ($event in $autoruns) {

            try {
                    $i += 1
                    Write-Progress -Activity "Processing" -CurrentOperation $i -PercentComplete (($i / $events_count) * 100)

                    # Get valus of interest
                    $imagePath = $event.'Image Path'
                    $LaunchString = $event.'Launch String'
                    $EntryLocation = $event.'Entry Location' + '\' + $event.'Entry'
                    $Signer = $event.'Signer'

                    
                    if ($imagePath -or $LaunchString -or $EntryLocation -or $Signer) {
                        $result = Get-ChatGPTResult -apiKey $apiKey -prompt "Is following image path '$imagePath' signed by '$Signer' configured to run via following registry key '$EntryLocation' with following Launch String '$LaunchString' - an indicator of compromise? Think about it step by step."
                    }
                    else {
                        $result = "Empty string"
                    }

                    
                    $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value $result

            }

            catch {
                Write-Warning "Error processing event $($process)" 
                $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value "Error"
            }
        }
    }

    End
    {
        Write-Warning "Following Indicators of compromise were identified in Autoruns:"
        $autoruns | Where-Object { $_.ChatGPT -match "Yes" } | ForEach-Object {
                    $imagePath = $event.'Image Path'
                    $LaunchString = $event.'Launch String'
                    $EntryLocation = $event.'Entry Location' + '\' + $event.'Entry'
                    $Signer = $event.'Signer'


            "Image Path" + $_.'Image Path' | Out-Host
            "Launch String: " + $_.'Launch String' | Out-Host
            "Entry Location: " + $_.'Entry Location' + '\' + $_.'Entry' | Out-Host 
            "Signer:" + $_.Signer | Out-Host
            "ChatGPT Response:" + $_.ChatGPT | Out-Host 
            "" | Out-Host 
        }


        $autoruns

    }
}


<#
.Synopsis
   Extracts events with ID 4104 from Microsoft-Windows-PowerShell/Operational log and enriches data with OpenAI API (text-davinci-003)
.DESCRIPTION
   Extracts events with ID 4104 from Microsoft-Windows-PowerShell/Operational log and enriches data with OpenAI API (text-davinci-003)
.EXAMPLE
   Get-ChatGPTPowerShellScriptBlockIoC -apiKey XXX 
.EXAMPLE
   Get-ChatGPTPowerShellScriptBlockIoC -apiKey XXX -Verbose -SkipWarning
#>
function Get-ChatGPTPowerShellScriptBlockIoC
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential

    )

    Begin
    {

        if($ComputerName -and (-not $Credential)){
            $Credential = get-credential
        }

        if($ComputerName){
            Write-Warning "Checking PowerShell Scriptblocks on $($ComputerName)"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-PowerShell/Operational";id=4104} -computername $ComputerName  -credential $Credential
        }
        else{
            Write-Warning "Checking PowerShell Scriptblocks"
            if ($SkipWarning -ne $true){
                Write-Warning "You are going to send various metadata to OpenAI.com, it might contain PASSWORDS and other CONFIDENTIAL information. Are you sure you want to continue?" -WarningAction Inquire
            }
            $events = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-PowerShell/Operational";id=4104}
        }
        
        $events_count = $events.Count
        "Found " + $events_count +" events to check" | Out-Host
    }
    Process
    {
        $i = 0
        foreach ($event in $events) {

            try {
                    $i += 1
                    Write-Progress -Activity "Processing" -CurrentOperation $i -PercentComplete (($i / $events_count) * 100)


                    $xmlevent = [xml]$event.ToXML()

                    try {
                        $ScriptBlockText = $xmlevent.Event.SelectSingleNode("//*[@Name='ScriptBlockText']")."#text"
                    }
                    catch {
                        $ScriptBlockText = ""
                    }


                    $event | Add-Member -MemberType NoteProperty -Name 'ScriptBlockText' -Value $ScriptBlockText

                    

                    if ($ScriptBlockText) {
                        $result = Get-ChatGPTResult -apiKey $apiKey -prompt "Is following PowerShell script obfuscated or contains indicators of compromise? '$ScriptBlockText'"
                    }
                    else {
                        $result = "Empty string"
                    }
                    
                    $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value $result

            }

            catch {
                Write-Warning "Error processing event $($event)" 
                $event | Add-Member -MemberType NoteProperty -Name 'ChatGPT' -Value "Error"
            }
        }
    }

    End
    {
        Write-Warning "Following Indicators of compromise were identified in process creation logs:"
        $events | Where-Object { $_.ChatGPT -match "Yes" } | ForEach-Object {
            "TimeCreated: " + $_.TimeCreated | Out-Host
            "Id: " + $_.Id | Out-Host
            "ScriptBlockText" + $_.ScriptBlockText | Out-Host
            "ChatGPT Response:" + $_.ChatGPT | Out-Host 
            "" | Out-Host 
        }

        $events

    }
}


<#
.Synopsis
   Queries ChatGPT for custom prompt
.DESCRIPTION
   Queries ChatGPT for custom prompt
.EXAMPLE
   Get-ChatGPTResult -apiKey XXX 
.EXAMPLE
   Get-ChatGPTResult -apiKey XXX -prompt "Is following file path 'C:\mimikatz.exe' an indicator of compromise?" -Verbose -SkipWarning
#>
function Get-ChatGPTResult
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        # OpenAI API key https://beta.openai.com/docs/api-reference/completions/create
        [Parameter(Mandatory=$true)]
        $prompt,

        [Parameter()]
        [switch]$SkipWarning,

        [Parameter()]
        [switch]$SkipRequest

    )

    Begin
    {
       $endpoint = "https://api.openai.com/v1/completions"

       $requestBody = @{
           'prompt' = $prompt 
           'model' = "text-davinci-003"
           'max_tokens' = 1024
           "temperature" = 0.7
           "frequency_penalty" = 1
           "presence_penalty"= 1
           "top_p" = 1
       }
       $requestBodyJson = $requestBody | ConvertTo-Json
    }
    Process
    {
       $result = "Debug output"
       if ($SkipRequest -ne $true){
            # Send the request to the API
            $httpClient = [System.Net.Http.HttpClient]::new()
            $content = [System.Net.Http.HttpRequestMessage]::new()
            
            $content.Headers.Add('Accept','application/json')
            $content.Headers.Add('Authorization',"Bearer $apiKey")
            
            
            $content.Content = [System.Net.Http.StringContent]::new(
                $requestBodyJson,
                [System.Text.Encoding]::UTF8,'application/json'
            )
            $content.Method = 'POST'
            
            $content.RequestUri = $endpoint
            $clientResultMessage = $httpClient.SendAsync($content).
            GetAwaiter().
            GetResult()
            
            # Process response
            $result =  $clientResultMessage.
                Content.
                ReadAsStringAsync().
                GetAwaiter().
                GetResult()
       }          

       Write-Verbose -Message "Question: $($prompt)"
       Write-Verbose -Message "Answer: $($result)"
       
       

    }
    End
    {
       if ($SkipRequest -ne $true){ 
            ([string]::join("",((($result | ConvertFrom-Json).choices[0].text).Split("`n"))))
       }
       else {
            $result
       }
    }
}


<#
.Synopsis
   Runs all functions all the module and produces corresponding reports
.DESCRIPTION
   Queries ChatGPT for custom prompt
.EXAMPLE
   Get-ChatGPTIoCScanResults -apiKey XXX 
.EXAMPLE
   Get-ChatGPTIoCScanResults -apiKey XXX -Verbose -SkipWarning
#>
function Get-ChatGPTIoCScanResults
{
    [CmdletBinding()]
    Param
    (
        # OpenAI API key https://beta.openai.com/docs/api-reference/authentication
        [Parameter(Mandatory=$true)]
        $apiKey,

        [Parameter()]
        [switch]$SkipWarning,

        [Parameter()]
        $Path,

        #Export only Indicators of compromise
        [Parameter()]
        [switch]$IoCOnly,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName,

        #Remote Computer's credentials
        [Parameter()]
        $Credential
    )

    Begin
    {
        if($ComputerName -and (-not $Credential)){
            $Credential = get-credential
        }

    }
    Process
    {


       if($SkipWarning) {
            if($ComputerName){
                $RunningProcessesIoC = Get-ChatGPTRunningProcessesIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey -SkipWarning 
                $ServiceIoC = Get-ChatGPTServiceIoC -ComputerName $ComputerName -apiKey $apiKey -Credential $Credential -SkipWarning 
                $ProcessCreationIoc= Get-ChatGPTProcessCreationIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey -SkipWarning 
                $SysmonProcessCreationIoC = Get-ChatGPTSysmonProcessCreationIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey -SkipWarning 
                $PowerShellScriptBlockIoC= Get-ChatGPTPowerShellScriptBlockIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey -SkipWarning 
                $AutorunsIoC= Get-ChatGPTAutorunsIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey  -SkipWarning
            }
            else {
                $RunningProcessesIoC = Get-ChatGPTRunningProcessesIoC -apiKey $apiKey -SkipWarning 
                $ServiceIoC = Get-ChatGPTServiceIoC -apiKey $apiKey -SkipWarning 
                $ProcessCreationIoc= Get-ChatGPTProcessCreationIoC -apiKey $apiKey -SkipWarning 
                $SysmonProcessCreationIoC = Get-ChatGPTSysmonProcessCreationIoC -apiKey $apiKey -SkipWarning 
                $PowerShellScriptBlockIoC= Get-ChatGPTPowerShellScriptBlockIoC -apiKey $apiKey -SkipWarning 
                $AutorunsIoC= Get-ChatGPTAutorunsIoC -apiKey $apiKey -SkipWarning
            }
       }
       else {
            if($ComputerName){
                $RunningProcessesIoC = Get-ChatGPTRunningProcessesIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey
                $ServiceIoC = Get-ChatGPTServiceIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey
                $ProcessCreationIoc= Get-ChatGPTProcessCreationIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey
                $SysmonProcessCreationIoC = Get-ChatGPTSysmonProcessCreationIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey
                $PowerShellScriptBlockIoC= Get-ChatGPTPowerShellScriptBlockIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey
                $AutorunsIoC= Get-ChatGPTAutorunsIoC -ComputerName $ComputerName -Credential $Credential -apiKey $apiKey
            }
            else {
                $RunningProcessesIoC = Get-ChatGPTRunningProcessesIoC -apiKey $apiKey
                $ServiceIoC = Get-ChatGPTServiceIoC -apiKey $apiKey
                $ProcessCreationIoc= Get-ChatGPTProcessCreationIoC -apiKey $apiKey
                $SysmonProcessCreationIoC = Get-ChatGPTSysmonProcessCreationIoC -apiKey $apiKey
                $PowerShellScriptBlockIoC= Get-ChatGPTPowerShellScriptBlockIoC -apiKey $apiKey
                $AutorunsIoC= Get-ChatGPTAutorunsIoC -apiKey $apiKey
            }

       }


    }
    End
    {
      if ($Path){
        if($IoCOnly){
            if($RunningProcessesIoC){ExportIoC -Name "RunningProcessesIoC" -Object $RunningProcessesIoC -IoCOnly -ComputerName $ComputerName -Path $Path}
            if($ServiceIoC){ExportIoC -Name "ServiceIoC" -Object $ServiceIoC -IoCOnly -ComputerName $ComputerName -Path $Path}
            if($ProcessCreationIoc){ExportIoC -Name "ProcessCreationIoc" -Object ($ProcessCreationIoc | Select-Object TimeCreated, Id, ParentProcess, Processcmdline, ProcessPath, ChatGPT) -IoCOnly -ComputerName $ComputerName -Path $Path}
            if($SysmonProcessCreationIoC ){ExportIoC -Name "SysmonProcessCreationIoC" -Object ($SysmonProcessCreationIoC | Select-Object TimeCreated, Id, ProcessPath, Processcmdline, ParentProcess, ChatGPT) -IoCOnly -ComputerName $ComputerName -Path $Path}
            if($PowerShellScriptBlockIoC){ExportIoC -Name "PowerShellScriptBlockIoC" -Object ($PowerShellScriptBlockIoC | Select-Object TimeCreated, Id, ScriptBlockText, ChatGPT) -IoCOnly -ComputerName $ComputerName -Path $Path}
            if($AutorunsIoC){ExportIoC -Name "AutorunsIoC" -Object $AutorunsIoC -IoCOnly -ComputerName $ComputerName -Path $Path}
        }
                       
        else{
            if($RunningProcessesIoC){ExportIoC -Name "RunningProcessesIoC" -Object $RunningProcessesIoC -ComputerName $ComputerName -Path $Path}
            if($ServiceIoC){ExportIoC -Name "ServiceIoC" -Object $ServiceIoC -ComputerName $ComputerName -Path $Path}
            if($ProcessCreationIoc){ExportIoC -Name "ProcessCreationIoc" -Object ($ProcessCreationIoc | Select-Object TimeCreated, Id, ParentProcess, Processcmdline, ProcessPath, ChatGPT) -ComputerName $ComputerName -Path $Path}
            if($SysmonProcessCreationIoC){ExportIoC -Name "SysmonProcessCreationIoC" -Object ($SysmonProcessCreationIoC | Select-Object TimeCreated, Id, ProcessPath, Processcmdline, ParentProcess, ChatGPT) -ComputerName $ComputerName -Path $Path}
            if($PowerShellScriptBlockIoC ){ExportIoC -Name "PowerShellScriptBlockIoC" -Object ($PowerShellScriptBlockIoC | Select-Object TimeCreated, Id, ScriptBlockText, ChatGPT) -ComputerName $ComputerName -Path $Path}
            if($AutorunsIoC){ExportIoC -Name "AutorunsIoC" -Object $AutorunsIoC -ComputerName $ComputerName -Path $Path}
        }
      }
    }
}


<#
.Synopsis
   Helper function to export reports
.DESCRIPTION
   Helper function to export reports
.EXAMPLE
   ExportIoC -Object $RunningProcessesIoC -IoCOnly $IoCOnly -ComputerName $ComputerName -Path $Path
.EXAMPLE
   ExportIoC 
#>

function ExportIoC
{
    Param
    (
        #Object name to export
        [Parameter(Mandatory=$true)]
        $Name,

        #Object to export
        [Parameter(Mandatory=$true)]
        $Object,
        
        #Path to reports folder
        [Parameter()]
        $Path,

        #Export only Indicators of compromise
        [Parameter()]
        [switch]$IoCOnly,

        #Remote Computer's Name
        [Parameter()]
        $ComputerName
    )

    Begin
    {
    }
    Process
    {
        Write-Warning "Exporting $($Name)"
        if($Object){
            if($IoCOnly){
                if($ComputerName){
                    $Object | Where-Object { $_.ChatGPT -match "Yes" } | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $Path -ChildPath "$($ComputerName)_$($Name).csv") 
                }
                else{
                    $Object | Where-Object { $_.ChatGPT -match "Yes" } | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $Path -ChildPath "$($Name).csv") 
                }
            }
            else{
                if($ComputerName){
                    $Object | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $Path -ChildPath "$($ComputerName)_$($Name).csv") 
                }
                else{
                    $Object | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $Path -ChildPath "$($Name).csv") 
                }
            }
        }
        else{
            Write-Warning "Object is empty, skipping"
        }
    }
    End
    {
    }
}

Add-Type -AssemblyName  System.Net.Http

