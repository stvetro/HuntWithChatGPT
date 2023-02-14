# HuntWithChatGPT
This is a tiny proof-of-concept PowerShell script to do threat hunting using ChatGPT (text-davinci-003). It extracts Windows event logs, ASEP/autoruns, running processes from target system and sends requests to OpenAI API to check if certain metadata is an indicator of compromise.

Get-ChatGPTAutorunsIoC - Checks modules configured to run automatically (Autoruns/ASEP)

Get-ChatGPTRunningProcessesIoC - Checks running processes and their command lines

Get-ChatGPTServiceIoC - Checks service installation events (event ID 7045)

Get-ChatGPTProcessCreationIoC - Checks process creation event ID 4688 from Security log

Get-ChatGPTSysmonProcessCreationIoC	- Checks process creation event ID 1 from Sysmon log

Get-ChatGPTPowerShellScriptBlockIoC - Checks PowerShell Script blocks (event ID 4104 from Microsoft-Windows-PowerShell/Operational)

Get-ChatGPTIoCScanResults	- Runs all cmdlets one by one and generates reports


    -apiKey <Object>
        OpenAI API key https://beta.openai.com/docs/api-reference/authentication
       
    -SkipWarning [<SwitchParameter>]
        skips the confirmation regards sending data to Open AI.
        
    -Path <Object>
        Path to report output folder
        
    -IoCOnly [<SwitchParameter>]
        Exports only Indicators of compromise instead of all metadata
        
    -ComputerName <Object>
        Remote Computer's Name
        
    -Credential <Object>
        Remote Computer's credentials
