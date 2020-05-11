<#
#######################INSTRUCTIONS######################
#                                                       #
# -Fill out the fields in the SCRIPT PARAMETERS section #
#                                                       #
# -Download the agent files. The files need to have a   #
#  specific name. Follow this naming convention:        #
#     Server_[version].msi                              #
#     Workstation_[version].msi                         #
#  [version] is the agent version. EX: Server_548.msi   #
#                                                       #
# -Create a shared folder for the agent files and logs. #
#  The directory tree should be:                        #
#     Shared_Folder                                     #
#        Agents                                         #
#           Server_548.msi                              #
#           Workstation_548.msi                         #
#        Logs                                           #
#                                                       #
# -Create a new GPO at the domain level. Edit the GPO   #
#  and navigate to:                                     #
#  Policies>Windows Settings>Scripts                    #
#  Click PowerShell scripts then click Add. When it     # 
#  asks to select a file, click browse and paste the    #
#  following files into the folder:                     #
#     aes.key                                           #
#     InstallAgentNewV2.ps1                             #
#     smtp_password.txt                                 #
#  Select the Powershell script as the startup script   #
#  Click OK through the menus                           #
#                                                       #  
#########################################################
#>

######SCRIPT PARAMETERS######
#Company name the script applies to
$CompanyName = ''                                     #Name as you'd like it to appear in the email subject
#Email configuration
$EmailSender = ''                                     #Who the email should come from
$EmailRecipient = ''                                  #Who the email should go to
$EmailSubject = "New agent install for $CompanyName"  #Do not change unless necessary
$EmailBody = ""                                       #Do not change unless necessary
$EmailServer = 'mail.smtp2go.com'                     #Do not change unless necessary
$EmailPort = 2525                                     #Do not change unless necessary

#Path to agent install files and log file name
$BasePath = ''                                        #Example: '\\SERVER01\ContinuumAgent\'
$AgentFolder = 'Agents\'                              #Example: 'Agents\'
$LogFolder = 'Logs\'                                  #Example: 'Logs\'
$LogFile = $env:ComputerName + ".txt"
######END SCRIPT PARAMETERS######

$ErrorActionPreference = "Stop"

#Turn on logging
Start-Transcript -Path "$BasePath${LogFolder}${LogFile}"

#Class for notification email
Class EmailProps
{
    [String]$EmSender
    [String]$EmRecip
    [String]$EmSubj
    [String]$EmBody
    [String]$EmServer
    [String]$EmPort
}

#Class for machine details
Class MachineProps
{
    [String]$MachType
    [String]$MachName
    [String]$MachIPAddress
    [String]$MachDomain
    [String]$MachVer
    [String]$MachCompany
}

#Get machine type
function MachineType
{
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $machineType = $NULL
    If ($osInfo.ProductType -eq 1)
    {
        $machineType = 1
        Write-Host "Workstation detected"
    }
    Else
    {
        $machineType = 0
        Write-Host "Server detected"
    }
    return $machineType
}

#Install agent from path
function InstallAgent($InstallerInfo, $Path, $MachineDetails, $EmailDetails, $CompanyName)
{        
    $RegCheck = ""
    $decryptPass = Get-Content .\smtp_password.txt | ConvertTo-SecureString -Key (Get-Content .\aes.key)
    $cred = New-Object System.Management.Automation.PSCredential ("agentinstallalert", $decryptPass)
    Write-Host "Installing agent from", "${Path}${InstallerInfo}"
    msiexec.exe /I "${Path}${InstallerInfo}"
    #Monitor registry key while installer runs
    While($RegCheck -eq "")
    {
        try
        {
            Start-Sleep -s 10
            $CurTime = Get-Date
            $RegCheck = Get-ItemProperty -Path HKLM:\Software\WOW6432Node\SAAZOD

        }
        catch [System.Management.Automation.ItemNotFoundException]
        {
            Write-Host "Continuum is not installed yet", $CurTime
        }
    }

    #Populate machine properties
    $MachineTime = $CurTime
    $MachineName = $MachineDetails.MachName
    $MachineIP = $MachineDetails.MachIPAddress
    If($MachineDetails.MachType -eq 1)
    {
        $MachineType = "Workstation"
    }
    Else
    {
        $MachineType = "Server"
    }
    $MachineDomain = $MachineDetails.MachDomain
    #Email parameters
    $EmailFrom = $EmailDetails.EmSender
    $EmailTo = $EmailDetails.EmRecip
    $EmailSubject = $EmailDetails.EmSubj
    $EmailBody = "
    Time Installed: $MachineTime
    Machine Name: ${MachineName}
    Machine IP Address: ${MachineIP}
    Machine Type: ${MachineType}
    Domain Name: ${MachineDomain}
    "
    $EmailServer = $EmailDetails.EmServer
    $EmailPort = $EmailDetails.EMPort
    
    Write-Host "Agent install finished"
    #Send email
    Send-MailMessage -From $EmailFrom  -To $EmailTo -Subject $EmailSubject -Body $EmailBody -SmtpServer $EmailServer -Port $EmailPort -Credential $cred
}

#Check if Continuum is already installed and pull properties if it is
function ContinuumProps
{
    #Check if Continuum is already installed
    try
    {
        $agentFile = Test-Path "C:\Program Files (x86)\SAAZOD\SAAZWatchDog.exe"
        $saazReg = Get-ItemProperty -Path HKLM:\Software\WOW6432Node\SAAZOD
    }
    catch [System.Management.Automation.ItemNotFoundException]
    {
        Write-Host "Continuum agent is not installed" 
    }
    finally
    {
        $ErrorActionPreference = "Continue"
    }
    
    #If already installed, pull version
    If ($agentFile -eq $true -and $saazReg -ne $null)
    {
        #Pull version of out registry and format it
        $i = 0
        $saazVersionArray = $saazReg.DisplayVersion.Split(".")
        do
        {
            $saazVersion+= $saazVersionArray[$i]
            $i++
        }While($i -le $saazVersionArray.count)
    }
    return $saazVersion
}

#Download agent
function GetInstallerInfo($Path, $Type, $AgentVer)
{
    $Files = Get-ChildItem $Path
    #Get installer version from file name and store it
    ForEach($file in $Files.Name)
    {
        If($file -like "*Workstation*")
        {
            $FileNameArrayWk = $file.Split(" ")
            $FileNameArrayIdxWk = $FileNameArrayWk.count - 1
            $FileNameWk= $FileNameArrayWk[$FileNameArrayIdxWk]
            $FileNameWkVer = $FileNameWk -replace '\D+(\d+).msi','$1'
        }
        ElseIf($file -like "*Server*")
        {
            $FileNameArraySv = $file.Split(" ")
            $FileNameArrayIdxSv = $FileNameArraySv.count - 1
            $FileNameSv= $FileNameArraySv[$FileNameArrayIdxSv]
            $FileNameSvVer = $FileNameSv -replace '\D+(\d+).msi','$1'
        }
    }

    #Check type of device
    If ($Type -eq 1)
    {
        If($AgentVer -lt $FileNameWkVer)
        {
            Write-Host "Agent Installer version:", $FileNameWkVer
            return $FileNameWk
        }
        Else
        {
            Write-Host "Agent is already on the current version"
        }
    }
    Else
    {
        If($AgentVer -lt $FileNameSvVer)
        {
            Write-Host "Agent Installer version:", $FileNameSvVer
            return $FileNameSv
        }
        Else
        {
            Write-Host "Agent is already on the current version"
        }
    }
}

#Check running context
$SecContext = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Running under", $SecContext

#Store any Continuum agent properties if they exist
$MachAgentInfo = ContinuumProps

#Create new machine definition and populate information
$NewMachine = [MachineProps]::New()
$NewMachine.MachName = (Get-WmiObject Win32_ComputerSystem).Name
$NewMachine.MachIPAddress = (Test-Connection -ComputerName $env:ComputerName -Count 1).IPV4Address.IPAddressToString
$NewMachine.MachDomain = (Get-WmiObject Win32_ComputerSystem).Domain
$NewMachine.MachType = MachineType
$NewMachine.MachVer = $MachAgentInfo
$NewMachine.MachCompany = $CompanyName

#Create new email definition and populate information
$NewEmail = [EmailProps]::New()
$NewEmail.EmSender = $EmailSender
$NewEmail.EmRecip = $EmailRecipient
$NewEmail.EmSubj = $EmailSubject
$NewEmail.EmBody = $EmailBody
$NewEmail.EmServer = $EmailServer
$NewEmail.EmPort = $EmailPort

#Get agent and return installation path
Write-Host "Installed Agent version:", $NewMachine.MachVer
$InstallerInfo = GetInstallerInfo "${BasePath}${AgentFolder}" $NewMachine.MachType $NewMachine.MachVer
#Install the agent
If($InstallerInfo -ne $null)
{
    InstallAgent $InstallerInfo "${BasePath}${AgentFolder}" $NewMachine $NewEmail $CompanyName
}
Stop-Transcript
