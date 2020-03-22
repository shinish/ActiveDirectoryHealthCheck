[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $CompanyLogo = '.\img.png',

    [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter desired title for report")]
    [String]
    $ReportTitle = "PowerShell Hacks - www.powershellhacks.com",

    [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter desired directory path to save; Default: C:\Automation\")]
    [String]
    $ReportSavePath = "C:\Automation\DomainControllerHealthChecker"

)


try{
    Import-Module ReportHTML -ErrorAction Stop
}
catch{
    Write-Verbose "Installing ReportHTML Module"
    install-Module ReportHTML -Force -Confirm:$false -Verbose
    Import-Module ReportHTML -ErrorAction Stop
}
#Function for Port Verification
function Get-Portchecker {
    [CmdletBinding()]
    param (
        [Parameter()]
        [array]
        $Ports,

        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName 
    )
    $WarningPreference = 'stop'
    $port = $ports.split(',').trim()
    $port | ForEach-Object {
        [int]$newPort = $_
        Test-NetConnection -ComputerName $ComputerName -Port $newPort |
        Select-Object ComputerName, RemotePort, TcpTestSucceeded
    }
}
#Function for RDP NLA Information is disabled
function Get-RdpNlaInformation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Computername
    )
    $nlaCheck = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $ComputerName -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
    if ($nlaCheck -eq 0) {
        $nlaStatus = "Enabled" 
    }
    elseif ($nlaCheck -eq 1) {
        $nlaStatus = "Disabled" 
    }
    return $nlaStatus
}

function Get-FirewallRuleFinder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $ComputerName
    )
    $firewallchecks = Invoke-command -ScriptBlock {
        Get-NetFirewallProfile | 
        Select-Object Name, Enabled
    } -ComputerName $ComputerName 

    if ($firewallchecks){
        $firewallreturn = $firewallchecks | select-object  @{n= "Computer Name"; e = {$_.pscomputername}},Name,Enabled
    }
    else{
        $firewallreturn =  [pscustomobject]@{'Name' = $computerName ;'Enabled'= $false }
    }
    return $firewallreturn
}

function get-smbversions{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory= $true)]
        [string]
        $ComputerName
    )
    $checkSMB1Status = (Get-WindowsFeature FS-SMB1 -ComputerName $ComputerName).Installed   
    $checkSMB2Status = Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol -ExpandProperty EnableSMB2Protocol
    $smbStats = [pscustomobject][ordered]@{
        ComputerName = $computername
        SMB1Status =  $checkSMB1Status
        SMB2Status =  $checkSMB2Status
    }
    return $smbStats

}


function get-TimeCheck{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName
    )
    $ntp = w32tm /query /computer:$ComputerName /source
    $ntpprop = [ordered] @{
        Name = $ComputerName
        NTPSource = $ntp
    }
   $win32Time =  [PSCustomObject] $ntpprop 
    return $win32Time
}

function Get-LbfoCheck{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName
    )
    $HashTB = @()
    $lbfocheck = Get-NetLbfoTeam -CimSession $ComputerName
    if  ($lbfocheck){
        foreach ($Member in $lbfocheck.Members){
            $AdapterSettings  = Get-NetAdapter -Name $Member  | 
                Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed
            $InHashTB = [ordered] @{
                TeamMember           = $AdapterSettings.Name
                InterfaceDescription = $AdapterSettings.InterfaceDescription
                IfIndex              = $AdapterSettings.ifIndex 
                Status               = $AdapterSettings.Status 
                MacAddress           = $AdapterSettings.MacAddress
                LinkSpeed            = $AdapterSettings.LinkSpeed
            }
            $Hash = [pscustomobject] $InHashTB
            $HashTB += $Hash
        }
        return $HashTB
    }
    else{
        Write-host "No Team Connection found"
    }
}

function Get-DiskInfo {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $ComputerName
    )
    $logicalDisks = Get-WmiObject -Class win32_logicaldisk -ComputerName $ComputerName | Where-Object {$_.DriveType  -eq '3'}
    $hashDisks = @()
    foreach($logicaldisk in $logicalDisks){
        $hashDisk = [ordered] @{
            Drive  = $logicaldisk.deviceid
            DriveSize = "{0:N2}" -f (($logicaldisk.Size)/1Gb)
            FreeDiskSpace = "{0:N2}" -f (($logicaldisk.FreeSpace)/1Gb)

        }
        $hashDisks += [pscustomobject] $hashDisk
    }
    $hashDisks
}

function  Get-ServiceStatus{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $ComputerName
    )
    $Services='DNS','DFS Replication','Intersite Messaging','Kerberos Key Distribution Center','NetLogon','w32time','Active Directory Domain Services'
    ForEach ($Service in $Services) {
        Get-Service $Service -ComputerName $computerName| 
        Select-Object MachineName, Name, Status
    }
}


function Get-CheckSystemType{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $ComputerName
    )
    $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
    switch ($ComputerSystemInfo.Model) { 

        "Virtual Machine" { 
            $MachineType = "Virtual Machine" 
            } 
        "VMware Virtual Platform" { 
            $MachineType = "Virtual Machine" 
            } 
        "VirtualBox" { 
            $MachineType = "Virtual Machine" 
            } 
        default { 
            $MachineType = "Physical" 
            } 
    } 
    return $MachineType



}

function get-DcReplication {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName
    )
    $dcdiagResult = dcdiag /s:$ComputerName
    $dcdiagResult  | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {    
        $obj = [ordered] @{   
            Entity = $_.Matches.Groups[1].Value       
            TestName = $_.Matches.Groups[3].Value        
            TestResult = $_.Matches.Groups[2].Value       
        }    
        [pscustomobject]$obj
    }
    return $obj
}


Function Get-SecurityCheck{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName
    )
    
    try{
        
        $ErrorCount = (Get-EventLog -LogName System -ComputerName $ComputerName -EntryType Error -After ((get-date).AddDays(-1))).count
        $WarningCount = (Get-EventLog -LogName System  -ComputerName $ComputerName -EntryType Warning -After ((get-date).AddDays(-1))).count
        $Lockouts = (Get-EventLog -LogName Security  -ComputerName $ComputerName -InstanceId 4740 -After ((get-date).AddDays(-1)) -ErrorAction Stop).count 
    }
    catch [System.ArgumentException]{
        $Lockouts = 0
    }
    $errorProps = [ordered]@{
                Lockouts =  $Lockouts
                Error    =  $ErrorCount
                Warning  =  $WarningCount
    }
    $errorHash = [pscustomobject]$errorProps
    return $errorHash

}


$tabarray = "DashBoard"

#Dashboard Report
$FinalReport = New-Object 'System.Collections.Generic.List[System.Object]'
$FinalReport.Add($(Get-HTMLOpenPage -TitleText $ReportTitle -LeftLogoString $CompanyLogo -RightLogoString $RightLogo))
$FinalReport.Add($(Get-HTMLTabHeader -TabNames $tabarray))


$DomainControllers  = Get-ADForest | ForEach-Object{ Get-ADDomainController -filter *  } |  Select-Object Name -ExpandProperty Name
$servicecollection = @()
$portCheckerCollection = @()
$NlaCollection = @()
$firewallCollection = @()

foreach ($DomainController in $DomainControllers ){
    Write-host "`nDomain Controller : $DomainController " -ForegroundColor Green

    #1.1 Service Report
    Write-host "`nCheck Service Status " -ForegroundColor Yellow
    $ServiceStats =  Get-ServiceStatus -ComputerName $DomainController
    $ServiceStats| ForEach-Object {
        Write-host "Service Name : $($_.Name) `nStatus       : $($_.Status) `nMachine Name : $($_.MachineName)`n" -ForegroundColor White 
    }
    $servicecollection +=$ServiceStats     
    #1.2 Port Checker
    Write-host "Port Checker" -ForegroundColor Yellow
    $portCheck = Get-Portchecker -ComputerName $DomainController -Ports "53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269,3389, 9389"
    $portCheck | ForEach-Object {
        Write-host "Computer Name  : $($_.ComputerName) `nPort           : $($_.RemotePort) `nTest Sucessful : $($_.TcpTestSucceeded)`n" -ForegroundColor White 
    }
    $portCheckerCollection +=$portCheck



    #3. RDP NLA Information
    Write-host "`nCheck RDP NLA Information" -ForegroundColor Yellow
    $validateNLAStatus = Get-RdpNlaInformation -Computername $DomainController
    Write-host "Status  : $validateNLAStatus" -ForegroundColor White 
    $NlaCollection +=@{"ComputerName" = $DomainController; "NLBStatus" = $validateNLAStatus }

    
    #4. firewall Information
    Write-host "`nCheck Windows Firewall Status " -ForegroundColor Yellow
    $firewall =  Get-FirewallRuleFinder -ComputerName $DomainController
    $firewall | ForEach-Object {
        Write-host "Scope : $($_.Name) `tEnabled : $($_.Enabled) `t$($_.PSComputerName)" -ForegroundColor White 
    }
    $firewallCollection += $firewall 

    #SMB Information
    Write-host "`nCheck SMB versions installed" -ForegroundColor Yellow
    $smbstats = get-smbversions -computer $DomainController
    $smbstats | ForEach-Object {
        Write-host "Computername : $($_.ComputerName) `nSMB v1       : $($_.SMB1Status) `nSMB v2/v3    : $($_.SMB2Status)`n" -ForegroundColor White 
    }

    
    #Time Source Information
    Write-host "`nCheck Time Source" -ForegroundColor Yellow
    $timeCheck = get-TimeCheck -ComputerName  $DomainController
    Write-host "Computername : $($timeCheck.Name) `nNTPSource    : $($timeCheck.NTPSource)" -ForegroundColor White 


    #Team Information
    Write-host "`nCheck Team Settings" -ForegroundColor Yellow
    $lbfoChecker = Get-LbfoCheck -ComputerName  $DomainController
    if($lbfoChecker){
        $lbfoChecker |ForEach-Object {
            Write-host "TeamMember  : $($_.TeamMember) `nLinkSpeed   : $($_.LinkSpeed)`n" -ForegroundColor White 
        }
    }
    else{
        Write-host "Teaming not configured" -ForegroundColor White 
    }

    #Replication Status
    Write-host "`nReplication Status" -ForegroundColor Yellow
    $ReplicationStatus =  get-DcReplication -ComputerName $DomainController
    $ReplicationStatus| ForEach-Object {
        Write-host "Entity       : $($_.Entity)`nTest Name    : $($_.TestName) `nTest Result  : $($_.TestResult) `n" -ForegroundColor White 
    }
  
    #Disk Status 
    Write-host "`nCheck Disk Status " -ForegroundColor Yellow
    $DiskStats =  get-DiskInfo -ComputerName $DomainController
    $DiskStats| ForEach-Object {
        Write-host "Drive           : $($_.Drive) `nDrive Size      : $($_.DriveSize) `nFree Disk Space : $($_.FreeDiskSpace)" -ForegroundColor White 
    }
    
    
    #Check System Type VM / Physical
    Write-host "`nCheck System Type" -ForegroundColor Yellow
    $ServiceSystemtype =  Get-CheckSystemType -ComputerName $DomainController
    Write-host "System Type : $ServiceSystemtype " -ForegroundColor White 

    #Replication Event Log
    Write-host "`nEventlog Checks" -ForegroundColor Yellow
    $SecurityStatus = Get-SecurityCheck -ComputerName $DomainController
    $SecurityStatus| ForEach-Object {
        Write-host "Lockouts Counts          : $($_.Lockouts)`nError Count(24 Hours)    : $($_.Error) `nWarning Count(24 hours)  : $($_.Warning) `n" -ForegroundColor White 
    }
}


$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "ActiveDirectory Health Check"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'Service Report'))
$FinalReport.Add($(Get-HTMLContentDataTable $servicecollection  -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Port Checker'))
$FinalReport.Add($(Get-HTMLContentDataTable $portCheckerCollection -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))


$FinalReport.Add($(Get-HTMLContentOpen -HeaderText "ActiveDirectory Health Check"))
$FinalReport.Add($(Get-HTMLColumn1of2))
$FinalReport.Add($(Get-HTMLContentOpen -BackgroundShade 1 -HeaderText 'RDP NLA Setting'))
$FinalReport.Add($(Get-HTMLContentDataTable $NlaCollection  -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLColumn2of2))
$FinalReport.Add($(Get-HTMLContentOpen -HeaderText 'Firewall Setting'))
$FinalReport.Add($(Get-HTMLContentDataTable $firewallCollection  -HideFooter))
$FinalReport.Add($(Get-HTMLContentClose))
$FinalReport.Add($(Get-HTMLColumnClose))
$FinalReport.Add($(Get-HTMLContentClose))




$FinalReport.Add($(Get-HTMLTabContentClose))
$FinalReport.Add($(Get-HTMLClosePage))
$Day = (Get-Date).Day
$Month = (Get-Date).Month
$Year = (Get-Date).Year
$ReportName = ("$Day-$Month-$Year-Active Directory Report")
Save-HTMLReport -ReportContent $FinalReport -ShowReport -ReportName $ReportName -ReportPath $ReportSavePath
Join-Path $ReportSavePath $ReportName 