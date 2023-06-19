<#
    ===========================================================================================================================================
    Release version: 2.0.0.2
    -------------------------------------------------------------------------------------------------------------------------------------------
    Maintained by:  Aviv.Cohen@Silk.US
    Organization:   Silk.us, Inc.
    Filename:       Silk_C_Activator.ps1
    As Known As:    Silk Dot C Activator PowerShell Script
    Copyright       (c) 2023 Silk.us, Inc.
    Description:    Activate Initiator with Silk Best Practices for SDP systems.
	Host Types:     Activate for Windows and Linux environments
    ------------------------------------------------------------------------------------------------------------------------------------------
    ===========================================================================================================================================
#>

<#
*******Script Disclaimer:******************************************************************
The Silk activator script is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, 
fitness for a particular purpose, and non-infringement.
While the script was tested and worked in the Silk LAB environment, we recommend you execute it in a single host before using it for the production environment. 
We strongly recommend for the activator script is to execute during the following two scenarios:
•   Upon first connectivity of Silk storage with a new host.
•   For existing hosts using a maintenance window to avoid the possibility of data flow intervasion.
*******************************************************************************************
#>

# Ensure the minimum version of the PowerShell Activator is 5
#Requires -Version 5

##################################### Silk Activator begin of the script - Activate ########################################
#region Validate Section
# Configure general the SDP Version
[string]$SDP_Version = "2.0.0.2"

# Checking the PS version and Edition
[string]$ActivatorProduct  = "DotC"
[string]$PSPlatform        = ""
[System.Boolean]$bExitMenu = $false
if($PSVersionTable.PSEdition -eq "Core" ) {
	if ($PSVersionTable.PSVersion.Major -ge 7) {
		# Platform Section - Powershell Core 7 (Win32NT / Unix)
		if(!($Platfrom_Windows)){Set-Variable Platfrom_Windows -option Constant -Scope Script -value "Win32NT"}
		if(!($Platfrom_Linux)){Set-Variable Platfrom_Linux -option Constant -Scope Script -value "Unix"}
		$PSPlatform = $PSVersionTable.Platform	
	}
	else {
		$bExitMenu = $true	
	}
}
# Must be desktop and on windows env
elseif($PSVersionTable.PSEdition -eq "Desktop") {
	if(!($Platfrom_Windows)){Set-Variable Platfrom_Windows -option Constant -Scope Script -value "Win32NT"}
	$PSPlatform = "Win32NT"
}
else {   
	# PowerShell PSEdition is not Core or Desktop, Not supported.
	$bExitMenu = $true
}
#endregion
##################################### End Silk Activator begin of the script - Activate ####################################

##################################### Global functions #####################################################################
#region PrintDescription
# Functions PrintDescription, print to the customer a short description about the parameter that he need to change.
Function PrintDescription {
	param(
        [parameter(Mandatory)]
        [string] $description
	)

	Write-host ""	
	$host.ui.RawUI.ForegroundColor = "Yellow"
	Write-host "$description"
	$host.ui.RawUI.ForegroundColor = $OrigColor	
}
#endregion

#region HTML Messages
# Functions to print colored messages
Function GoodMessage {
	$host.ui.RawUI.ForegroundColor = "Green"
	Write-host "$($MessageCurrentObject) - [OK] - $args"
	$host.ui.RawUI.ForegroundColor = $OrigColor
	$SDPBPHTMLBody += "<div id='GoodMessage'>$($MessageCurrentObject) - [OK] - $args</div>"
}

Function BadMessage {
	$host.ui.RawUI.ForegroundColor = "Red"
	Write-host "$($MessageCurrentObject) - [ERR] - $args"
	$host.ui.RawUI.ForegroundColor = $OrigColor
	$SDPBPHTMLBody += "<div id='BadMessage'>$($MessageCurrentObject) - [ERR] - $args</div>"
}

Function InfoMessage {
	$host.ui.RawUI.ForegroundColor = "Magenta"
	Write-host "$($MessageCurrentObject) - [INFO] - $args"
	$host.ui.RawUI.ForegroundColor = $OrigColor
	$SDPBPHTMLBody += "<div id='InfoMessage'>$($MessageCurrentObject) - [INFO] - $args</div>"
}

Function DataMessage {
	$host.ui.RawUI.ForegroundColor = "Cyan"
	Write-host "$($MessageCurrentObject) - [Data] -`n$args"
	$host.ui.RawUI.ForegroundColor = $OrigColor
	$SDPBPHTMLBody += "<div id='DataMessage'>$($MessageCurrentObject) - [Data] - $args</div>"
}

Function DataMessageBlock {
	$host.ui.RawUI.ForegroundColor = "Cyan"
	Write-host "$($MessageCurrentObject) - [Data] -`n$args"
	$host.ui.RawUI.ForegroundColor = $OrigColor	
	$SDPBPHTMLBody += "<div id='DataMessage'><p id='whitepreclass'>$args</p></div>"
}

Function WarningMessage {	
	$host.ui.RawUI.ForegroundColor = "Yellow"
	Write-host "$($MessageCurrentObject) - [WARN] - $args"
	$host.ui.RawUI.ForegroundColor = $OrigColor
	$SDPBPHTMLBody += "<div id='WarningMessage'>$($MessageCurrentObject) - [WARN] - $args</div>"
}
#endregion

#region PrintDelimiter and PrintDelimiterServer
Function PrintDelimiter {
	Write-host "---------------------------------------------"
	$SDPBPHTMLBody += "<hr>"
}

Function PrintDelimiterServer {
	Write-host "============================================="
	$SDPBPHTMLBody += "<hr class='server'>"
}
#endregion 

#region GenerateHTML
# Function to generate the HTML report
Function GenerateHTML {
	# Set the output file location and name
	$OutputPath     = $PSScriptRoot
	$CurrentDate    = Get-Date	
	$OutputFilename = "SDP_$($ActivatorProduct)_$($HostType)_Activation_$($CurrentDate.Month)-$($CurrentDate.Day)-$($CurrentDate.Year)_$($CurrentDate.Hour)-$($CurrentDate.Minute)-$($CurrentDate.Second).html"
	# Check the OS type and create the full path name
	if ($PSPlatform -eq $Platfrom_Linux) {
		$OutputFile = "$($OutputPath)/$($OutputFilename)"
	}
	else {
		$OutputFile= "$($OutputPath)\$($OutputFilename)"
	}

	# Write the HTML Header
	Write-Output "<!DOCTYPE html PUBLIC `"-//W3C//DTD XHTML 1.0 Strict//EN`"  `"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd`">" | Out-File $OutputFile
	Write-Output "<html xmlns=`"http://www.w3.org/1999/xhtml`">" | Out-File -Append $OutputFile
	Write-Output "<head>" | Out-File -Append $OutputFile
	Write-Output "<title>Silk Best Practices Activator - $($CurrentDate.Month)-$($CurrentDate.Day)-$($CurrentDate.Year)_$($CurrentDate.Hour)-$($CurrentDate.Minute)-$($CurrentDate.Second)</title>" | Out-File -Append $OutputFile
	
	# Set the CSS stylesheet 
	Write-Output "<style>" | Out-File -Append $OutputFile
	Write-Output "body {background-color: rgb(24, 24, 24); font-family: `"Lucida Console`"; font-size: 14px;}" | Out-File -Append $OutputFile
	Write-Output "#BadMessage {color: red;  font-weight : bold;}" | Out-File -Append $OutputFile
	Write-Output "#GoodMessage {color: limegreen;}" | Out-File -Append $OutputFile
	Write-Output "#InfoMessage {color: magenta;}" | Out-File -Append $OutputFile
	Write-Output "#DataMessage {color: SlateBlue;}" | Out-File -Append $OutputFile
	Write-Output "#WarningMessage {color: yellow;}" | Out-File -Append $OutputFile
	Write-Output "#whitepreclass {white-space: pre;}" | Out-File -Append $OutputFile
	Write-Output "#Headline {color: DodgerBlue;}" | Out-File -Append $OutputFile
	Write-Output "#host_space {font-size: 0; height: 20px; line-height: 0;}" | Out-File -Append $OutputFile
	Write-Output "hr.server {border: 3px solid grey; border-radius: 3px;}" | Out-File -Append $OutputFile
	Write-Output "</style>" | Out-File -Append $OutputFile
	
	# Close the HTML head
	Write-Output "</head><body>" | Out-File -Append $OutputFile
	
	# Create the headline
	Write-Output "<div id='Headline'>Silk Data Platform host activation script running version - $($SDP_Version).</div>" | Out-File -Append $OutputFile
	Write-Output $HeadlineMessage | Out-File -Append $OutputFile
	
	# Write the HTML bpdy
	Write-Output $SDPBPHTMLBody | Out-File -Append $OutputFile
	
	# Close HTML properly
	Write-Output "</body>" | Out-File -Append $OutputFile
	Write-Output "</html>" | Out-File -Append $OutputFile
	Write-Output "<div id='InfoMessage'>Summary report was written into $OutputFile</div>" | Out-File -Append $OutputFile

	# Write the BP link before the end of the HTML file
	$BP_Link = "https://support.silk.us/sys/folder/detail/7Os00000000002k00oU?retUrl=%2Fsys%2Ffolder%2Fdetail%2F7Os00000000002h00oU%3FretUrl%3D%252FSys%252Fdocument%252Findex"
	Write-Output "<div id='Headline'><a href='$($BP_Link)' style='color: #8ebf42' target='_blank'>Link - Host Connectivity and Networking Best Practice Guide</a></div>" | Out-File -Append $OutputFile	
	
	# Write to the console
	$host.ui.RawUI.ForegroundColor = "Cyan"
	Write-Output "Summary report was written to $OutputFile"
	Write-Output "Guide Link - Host Connectivity and Networking Best Practice Guide -  $($BP_Link)"
	$host.ui.RawUI.ForegroundColor = $OrigColor	

	# Opening the htmk file into default browser.
	if ($PSPlatform -eq $Platfrom_Windows) {
		Invoke-Expression "& '$OutputFile'"
	}
}
#endregion

#region Check Admin User Cross Platform
# CheckAdminUserCrossPlatform Function - Checking the current user in Windows and Linux environment. You must run as administrator (Windows)
function CheckAdminUserCrossPlatform {
	if ($PSPlatform -eq $Platfrom_Linux) {
		if ($(whoami) -eq "root") {
			GoodMessage "Running as a root user on Linux OS" 
			return $True
		}
		else {
			WarningMessage "The script is not running as root admin - but with user $(whoami)" 
			return $true
		}
	}
	elseif ($PSPlatform -eq $Platfrom_Windows) {
		if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))	{
			WarningMessage "The script is not running as administrator - switching to run as administrator"
			return $False
		}
		else {
			GoodMessage "Running as an Administrator, on Windows OS version - $((Get-CimInstance Win32_OperatingSystem).version)" 
			return $True
		}
	}
	else {
		BadMessage "The platform is not Windows or Linux, Please rerun the activator script on one of those platforms" 
		return $False
	}
}
#endregion 

#region TrimHostNames
# TrimHostNames Function - Helping to trim "," from windows and linux OS array
function TrimHostNames {
	[cmdletbinding()]
	Param(
		[string]$HostNames
	)
	
	$HostNames = $HostNames.trim()
	
	if($HostNames[0] -eq ",") {
		$HostNames = $HostNames.TrimStart(",")
	}
	
	if($HostNames[-1] -eq ",") {
		$HostNames = $HostNames.TrimEnd(",")
	}
	
	return $HostNames.trim()
}
#endregion

#region handle_string_array_messages
Function handle_string_array_messages {
	Param(
		[string]$StringArray,
		[string]$MessageType
	)

	switch($MessageType) {
		"Good" {GoodMessage $StringArray}
		"Bad" {BadMessage $StringArray}
		"Warning" {WarningMessage $StringArray}
		"Info" {InfoMessage $StringArray}
		"Data" {DataMessageBlock $StringArray}
	}
}
#endregion

#region User Selections Prompt For Choice
# Get user selection
Function UserSelections {    
	param(
        [parameter(Mandatory)][string] $title,
        [parameter()][string] $defaultValue
    )	

	if ($defaultValue) {
		$message = "$title - Would you like to configure $($title) to $($defaultValue)?"
	}
	else {
		$message = "$title - Would you like to configure $($title)?"
	}

	$yes     = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Configure $($title)."
	$no      = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skip $($title)."
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	$result  = $host.ui.PromptForChoice("", $message, $options, 0) 
	Write-host "---------------------------------------------------------------------------------------------------------"
	switch ($result) {
			0 {return $True}
			1 {return $False}
	}
}
#endregion
##################################### End Global functions #################################################################

##################################### Activator Main functions ##################################################################
#region Windows_Activator
function Windows_Activator {
	[cmdletbinding()] 
	Param(	
			[parameter()][String[]]$WinServerArray,	
			[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
		)

	#region RemoteServerDiskInfo
	# Internal function RemoteServerDiskInfo
	Function RemoteServerDiskInfo {
		param (
			[parameter()]$pssessions_local,
			[parameter()]$cimsession_local
			)

		# Get all disks and their associated physical disks by SerialNumber (using with CimSession for local and remote servers)
		[string[]]$SilkFriendlyNames = @("KMNRIO K2","SILK K2","SILK KDP","SILK SDP")
		$disks = invoke-Command -Session $pssessions_local -ArgumentList (,$SilkFriendlyNames) -ScriptBlock {param($arr) Get-Disk | Where-Object {
			$diskName = $_.FriendlyName
			$arr | ForEach-Object {
				$pattern = [regex]::Escape($_)
				if ($diskName -match $pattern) {
					return $true
				}
			}
		} | Select-Object SerialNumber, Number, UniqueId, FriendlyName, LoadBalancePolicy, OperationalStatus, HealthStatus, Size, PartitionStyle}
		$physicalDisks = invoke-Command -Session $pssessions_local -ScriptBlock {Get-PhysicalDisk}

		# Create an empty array to store the combined data
		$server_diskInfo = @()

		# Loop through each disk and find its associated physical disk by SerialNumber,
		# Foreach disk we find the PhysicalDiskStorageNodeView and Partition (if exist)
		foreach ($disk in $disks | Sort-Object SerialNumber) {
			$serialNumber = $disk.SerialNumber
			$physicalDisk = $physicalDisks | Where-Object { $_.SerialNumber -eq $serialNumber }
			$PhysicalDiskStorageNodeView = get-PhysicalDiskStorageNodeView -CimSession $cimsession_local -PhysicalDisk $physicalDisk
			$disknumber   = $null
			$disknumber   = $disk.Number
			$driveLetter  = $null
			
			if($disknumber)	{
				$partitions  = Get-Partition -CimSession $cimsession_local -DiskNumber $disknumber -ErrorAction SilentlyContinue
				$partition   = $partitions | Where-Object {$_.AccessPaths -ne $null}

				if ($partition) {
					$driveLetter = $partition.DriveLetter -join ","
				}
			}
			
			$combinedDisk = [PSCustomObject]@{
				DeviceId      = $physicalDisk.DeviceId
				DiskNumber    = $disknumber
				SerialNumber  = $serialNumber
				UniqueId      = $disk.UniqueId
				FriendlyName  = $disk.FriendlyName
				LoadBalancePolicy = $PhysicalDiskStorageNodeView.LoadBalancePolicy
				CanPool      = $physicalDisk.CanPool
				OperationalStatus = $physicalDisk.OperationalStatus
				HealthStatus = $physicalDisk.HealthStatus
				SizeGB       = [math]::Round($disk.Size/1GB,4)
				DriveLetter  = $driveLetter
				DiskStatus   = $disk.OperationalStatus
				PartitionStyle = $disk.PartitionStyle
			}
			$server_diskInfo += $combinedDisk
		}
		return $server_diskInfo
	}

	# Start script initialization	
	$MessageCurrentObject = "Windows Activator"
	InfoMessage "Applying Silk BP on Windows Server/s"

	# Function Local variables
	[Boolean]$bool_local_user = $false

	# Write the user name to the HTMl
	if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
		InfoMessage "Using $($Credential.UserName) login user for Windows Activator"
	}
	else {
		InfoMessage "using $(whoami) Login user for Windows Activator"
	}

	PrintDelimiterServer

	#connect with remote session to a windows server
	Try {	
		# Checked if the customer was not Specified server, meaning that he want to run it locally.
		if ([string]::IsNullOrEmpty($WinServerArray)) {
			# If we enter here, this is mean that the server array contain only one server and it's locally.
			InfoMessage "No server/s was Specified, running locally: $($env:COMPUTERNAME) with local user $(whoami)"
			$WinServerArray = $env:COMPUTERNAME

			# Local Server using local user.
			$bool_local_user = $True
		}

		# Write the headline messages into HTML report
		$HeadlineMessage
		$HeadlineMessage = "<div id='Headline'>Running activiation for Windows host(s) `"$($WinServerArray)`".</div>"

		foreach ($WinServer in $WinServerArray)	{
			PrintDelimiter

			# Trim the server name
			$WinServer = $WinServer.Trim()
			
			# initialization Windows Server for Messages Function
			$MessageCurrentObject = $WinServer
			
			# Reboot checking boolean parameter
			[boolean]$bNeedReboot = $false
			
			# Test coneection to the windows server, if no ping that is meaning that we could not reach it, script finish.
			if (-not (Test-Connection -ComputerName $WinServer -Count 2 -Quiet)) {
				WarningMessage "The windows Server $($WinServer) not responding to ping, skipping this server..."
			}
			else {
				# Write that ping was sucessfully
				GoodMessage "Pinging  $($WinServer) was successfully"

				if($bool_local_user) {
					$pssessions = New-PSSession
					$CIMsession = New-CimSession
				}
				else {
					# Initialization pssessions
					if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
						$pssessions = New-PSSession -ComputerName $WinServer -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue
						$CIMsession = New-CimSession -ComputerName $WinServer -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue
					}
					else {
						$pssessions = New-PSSession -ComputerName $WinServer -Authentication Kerberos -ErrorAction SilentlyContinue
						$CIMsession = New-CimSession -ComputerName $WinServer -Authentication Kerberos -ErrorAction SilentlyContinue
					}
				}

				# Reseting the counter message sections
				[int]$MessageCounter = 1

				# iSCSI Section
				PrintDescription "Category: SAN Connectivity related.`nParameter type: The ISCSI settings are global parameters and may impact other attached storage arrays.`nDescription: The ISCSI settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
				$ISCSI_Service = UserSelections "ISCSI" "Configuring MSiSCSI service"

				# MPIO Section
				PrintDescription "Category: Multipath Microsoft DSM Connectivity related, High Availability related.`nParameter type: The MPIO framework settings are global parameters and may impact other attached storage arrays.`nDescription: The MPIO framework settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
				$MPIO_Installation = UserSelections "MPIO Feature" "Installing Multipath-IO"
				$MPIO_Configuration = UserSelections "MPIO Configuration" "configure MPIO parameters"

				# Settings LQD Silk Disk
				PrintDescription "Category: Multipath Microsoft DSM Connectivity related, High Availability related.`nParameter type: Disk Load Balance Policy Settings.`nDescription: Setting the Silk Disks Load Balance Policy to Least Queue Depth (LQD)" 
				$MPIO_LoadBalancePolicy = UserSelections "MPIO" "Disk Load Balance Policy (LQD)"

				# Settings CTRL Silk Disk OFFLINE
				PrintDescription "Category: SAN Connectivity related.`nParameter type: CTRL LU disk XXXXXX0000 Settings.`nDescription: Setting the CTRL Silk Disk Offline to avoid LU resets" 
				$CTRL_LU_Offline = UserSelections "Management Lugical Unit" "CTRL Silk Disk"

				# Windows TRIM/Unmap
				PrintDescription "Category: Performance related.`nParameter type: TRIM / UNmap Disablie Disable Delete Notification.`nDescription: The TRIM functionality within Windows is controlled by a registry setting. By default, the setting is enabled which effectively enables auto-unmap."
				$WinTrimUnmapRegistry = UserSelections "Trim / UNmap" "Disable Delete Notification Key"

				# Defragmentation Scheduled Task
				PrintDescription "Category: Performance related.`nParameter type: Disablie Disk Defragmentation Scheduled Task.`nDescription: In a Windows, Hyperv and even Windows server run as a virtual Machine on Cloud environments, it is recommended to Disable Disk Fragmentation Scheduled Task (ScheduledDefrag) to avoid performance issues"
				$Defragmentation = UserSelections "Defragmentation" "Disable Windows Defragmentation Scheduled Task"

				# Acitviation iSCSI Service according to BP
				if($ISCSI_Service) {
					InfoMessage "$MessageCounter - Running activation for iSCSI service"
					# $MSiSCSI = (invoke-Command -Session $pssessions -ScriptBlock {Get-WmiObject -Class Win32_Service -Filter "Name='MSiSCSI'"})
					$MSiSCSI = Get-CimInstance -CimSession $CIMsession -Class Win32_Service -Filter "Name='MSiSCSI'"
					
					if($MSiSCSI) {
						if ($MSiSCSI.State -match "Running") {
							GoodMessage "MSiSCSI service is running"

							# Checking if the service startup type is set to automatic
							if ($MSiSCSI.StartMode -eq "Auto") {
								GoodMessage "MSiSCSI service is set to start automatically"	
							}
							else {
								WarningMessage "MSiSCSI service is not set to start automatically but to $($MSiSCSI.StartMode), Setting MSiSCSI service to start automatically"
								(invoke-Command -Session $pssessions -ScriptBlock {(Set-Service -Name MSiSCSI -StartupType Automatic)}) | Out-Null
								GoodMessage "Setting MSiSCSI service to start automatically complete"
							} 
						}
						else { 
							WarningMessage "MSiSCSI service is not running, Current state is - $($MSiSCSI.State), Starting MSiSCSI service and set to start automatically"
							(invoke-Command -Session $pssessions -ScriptBlock {start-Service MSiSCSI}) | Out-Null
							(invoke-Command -Session $pssessions -ScriptBlock {(Set-Service -Name MSiSCSI -StartupType Automatic)}) | Out-Null
							GoodMessage "Starting MSiSCSI service and set to start automatically complete"
						}
					}
					else { 
						BadMessage "iSCSI service not found, Could not start or enable it"
					}
				}
				else {
					InfoMessage "$MessageCounter - Skipping Windows iSCSI service configuration"
				}

				$MessageCounter++
				PrintDelimiter
				
				# MPIO Installation
				if($MPIO_Installation) {
					InfoMessage "$MessageCounter - Running activation for Multipath configuration (Windows Feature and Optional Feature)"
					$MultipathIO = (invoke-Command -Session $pssessions -ScriptBlock {Get-WindowsFeature -Name Multipath-IO})
					
					# Multipath-IO Feature
					if($MultipathIO) {
						if ($MultipathIO.InstallState -eq "Installed") {
							GoodMessage "Multipath value is Installed properly configured according to Silk's BP"

							# Multipath-IO Optional Feature
							$MultipathIOFeature = (invoke-Command -Session $pssessions -ScriptBlock {(get-WindowsOptionalFeature -Online -FeatureName MultipathIO)})
							if($MultipathIOFeature) {
								if ($MultipathIOFeature.State -match "Enabled") {
									GoodMessage "Multipath Windows Optional Feature is properly configured according to Silk's BP"
								}
								else { 
									WarningMessage "Multipath Windows Optional Feature is not properly configured according to Silk's BP, The current state is $($MultipathIOFeature.State), Enable Windows Optional Feature starting..."
									(invoke-Command -Session $pssessions -ScriptBlock {Enable-WindowsOptionalFeature -online -FeatureName MultipathIO -NoRestart}) | Out-Null
									GoodMessage "Enable Windows Optional Feature complete, server reboot required!"
									$bNeedReboot = $true
								}
							}
							else { 
								WarningMessage "Multipath Optional Feature is not enabled, Enable Windows Optional Feature starting..."
								(invoke-Command -Session $pssessions -ScriptBlock {Enable-WindowsOptionalFeature -online -FeatureName MultipathIO -NoRestart}) | Out-Null
								GoodMessage "Enable Windows Optional Feature complete, server reboot required!"
								$bNeedReboot = $true
							}
						}
						else { 
							WarningMessage "Multipath is not installed, The current state is $($MultipathIO.InstallState), Install Windows Feature starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Install-WindowsFeature -name Multipath-IO}) | Out-Null
							(invoke-Command -Session $pssessions -ScriptBlock {Enable-WindowsOptionalFeature -online -FeatureName MultipathIO -NoRestart}) | Out-Null
							GoodMessage "Install Windows Feature and Enable Windows Optional Feature complete, server reboot required!"
							$bNeedReboot = $true
						}
					}
					else { 
						WarningMessage "Multipath Feature is not installed, Will install it and the Optional Features"
						(invoke-Command -Session $pssessions -ScriptBlock {Install-WindowsFeature -name Multipath-IO}) | Out-Null
						(invoke-Command -Session $pssessions -ScriptBlock {Enable-WindowsOptionalFeature -online -FeatureName MultipathIO -NoRestart}) | Out-Null
						GoodMessage "Install Windows Feature and Enable Windows Optional Feature complete, server reboot required!"
						$bNeedReboot = $true
					}
				}
				else {
					InfoMessage "$MessageCounter - Skipping Windows MPIO Installation (Windows Feature and Optional Feature)"
				}

				$MessageCounter++
				PrintDelimiter

				# MPIO Settings and Confioguration
				if($MPIO_Configuration) {
					InfoMessage "$MessageCounter - Running activation for MPIO Configuration and additional Settings"

					# MPIO sections  Continully only if the Multipath-IO and MultipathIO Feature are installed and enabled
					$MultipathIO        = (invoke-Command -Session $pssessions -ScriptBlock {Get-WindowsFeature -Name Multipath-IO})
					$MultipathIOFeature = (invoke-Command -Session $pssessions -ScriptBlock {(get-WindowsOptionalFeature -Online -FeatureName MultipathIO)})
					if (($MultipathIO.InstallState -match "Installed") -and  ($MultipathIOFeature.State -match "Enabled")) {
						# MPIO Section 
						$MPIO = $null
						$MPIO = (Invoke-Command -Session $pssessions -ScriptBlock {Get-MPIOSetting})
						$MPIO_out = ($MPIO | Out-String).Trim()
						$MPIO = $MPIO | Out-String -Stream
						$MPIO = $MPIO.Replace(" ", "")
						
						ForEach ($MPIOobject in $MPIO) {
							switch ($($MPIOobject.Split(':')[0])) {
								'PathVerificationState'     { $PathVerificationState = $($MPIOobject.Split(':')[1]) } # Enabled
								'PathVerificationPeriod'    { $PathVerificationPeriod = $($MPIOobject.Split(':')[1]) } # 1 
								'PDORemovePeriod'           { $PDORemovePeriod = $($MPIOobject.Split(':')[1]) } # 20
								'RetryCount'                { $RetryCount = $($MPIOobject.Split(':')[1]) } # 3
								'RetryInterval'             { $RetryInterval = $($MPIOobject.Split(':')[1]) } # 3
								'UseCustomPathRecoveryTime' { $UseCustomPathRecoveryTime = $($MPIOobject.Split(':')[1]) } # Enabled
								'CustomPathRecoveryTime'    { $CustomPathRecoveryTime = $($MPIOobject.Split(':')[1]) }	# 20
								'DiskTimeoutValue'          { $DiskTimeOutValue = $($MPIOobject.Split(':')[1]) } # 100
							}
						}

						# Print the MPIO Settings
						InfoMessage "MPIO Settings Section"

						# Print the MPIO into the html
						handle_string_array_messages $MPIO_out "Data"

						# Checking the MSDSM supported hardware list
						$MSDSMSupportedHW = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMSupportedHW -VendorId MSFT2005 -ProductId iSCSIBusType_0x9})
						if ($MSDSMSupportedHW) {
							GoodMessage "MPIO DSM value is properly configured according to Silk's BP"
						}
						else {
							WarningMessage "MPIO DSM is not set to VendorId:MSFT2005 and ProductId:iSCSIBusType_0x9, Adding MPIO iSCSI support (Claiming all the iSCSI attached storage for the MPIO) starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {New-MSDSMSupportedHW -VendorId MSFT2005 -ProductId iSCSIBusType_0x9}) | Out-Null
							GoodMessage "Adding MPIO iSCSI support complete, server reboot required!"
							$bNeedReboot = $true
						}

						if ($PathVerificationState -match "Enabled") {
							GoodMessage "PathVerificationState value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "PathVerificationState is not Enabled, Current Value is $($PathVerificationState), Configure PathVerificationState parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPathVerificationState Enabled }) | Out-Null
							GoodMessage "Configure PathVerificationState parameter completed, server reboot required"
							$bNeedReboot = $true
						}
						
						if ($PathVerificationPeriod -match "1")	{
							GoodMessage "PathVerificationPeriod value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "PathVerificationPeriod value is not set 1, Current Value is $($PathVerificationPeriod), Configure PathVerificationPeriod parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPathVerificationPeriod 1 }) | Out-Null
							GoodMessage "Configure PathVerificationPeriod parameter completed, server reboot required"
							$bNeedReboot = $true
						}

						if ($RetryCount -match "3")	{
							GoodMessage "RetryCount value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "RetryCount value is not set 3, Current Value is $($RetryCount), Configure RetryCount parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewRetryCount 3}) | Out-Null
							GoodMessage "Configure RetryCount parameter completed, server reboot required"
							$bNeedReboot = $true
						}

						if ($DiskTimeOutValue -match "100") {
							GoodMessage "DiskTimeOutValue value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "DiskTimeOutValue value is not set 100, Current Value is $($DiskTimeOutValue),Configure DiskTimeOutValue parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {set-MPIOSetting -NewDiskTimeout 100}) | Out-Null
							GoodMessage "Configure DiskTimeOutValue parameter completed, server reboot required"
							$bNeedReboot = $true
						}

						if ($RetryInterval -match "3") {
							GoodMessage "RetryInterval value is properly configured according to Silk's BP."
						}
						else { 
							WarningMessage "RetryInterval value is not set 3, Current Value is $($RetryInterval), Configure RetryInterval parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewRetryInterval 3 }) | Out-Null
							GoodMessage "Configure RetryInterval parameter completed, server reboot required"
							$bNeedReboot = $true
						}

						if ($PDORemovePeriod -match "20") {
							GoodMessage "PDORemovePeriod value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "PDORemovePeriod value is not set 20, Current Value is $($PDORemovePeriod), Configure PDORemovePeriod parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPDORemovePeriod 20}) | Out-Null
							GoodMessage "Configure PDORemovePeriod parameter complete, server reboot required"
							$bNeedReboot = $true
						}

						if ($UseCustomPathRecoveryTime -match "Enabled") {
							GoodMessage "UseCustomPathRecoveryTime value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "UseCustomPathRecoveryTime value is not set Enabled, Current Value is $($UseCustomPathRecoveryTime), Configure UseCustomPathRecoveryTime parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -CustomPathRecovery Enabled}) | Out-Null
							GoodMessage "Configure UseCustomPathRecoveryTime parameter complete, server reboot required"
							$bNeedReboot = $true
						}

						if ($CustomPathRecoveryTime -match "20") {
							GoodMessage "CustomPathRecoveryTime value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "CustomPathRecoveryTime value is not set 20, Current Value is $($CustomPathRecoveryTime), Configure CustomPathRecoveryTime parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPathRecoveryInterval 20}) | Out-Null
							GoodMessage "Configure CustomPathRecoveryTime parameter complete, server reboot required"
							$bNeedReboot = $true
						}

						# Load Balance and Failover Policy
						$MSDSMGlobalDefaultLoadBalancePolicy = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMGlobalDefaultLoadBalancePolicy})
						if($MSDSMGlobalDefaultLoadBalancePolicy) {
							if($MSDSMGlobalDefaultLoadBalancePolicy -match "LQD") {
								GoodMessage "Microsoft Global load balance policy value is properly configured according to Silk's BP"
							}
							else { 
								WarningMessage "Microsoft Global load balance policy is not set to LQD but set to - $($MSDSMGlobalDefaultLoadBalancePolicy), Configure MSDSMGlobalDefaultLoadBalancePolicy parameter starting..."
								(invoke-Command -Session $pssessions -ScriptBlock {Set-MSDSMGlobalDefaultLoadBalancePolicy -Policy LQD}) | Out-Null
								GoodMessage "Configure MSDSMGlobalDefaultLoadBalancePolicy parameter complete"
							}
						}
						else { 
							BadMessage "Could not get the state of server global load balance policy " 
						}

						# MSDSMAutomaticClaimSettings - Gets settings for MSDSM automatically claiming SAN disks for MPIO.
						$MSDSMAutomaticClaimSettings = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMAutomaticClaimSettings})
						if($MSDSMAutomaticClaimSettings["iSCSI"]) {
							GoodMessage "MSDSM automatically claiming SAN disks for MPIO value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "MSDSM automatically claiming SAN disks for MPIO value is not properly configured according to Silk's BP, Enable MSDSMAutomaticClaim for iSCSI parameter starting..."
							(invoke-Command -Session $pssessions -ScriptBlock {Enable-MSDSMAutomaticClaim -BusType iSCSI -Confirm:$false}) | Out-Null
							GoodMessage "Enable MSDSMAutomaticClaim for iSCSI parameter complete"
						}
					}
					else {
						BadMessage "Because the MPIO is not fully installed and Enabled we can't continue with activate the MPIO Settings and additional configurations"
					}
				}
				else {
					InfoMessage "$MessageCounter - Skipping Windows MPIO configuration and additional Settings"
				}

				$MessageCounter++
				PrintDelimiter

				# Init empty server disk.
				$server_diskInfo = @()

				# Load Balance and Failover Policy for Individual Volumes
				if($MPIO_LoadBalancePolicy)	{
					InfoMessage "$MessageCounter - Running Activiation for Load Balance and Failover Policy for Individual Volumes"

					# Checking if the mpclaim found (if not -> mean that MPIO is not installed)
					$mpclaim_installed = (invoke-Command -Session $pssessions -ScriptBlock {Get-Command mpclaim.exe})

					if($mpclaim_installed) {
						
						# Check if the array of disk is empty, if yes, we fill it only once
						if($server_diskInfo.Count -eq 0) {
							$server_diskInfo = RemoteServerDiskInfo -pssessions_local $pssessions -cimsession_local $CIMsession
						}

						# Check the PD count 
						if($server_diskInfo.Count -ne 0) {
							
							# Sort the disk information and print it into html							
							$server_diskInfo_out = ($server_diskInfo | Select-Object DeviceId,DiskNumber,SerialNumber,FriendlyName,LoadBalancePolicy,CanPool,OperationalStatus,HealthStatus,SizeGB,DriveLetter,DiskStatus,PartitionStyle | Format-Table * -AutoSize | Out-String).Trim()

							# Print the MPIO into the html
							handle_string_array_messages $server_diskInfo_out "Data"

							foreach ($PD_Temp in $server_diskInfo)	{
								# Check for each Individual if it LQD or not
								if ($PD_Temp.LoadBalancePolicy -match "Least Queue Depth") {
									GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Least Queue Depth)"
								}
								else {
									# Check if the physical disk have DeviceID, if not we skip it
									if ($PD_Temp.DeviceId)	{
										WarningMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (Least Queue Depth) but set to - $($PD_Temp.LoadBalancePolicy)"
										$UniqueID = $PD_Temp.UniqueId.Trim()
										# $MPIODisk = (invoke-Command -Session $pssessions -ScriptBlock {(Get-WmiObject -Namespace root\wmi -Class mpio_disk_info).driveinfo | Select-Object Name,SerialNumber})
										$MPIODisk = (Get-CimInstance -CimSession $CIMsession -Namespace root\wmi -Class mpio_disk_info).DriveInfo | Select-Object Name,SerialNumber
										$MPIODisk = $MPIODisk | Where-Object {$_.SerialNumber -eq $UniqueID}
										$MPIODiskID = $MPIODisk.Name.Replace("MPIO Disk","")
										(invoke-Command -Session $pssessions -Args $MPIODiskID -ScriptBlock {mpclaim -l -d $args[0] 4}) | out-null
										GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Least Queue Depth)"
									}
									else {
										WarningMessage "SerialNumber - $($PD_Temp.SerialNumber) don't have disk DeviceId, skipping..." 
									}
								}
							}
						}
						else {
							InfoMessage "No SILK SDP Disks found on the server"
						}
					}
					else {
						BadMessage "The mpclaim.exe not found. Check if MPIO Installed and Enabled"
					}
				}
				else {
					InfoMessage "$MessageCounter - Skipping Individual Disk MPIO configuration"
				}

				$MessageCounter++
				PrintDelimiter 

				if($CTRL_LU_Offline) {
					InfoMessage "$MessageCounter - Running Activiation for CTRL Silk Disk"

					# Check if the array of disk is empty, if yes, we fill it only once
					if($server_diskInfo.Count -eq 0) {
						$server_diskInfo = RemoteServerDiskInfo -pssessions_local $pssessions -cimsession_local $CIMsession
					}
					
					if($server_diskInfo.Count -ne 0) {
						# Run over the CTRL disks and verify that each disk is Offline
						foreach ($PD_Temp in ($server_diskInfo | Where-Object {$_.SerialNumber.EndsWith("0000")})) {
							# Check for each Individual if it offline or not
							if ($PD_Temp.DiskStatus -match "Offline") {
								GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (DiskStatus - Offline)"
							}
							elseif ($PD_Temp.DiskStatus -match "Online") {
								if ($PD_Temp.DeviceId) {									
									WarningMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (DiskStatus - Offline) but set to - $($PD_Temp.DiskStatus)"
									Get-Disk -CimSession $CIMsession -SerialNumber $PD_Temp.SerialNumber | Where-Object IsOffline -Eq $False | Set-Disk -IsOffline $True 
									GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (DiskStatus - Offline)"
								}
								else {
									WarningMessage "SerialNumber - $($PD_Temp.SerialNumber) don't have disk DeviceId, skipping..." 	
								}
							}
							else {
								WarningMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) is not Online or Offline but set to - $($PD_Temp.DiskStatus), skipping..."
							}
						}						
					}
					else {
						InfoMessage "No CTRL SILK SDP Disks found on the server"
					}					
				}
				else{
					InfoMessage "$MessageCounter - Skipping CTRL Silk Disk Settings"
				}

				$MessageCounter++
				PrintDelimiter

				if($WinTrimUnmapRegistry) {
					# Check that TRIM/UNMAP Registry Key
					InfoMessage "$MessageCounter - Running activation for Windows TRIM/UNMAP Registry Key..."
					$WindowsrimUnampRegData = (invoke-Command -Session $pssessions -ScriptBlock {Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name DisableDeleteNotification})
					if($WindowsrimUnampRegData) {					
						if ($WindowsrimUnampRegData.DisableDeleteNotification -eq 1) {
							GoodMessage "Trim / UNMAP registry key Disable Update Notification set properly (to 1)"
						}
						else {
							WarningMessage "Trim / UNMAP registry key Disable Update Notification is not set properly (to 1) but to - $($WindowsrimUnampRegData.DisableDeleteNotification), Disabling DisableDeleteNotification, starting..." 
							(invoke-Command -Session $pssessions -ScriptBlock {(Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name DisableDeleteNotification -Value 1)}) | Out-Null
							GoodMessage "Windows Trim / UNMAP DisableDeleteNotification Task, complete"
						}
					}
					else {
						InfoMessage "No DisableDeleteNotification was found in registry under HKLM:\System\CurrentControlSet\Control\FileSystem location"
					}
				}

				$MessageCounter++
				PrintDelimiter

				if($Defragmentation) {
					InfoMessage "$MessageCounter - Running activation for Disk Defrag configuration" 
					$ScheduledDefragTask = (Get-ScheduledTask -CimSession $CIMsession -TaskName ScheduledDefrag)
					if($ScheduledDefragTask) {
						if($ScheduledDefragTask.State -match "disabled") {
							GoodMessage " Scheduled Disk Fragmentation policy value is properly configured according to Silk's BP"
						}
						else { 
							WarningMessage "Scheduled Disk Fragmentation is not set to Disabled but to $($ScheduledDefragTask.State), Disabling ScheduledDefrag Task, starting..." 
							(Get-ScheduledTask -CimSession $CIMsession ScheduledDefrag | Disable-ScheduledTask -CimSession $CIMsession -ErrorAction SilentlyContinue) | Out-Null
							GoodMessage "Disabling ScheduledDefrag Task, complete"
						}
					}
					else { 
						WarningMessage "Scheduled Disk Fragmentation is not found on the windows Scheduled Task, Nothing to do"
					}
				}
				else {
					InfoMessage "$MessageCounter - Skipping Windows disk defragmentation deactivation"
				}

				$MessageCounter++
				PrintDelimiter

				# Remove the CIM session
				if(![string]::IsNullOrEmpty($CIMsession.Id)) {
					#Disconwnect from the server
					Get-CimSession -Id $($CIMsession.Id) | Remove-CimSession -Confirm:$false -ErrorAction SilentlyContinue
					$CIMsession = $null
					InfoMessage "Remove the CimSession To $($WinServer)"
				}

				# Remove the PSSession
				if(![string]::IsNullOrEmpty($pssessions.Id)) {
					#Remove the Session from the server
					Get-PSSession -Id $($pssessions.Id) | Remove-PSSession -Confirm:$false -ErrorAction SilentlyContinue
					$pssessions = $null
					InfoMessage "Remove the PSSession To $($WinServer)"
				}				
			}

			if($bNeedReboot) {
				WarningMessage "Activation for $($WinServer) completed, Settings changed, reboot required!"
			}
			else {
				InfoMessage "Activation for $($WinServer) completed."
			}

			PrintDelimiter
			$SDPBPHTMLBody += "<div id='host_space'></div>"
		}
	}
	catch {
		# Get the exception messages
		$ExceptionMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		BadMessage "Caught exception during Windows Activator at line: $($line)"
		BadMessage $ExceptionMessage
	}
	Finally {
		# Once all data is collected - output into HTML
		$MessageCurrentObject = "Finished activating`n"

		PrintDelimiterServer

		# Remove the CIM session
		if(![string]::IsNullOrEmpty($CIMsession.Id)) {
			#Disconwnect from the server
			Get-CimSession -Id $($CIMsession.Id) | Remove-CimSession -Confirm:$false -ErrorAction SilentlyContinue
			$CIMsession = $null
			InfoMessage "Remove the CimSession To $($WinServer)"
		}

		# Remove the pssessions
		if(![string]::IsNullOrEmpty($pssessions.Id)) {
			#Disconwnect from the server
			Get-PSSession -Id $($pssessions.Id) | Remove-PSSession -Confirm:$false -ErrorAction SilentlyContinue
			$pssessions = $null
			InfoMessage "Remove the PSSession To $($WinServer)"
		}
	}
}
#endregion

#region Linux Activator as a subfunction
function Linux_Activator {	
	[cmdletbinding()] 
	Param(
		[parameter()][string[]]$ServerArray,
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	# Internal Sub Functions

	#region InternalSubFunctions	
	Function ValidatePlinkExecutable {
		InfoMessage "Validate Plink Executable."
		$Plink_Installed = $false

		try {
			# get the plink command
			$Plink_command = Get-Command -Name plink

			if ($Plink_command) {
				$Plink_min_version =  0.74
				$Plink_Source      = $Plink_command.Source
				$Plink_release     = (&$plink_source -V | select-string "plink: Release").ToString().replace("plink: Release ","").trim()
				
				# Check if the version is only numbers
				if($Plink_release -match "^[\d\.]+$") {
					if($Plink_release -ge $Plink_min_version) {
						InfoMessage "plink (version - $($Plink_release)) is installed at $Plink_Source, and we can continue to activate Linux initiator/s."
						GoodMessage "Plink Command checks passed."
						$Plink_Installed = $True
					}
					else {
						BadMessage "plink is installed at $Plink_Source, yet it version must be above version $($Plink_min_version)"
					}
				}
				else {
					BadMessage "plink is installed at $Plink_Source, yet can't determine the plink version $($Plink_release)"
				}
			}
			else {
				BadMessage "No Plink command found, please check that plink is installed."
			}
		}
		catch {
			BadMessage "No Plink command found, please check that plink is installed."
		}
		
		# Return true / false.
		return $Plink_Installed
	}
	#endregion

	#region Install_Package
	Function Install_Package {
		Param(		
			[parameter()][string]$Pacakge,
			[parameter()][string]$LinuxOSType
		)

		[System.Boolean]$bPackageInstall = $False

		$bPackageInstall = Checking_Package $Pacakge $linuxtype
		if($bPackageInstall) {
			switch -Wildcard ($LinuxOSType) {
				'rhel*' {
					$command = "sudo yum -y install $($Pacakge)"
				}
				'debian*' {
					$command = "sudo apt-get -y install $($Pacakge)"
				}
			}

			WarningMessage "package $($Pacakge) not Installed, and will be install, Package installation starting..."
			$rpmInstall = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
			GoodMessage "Package command installation completed"

			# Recheck again if the package was installed
			Checking_Package $Pacakge $linuxtype
		}		
	}
	#endregion

	#region Checking_Package
	Function Checking_Package {
		Param(		
			[parameter()][string]$Pacakge,
			[parameter()][string]$LinuxOSType
		)

		# Return if found error
		[System.Boolean]$bfoundErrorInFunction = $False

		# Checking the PREREQUISITES of the packages that must be installed on the machine (device-mapper-multipath / lsscsi  / scsi-initiator-utils)
		# Need commands to be with 2>&1 in the end to get the stderr
		switch -Wildcard ($LinuxOSType) {
			'rhel*' {
				$command = "sudo rpm -qa | grep $($Pacakge)"
			}
			'debian*' {
				$command = "sudo dpkg -s | grep $($Pacakge)"
			}
		}
		
		$rpmCheck = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer

		if ($rpmCheck) {
			GoodMessage "package $($Pacakge) already Installed - version:"
			handle_string_array_messages ($rpmCheck | Out-String).trim() "Data"
		}
		else {
			BadMessage "package $($Pacakge) not Installed"
			$bfoundErrorInFunction = $True
		}

		# Return $bfoundErrorInFunction value
		return $bfoundErrorInFunction
	}
	#endregion

	#region Checking_Service
	Function Checking_Service {
		Param(
			[parameter()][string]$Service,
			[parameter()][string]$LinuxOSType
		)

		# Checking the MPIO and iSCSI Services on the machine
		[string]$ServiceActive  = "active"
		[string]$ServiceEnabled = "enabled"
		
		$command = "sudo systemctl is-active $($Service); sudo systemctl is-enabled $($Service)"
		$CheckingServiceStatus = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer

		# Check if it null
		if($CheckingServiceStatus) {
			$CheckingServiceStatus_output = $CheckingServiceStatus -join " "
			if(($CheckingServiceStatus[0] -eq $ServiceActive) -AND ($CheckingServiceStatus[1] -eq $ServiceEnabled))	{
				GoodMessage "$($Service) service is running and enabled..."
			}
			else {
				$command = "sudo systemctl enable $($Service) ; sudo systemctl start $($Service)"
				WarningMessage "Service $($Service) is not running or enabled, current state is - $($CheckingServiceStatus_output), Enabling and Starting Service starting..."
				$EnablingService = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
				InfoMessage "Enabling and Starting Service is completed"
			}
		}
		else {
			BadMessage "$($Service) service not found (via systemctl), Please installed it."
		}
	}
	#endregion

	#region Invoke-LinuxCommand
	function Invoke-LinuxCommand {
		param (
			[Parameter()][string]$Command,
			[Parameter()][string]$Server,
			[Parameter()][string]$LinuxUserName,
			[Parameter()][string]$LinuxUserPassword,
			[Parameter()][bool]$UseLocalServer
		)
		
		if ($UseLocalServer) {
			$rtrValue = Invoke-Expression $Command
		} else {
			$rtrValue = Invoke-Expression 'plink -P 22 -ssh $Server -pw $LinuxUserPassword -l $LinuxUserName -no-antispoof $Command'
		}

		# Return the output of the command
		return $rtrValue
	}
	#endregion

	# End Internal Sub Functions

	# Local Variable
	[boolean]$bLocalServer = $false

	# Start script initialization
	$MessageCurrentObject = "Linux Activator"
	InfoMessage "Applying Silk BP on Linux Server/s"

	# Check the Windows servers, if it empty run this with local user
	if ([string]::IsNullOrEmpty($ServerArray)) {
		# Get the user name
		$linux_username = $(whoami)

		# Local user True
		$bLocalServer = $True

		# Set local server name - $ServerArray
		$ServerArray = hostname

		# Init the user and password to empty string
		$linux_userpassword = $linux_username = ""
	}
	else {
		# Get the user and password of the exeute user
		$linux_username     = $Credential.UserName
		$linux_userpassword = $Credential.GetNetworkCredential().Password

		# If the server is not local we must verify of plink, without plink we can't query remote server/s.
		if( -not (ValidatePlinkExecutable))	{
			return
		}
	}

	Try {
		# Write the user name to the HTMl
		InfoMessage "Using $($linux_username) login user for Linux Activator"

		PrintDelimiter

		# Write the headline messages into HTML report
		$HeadlineMessage
		$HeadlineMessage = "<div id='Headline'>Running activation for Linux host(s) `"$($ServerArray)`".</div>"

		# Run over the Server array list
		foreach ($Server in $ServerArray) {
			# Trim the server
			$Server = $Server.trim()
			
			# Init the name of the Linux server 
			$MessageCurrentObject = $Server
			
			if (-not (Test-Connection -ComputerName $Server -Count 2 -Quiet)) {
				BadMessage "Linux server $($Server) not responding to ping, skipping this server."
			}
			else {
				# Write that ping was sucessfully
				GoodMessage "Pinging  $($Server) was successfully"

				# Reseting the counter message sections
				[int]$MessageCounter = 1

				# Fixing the secure key question in the first time
				$command = "echo connected"
				if($bLocalServer) {
					$plink_results = Invoke-Expression $command
				}
				else {
					$plink_results = Write-Output y | plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
				}

				if($plink_results -ne "connected") {
					BadMessage "Could't connect to Linux server $($Server), please check user and password."
				}
				else {
					# Write that connection is made
					GoodMessage "Connection established  to Linux server $($Server) via plink executable"

					# Checking that "lsb_release" command found
					$bLinuxDistroFound = $true
					$command           = "command -v lsb_release"
					$checking_lsb_comm = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer

					if($checking_lsb_comm) {
						# Checking the data
						$command  = "lsb_release -a | grep -E 'Release:|Distributor ID:'"
						$Splinter = ":"
						$Linux_Distro_info = (Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer) | Sort-Object

					}
					else {
						$command  = "cat /etc/os-release | grep -E '\bID=|\bVERSION_ID='"
						$Splinter = "="
						$Linux_Distro_info = (Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer) | Sort-Object

						if(-not($Linux_Distro_info)) {
							$bLinuxDistroFound = $false
						}
					}

					if($bLinuxDistroFound) {
						# Get the linux distro and version
						$Linux_OS_Type          = $Linux_Distro_info[0].split($Splinter)[1].replace("""","").trim()
						$Linux_OS_Version_print = $Linux_Distro_info[1].split($Splinter)[1].replace("""","").trim()
						$Linux_OS_Version       = [int]$Linux_OS_Version_print.split(".")[0]						
						InfoMessage "Linux distribution is: $($Linux_OS_Type)"
						InfoMessage "Linux distribution version is: $($Linux_OS_Version_print)"

						switch($Linux_OS_Type) {
							"rhel" {
								if($Linux_OS_Version -ge 7) {
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6) {
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							"centos" {
								if($Linux_OS_Version -ge 7) {
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6) {
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							"ubuntu" {
								if($Linux_OS_Version -ge 14) {
									$linuxtype = "debian7"
								}
								elseif($Linux_OS_Version -ge 12) {
									$linuxtype = "debian6"
								}
								else {
									$linuxtype = $false
								}
							}
							"debian" {
								if($Linux_OS_Version -ge 7) {
									$linuxtype = "debian7"
								}
								elseif($Linux_OS_Version -ge 6) {
									$linuxtype = "debian6"
								}
								else {
									$linuxtype = $false
								}
							}
							"suse" {
								if($Linux_OS_Version -ge 12) {
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 11) {
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							"sles" {
								if($Linux_OS_Version -ge 12) {
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 11) {
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							# Oracle Linux Server
							"ol" {
								if($Linux_OS_Version -ge 7) {
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6) {
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							# Oracle Linux Server
							"OracleServer" {
								if($Linux_OS_Version -ge 7) {
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6) {
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							Default {
								$linuxtype = $false
							}
						}
					}
					
					if(-not ($linuxtype)) {
						WarningMessage "Linux distribution is not found in the Linux OS (cat /etc/os-release | lsb_release -a)"
						WarningMessage "Contact Silk Customer Support if you are using a different version of Oracle Linux, CentOS Linux, Ubuntu, Debian or SUSE Linux"
						Start-Sleep -Seconds 3
						
						# Ask the customer what is the Linux OS Distro
						Write-host -ForegroundColor Black -BackgroundColor yellow "Please select a Linux distribution"
						Write-host -ForegroundColor Black -BackgroundColor yellow "-----------------------------------------------------"
						write-host -ForegroundColor Black -BackgroundColor White "Option A - RedHat 6.x, CentOS 6.x, Oracle 6.x, Suse 11.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option B - RedHat 7.x, CentOS 7.x, CentOS 8.x, Suse 12.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option C - Debian 6.x, Ubuntu 12.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option D - Debian 7.x, Ubuntu 14.x"

						# Choose the Linux distributions 
						$linuxtitle   = "Please select a Linux distribution"
						$linuxmessage = "Please select from the following options"
						$rhel6 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &A", "Configuring settings according to a RedHat 6 system best practices."
						$rhel7 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &B", "Configuring settings according to a RedHat 7 system best practices."
						$debian6 	  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &C", "Configuring settings according to a Debian 6 system best practices."
						$debian7 	  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &D", "Configuring settings according to a Debian 7 system best practices."

						$linuxoptions = [System.Management.Automation.Host.ChoiceDescription[]]($rhel6, $rhel7, $debian6, $debian7)
						$linuxresult  = $host.ui.PromptForChoice($linuxtitle, $linuxmessage, $linuxoptions,0) 
						
						switch ($linuxresult) {
							0 {$linuxtype = "rhel6"}
							1 {$linuxtype = "rhel7"}
							2 {$linuxtype = "debian6"}
							3 {$linuxtype = "debian7"}
						}
					}

					InfoMessage "$MessageCounter - Silk Activator - script will activate according to Linux distribution - $($linuxtype)"
					PrintDelimiter

					PrintDescription "Category: High Availability related.`nParameter type: iSCSI and Multipath Services and Packages.`nDescription:Installing the iSCSI and Multipath packages and services"
					$iscsi_n_mpio_services = UserSelections "Iscsi & MPIO Packages and Services"

					PrintDescription "Category: High Availability related.`nParameter type: The Multipath configuration settings.`nDescription:Multipathing allows the combination of multiple physical connections between a server and a storage array into one virtual device"
					$Multipath_Conf = UserSelections "Multipath Configuration"

					PrintDescription "Category: High Availability related.`nParameter type: The ioscheduler configuration.`nDescription:I/O schedulers attempt to improve throughput by reordering request access into a linear order based on the logical addresses of the data and trying to group these together"
					$ioscheduler_Conf = UserSelections "ioscheduler Configuration"

					if($iscsi_n_mpio_services) {
						# Checking the PREREQUISITES of the packages that must be installed on the machine (device-mapper-multipath* / lsscsi  / scsi-initiator-utils*)
						InfoMessage "$MessageCounter - Checking / Enabling / Installing Packages and Services "
						switch -Wildcard ($linuxtype) {
							'rhel*' {
								Install_Package "device-mapper-multipath" $linuxtype
								Install_Package "lsscsi" $linuxtype
								Install_Package "iscsi-initiator-utils" $linuxtype
							}
							'debian*' {
								Install_Package "multipath-tools" $linuxtype
								Install_Package "lsscsi" $linuxtype
								Install_Package "open-iscsi" $linuxtype
							}
						}

						PrintDelimiter

						switch -Wildcard ($linuxtype) {
							'rhel*' {
								Checking_Service "multipathd" $linuxtype
								Checking_Service "iscsid" $linuxtype
							}
							'debian*' {
								Checking_Service "multipathd" $linuxtype
								Checking_Service "iscsid" $linuxtype
								Checking_Service "open-iscsi" $linuxtype
							}
						}

						$MessageCounter++
						PrintDelimiter
					}
					else {
						InfoMessage "$MessageCounter - Skipping Linux iSCSI and MPIO Packages and Services section."
					}

					$MessageCounter++
					PrintDelimiter 

					if($Multipath_Conf) {
						# Get multipath.conf file from server
						InfoMessage "$MessageCounter - Running the Activator for MPIO configuration"
						$multipath_path = "/etc/multipath.conf"
						
						# Windows need to have two '"' each string
						if ($PSPlatform -eq $Platfrom_Windows) {
							$multipathfile = @('# Silk BP Configuration (/etc/multipath.conf)
							defaults {
							XXXXXXfind_multipaths         yes
							XXXXXXuser_friendly_names     yes
							XXXXXXpolling_interval        1
							XXXXXXverbosity               2
							}

							blacklist {
							XXXXXXdevnode ""^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*""
							XXXXXXdevnode ""^hd[a-z]""
							XXXXXXdevnode ""^sda$""
							}

							devices {
							XXXXXXdevice {
							XXXXXXXXXXXXvendor                          ""KMNRIO""
							XXXXXXXXXXXXproduct                         ""KDP""
							XXXXXXXXXXXXpath_grouping_policy            multibus
							XXXXXXXXXXXXpath_checker                    tur
							XXXXXXXXXXXXpath_selector                   ""queue-length 0""
							XXXXXXXXXXXXno_path_retry                   fail
							XXXXXXXXXXXXhardware_handler                ""0""
							XXXXXXXXXXXXfailback                        immediate
							XXXXXXXXXXXXfast_io_fail_tmo                2
							XXXXXXXXXXXXdev_loss_tmo                    3
							XXXXXXXXXXXXmax_sectors_kb                  1024
							XXXXXX}
							XXXXXXdevice {
							XXXXXXXXXXXXvendor                          ""SILK""
							XXXXXXXXXXXXproduct                         ""KDP""
							XXXXXXXXXXXXpath_grouping_policy            multibus
							XXXXXXXXXXXXpath_checker                    tur
							XXXXXXXXXXXXpath_selector                   ""queue-length 0""
							XXXXXXXXXXXXno_path_retry                   fail
							XXXXXXXXXXXXhardware_handler                ""0""
							XXXXXXXXXXXXfailback                        immediate
							XXXXXXXXXXXXfast_io_fail_tmo                2
							XXXXXXXXXXXXdev_loss_tmo                    3
							XXXXXXXXXXXXmax_sectors_kb                  1024
							XXXXXX}
							XXXXXXdevice {
							XXXXXXXXXXXXvendor                          ""SILK""
							XXXXXXXXXXXXproduct                         ""SDP""
							XXXXXXXXXXXXpath_grouping_policy            multibus
							XXXXXXXXXXXXpath_checker                    tur
							XXXXXXXXXXXXpath_selector                   ""queue-length 0""
							XXXXXXXXXXXXno_path_retry                   fail
							XXXXXXXXXXXXhardware_handler                ""0""
							XXXXXXXXXXXXfailback                        immediate
							XXXXXXXXXXXXfast_io_fail_tmo                2
							XXXXXXXXXXXXdev_loss_tmo                    3
							XXXXXXXXXXXXmax_sectors_kb                  1024
							XXXXXX}
							}

							blacklist_exceptions {
							XXXXXXproperty ""(ID_SCSI_VPD|ID_WWN|ID_SERIAL)""
							}')
						}
						else {
							$multipathfile = @('# Silk BP Configuration (/etc/multipath.conf)
							defaults {
							XXXXXXfind_multipaths         yes
							XXXXXXuser_friendly_names     yes
							XXXXXXpolling_interval        1
							XXXXXXverbosity               2
							}

							blacklist {
							XXXXXXdevnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"
							XXXXXXdevnode "^hd[a-z]"
							XXXXXXdevnode "^sda$"
							}

							devices {
							XXXXXXdevice {
							XXXXXXXXXXXXvendor                          "KMNRIO"
							XXXXXXXXXXXXproduct                         "KDP"
							XXXXXXXXXXXXpath_grouping_policy            multibus
							XXXXXXXXXXXXpath_checker                    tur
							XXXXXXXXXXXXpath_selector                   "queue-length 0"
							XXXXXXXXXXXXno_path_retry                   fail
							XXXXXXXXXXXXhardware_handler                "0"
							XXXXXXXXXXXXfailback                        immediate
							XXXXXXXXXXXXfast_io_fail_tmo                2
							XXXXXXXXXXXXdev_loss_tmo                    3
							XXXXXXXXXXXXmax_sectors_kb                  1024
							XXXXXX}
							XXXXXXdevice {
							XXXXXXXXXXXXvendor                          "SILK"
							XXXXXXXXXXXXproduct                         "KDP"
							XXXXXXXXXXXXpath_grouping_policy            multibus
							XXXXXXXXXXXXpath_checker                    tur
							XXXXXXXXXXXXpath_selector                   "queue-length 0"
							XXXXXXXXXXXXno_path_retry                   fail
							XXXXXXXXXXXXhardware_handler                "0"
							XXXXXXXXXXXXfailback                        immediate
							XXXXXXXXXXXXfast_io_fail_tmo                2
							XXXXXXXXXXXXdev_loss_tmo                    3
							XXXXXXXXXXXXmax_sectors_kb                  1024
							XXXXXX}
							XXXXXXdevice {
							XXXXXXXXXXXXvendor                          "SILK"
							XXXXXXXXXXXXproduct                         "SDP"
							XXXXXXXXXXXXpath_grouping_policy            multibus
							XXXXXXXXXXXXpath_checker                    tur
							XXXXXXXXXXXXpath_selector                   "queue-length 0"
							XXXXXXXXXXXXno_path_retry                   fail
							XXXXXXXXXXXXhardware_handler                "0"
							XXXXXXXXXXXXfailback                        immediate
							XXXXXXXXXXXXfast_io_fail_tmo                2
							XXXXXXXXXXXXdev_loss_tmo                    3
							XXXXXXXXXXXXmax_sectors_kb                  1024
							XXXXXX}
							}

							blacklist_exceptions {
							XXXXXXproperty "(ID_SCSI_VPD|ID_WWN|ID_SERIAL)"
							}')
						}
						
						# $multipathfile = $multipathfile | Out-String -Stream
						$multipathfile = (($multipathfile -split "`n") | ForEach-Object {$_.TrimStart()} | ForEach-Object {$_.replace("XXXXXX","         ")}) -join "`n"

						$command = "test -f $($multipath_path) && echo true || echo false"
						$multipathconffileexists = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer

						if ($multipathconffileexists -match "true") {
							$command = "cat $($multipath_path)"
							$multipathconf = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
							
							# 	Write the Multipath into the HTML file
							InfoMessage "File - $($multipath_path) - Content:"
							handle_string_array_messages ($multipathconf |out-string).Trim() "Data"

							# Backup the orginal one 
							$backup_multipath_file = $multipath_path.Replace(".conf","_backup.conf")
							InfoMessage "Backing up file - $($multipath_path) ,to - $($backup_multipath_file)"
							$command = "sudo cp $($multipath_path) $($backup_multipath_file)"
							$command_multipath_backup_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						}
						else {
							BadMessage "multipath.conf file not found on $($multipath_path), we will create it"						
						}

						# $command_multipath_write = "sudo bash -c 'sudo echo '$($multipathfile)' > $($multipath_path)''"
						$command = "echo '$multipathfile' | sudo tee $($multipath_path)"
						InfoMessage "Setting the multipath.conf according to Silk's Best Practices"
						$command_multipath_write_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						GoodMessage "multipath.conf file was set with Silk's best practices"
						
						# If it was created from windows (Plink remotlly)
						if ($PSPlatform -eq $Platfrom_Windows) {						
							$command = "sudo sed -i -e 's/\r//g' $($multipath_path)"
							$command_multipath_write_dos2unix_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer							
							GoodMessage "multipath.conf file was set as dos2unix, Removed ^M characters"
						}

						# Restart and Enable the multipathd
						$command  = "sudo systemctl enable multipathd.service"
						$multipath_command_enable_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						$command = "sudo systemctl restart multipathd"
						$multipath_command_restart_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						GoodMessage "multipathd service executed a restarted and enabled"
					}
					else {
						InfoMessage "$MessageCounter - Skipping Linux Multipath Configuration"
					}

					$MessageCounter++
					PrintDelimiter

					if($ioscheduler_Conf) {
						InfoMessage "$MessageCounter - Running the Activator for ioscheduler configuration"	

						$udev_Silk_BP_data = @('# Silk BP Configuration for 98-sdp-io.rules')
						if ($PSPlatform -eq $Platfrom_Windows) {
							# UDEV for 2002* 
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""2002*"", ATTR{queue/scheduler}=""noop""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""2002*"", ATTR{device/timeout}=""300""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""2002*"", ATTR{queue/scheduler}=""none""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-2002*"", ATTR{queue/scheduler}=""noop""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-2002*"", ATTR{queue/scheduler}=""none""'
							
							# UDEV for 280b*
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""280b*"", ATTR{queue/scheduler}=""noop""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""280b*"", ATTR{device/timeout}=""300""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""280b*"", ATTR{queue/scheduler}=""none""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-280b*"", ATTR{queue/scheduler}=""noop""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-280b*"", ATTR{queue/scheduler}=""none""'
						}
						else {
							# UDEV for 2002* 
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="2002*", ATTR{queue/scheduler}="noop"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="2002*", ATTR{device/timeout}="300"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="2002*", ATTR{queue/scheduler}="none"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-2002*", ATTR{queue/scheduler}="noop"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-2002*", ATTR{queue/scheduler}="none"'
							
							# UDEV for 280b*
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="280b*", ATTR{queue/scheduler}="noop"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="280b*", ATTR{device/timeout}="300"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="280b*", ATTR{queue/scheduler}="none"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-280b*", ATTR{queue/scheduler}="noop"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-280b*", ATTR{queue/scheduler}="none"'
						}
						# Get /usr/lib/udev/rules.d/98-sdp-io.rules file from server
						$udev_Silk_BP_data = $udev_Silk_BP_data | Out-String -Stream
						
						# Get udev.rules file from server 
						$udev_file_path = "/usr/lib/udev/rules.d/98-sdp-io.rules"

						$command = "test -f $($udev_file_path) && echo true || echo false"
						$ioschedulersfileexists = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						
						if($ioschedulersfileexists -match "true") {
							$command = "sudo cat $udev_file_path"
							$ioschedulersData = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer

							# 	Write the 98-sdp-io.rules into the HTML file
							InfoMessage "File - $($udev_file_path) - Content Before Overwrite:"
							handle_string_array_messages ($ioschedulersData |out-string).trim() "Data"

							# Backup the orginal one 
							$backup_udev_file = $udev_file_path.Replace(".rules","_backup.rules")
							InfoMessage "Backing up file - $($udev_file_path) ,to - $($backup_udev_file)"
							$command = "sudo cp $($udev_file_path) $($backup_udev_file)"
							$command_udev_backup_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						}
						else {
							WarningMessage "98-sdp-io.rules not found on $($udev_file_path), We will create it"
						}

						# Overwrite the current schedulers values
						$udev_Silk_BP_data = $udev_Silk_BP_data -join "`n"
						$command = "echo '$udev_Silk_BP_data' | sudo tee $($udev_file_path)"
						$ioschedulersfileexists = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						GoodMessage "Silk io-schedulers.rules file was set with Silk's best practices"

						#rewrites the io-schedulers.rules according to Silks BP
						InfoMessage "Reloading the UDEV rules"
						$command = 'sudo udevadm trigger && sudo udevadm settle'
						$command_reload_udev_output = Invoke-LinuxCommand -Command $command -Server $Server -LinuxUserName $linux_username -LinuxUserPassword $linux_userpassword -UseLocalServer $bLocalServer
						GoodMessage "udevadm trigger && udevadm settle commands executed"
					}
					else {
						InfoMessage "$MessageCounter - Skipping Linux ioscheduler Configuration"
					}

					$MessageCounter++
					PrintDelimiter
				}
			}

			InfoMessage "Activation for $($Server) completed."

			PrintDelimiter
			$SDPBPHTMLBody += "<div id='host_space'></div>"
		}
	}
	
	catch {
		# Get the exception messages
		$ExceptionMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber

		BadMessage "Caught exception during Linux Activator at line: $($line)"
		BadMessage $ExceptionMessage
	}
	
	Finally {
		# Once all data is collected - output into HTML
		$MessageCurrentObject = "Finished activating`n"
		
		PrintDelimiterServer
	}
}
#endregion
##################################### End Activator functions ##############################################################

##################################### Main #################################################################################
#region Main Section
if($bExitMenu) {
	write-host "PSVersion is - $($PSVersionTable.PSVersion.Major)"
	write-host "PSEdition is - $($PSVersionTable.PSEdition)"
	Write-Warning -Message "PowerShell version failed in the prerequisites,`nPlease read pre-requisites section in Silk guide.`nGood Bye!"
	Write-Warning -Message "`n`tPress any key to continue...";
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); 
	return
}
else {
	# Global parameter for messages
	Set-Variable -Name SDP_Version -Option AllScope -Scope Script
	Set-Variable -Name MessageCurrentObject -Option AllScope -Scope Script
	Set-Variable -Name HostType -Option AllScope -Scope Script
	Set-Variable -Name SDPBPHTMLBody -Value "" -Option AllScope -Scope Script

	#Global parameter for all Functions for the HTML output file
	$TempOrigColor = $host.ui.RawUI.ForegroundColor
	Set-Variable -Name OrigColor -Value $TempOrigColor -Option AllScope -Scope Script

	# clear the console
	 clear-host

	# Start time 
	$bDate = Get-date

	$MessageCurrentObject = "Silk Activator pre-Checking Section"

	# Print the PowerShell versions and edtion
	InfoMessage "Silk Activator for Prodcut - $($ActivatorProduct)"
	InfoMessage "PowerShell Version is - $($PSVersionTable.PSVersion.Major)"
	InfoMessage "PowerShell Edition is - $($PSVersionTable.PSEdition)"

	if (CheckAdminUserCrossPlatform) {	
		# Global Variables
		[string]$HostType = ""

		#region Script Choice Selection Host Type		
		$optionLinux   = New-Object System.Management.Automation.Host.ChoiceDescription '&Linux'  , 'Host Type: Linux'
		$optionWindows = New-Object System.Management.Automation.Host.ChoiceDescription '&Windows', 'Host Type: Windows'
		$optionExit    = New-Object System.Management.Automation.Host.ChoiceDescription "&Exit"   , "Exit"

		$optionsContainer = [System.Management.Automation.Host.ChoiceDescription[]]($optionLinux, $optionWindows,$optionExit)

		$optiontitle    = 'The Silk Best Practices Activator Script'
		$optionmessage  = 'Choose your Host Type'
		$HostTypeResult = $host.ui.PromptForChoice($optiontitle, $optionmessage, $optionsContainer, 2)
		$bExit          = $False
		
		switch ($HostTypeResult) {
			0 { $HostType = "Linux"   }
			1 { $HostType = "Windows" }
			2 { 
				Write-Host "Exiting, Good Bye." -ForegroundColor Yellow
				$bExit = $True
				$HostType = "Exit"
				start-sleep -seconds 1
			}
		}
		#endregion

		if(-not($bExit)) { 
			switch($HostType) {
				# Linux
				"Linux" {
					Write-Host -ForegroundColor Yellow "This script gets Linux server/s as inputs and activate is according to Silk's best practices."
					[string]$LinuxServerString  = ""
					[string[]]$LinuxServerarray = @()
					$LinuxServerString = read-host  ("Linux Server -Specify the Servers names or IP addresses to connect to (comma as a separation between them).`nPress enter if you want check local server with logon user")
					$LinuxServerString = TrimHostNames $LinuxServerString
					$LinuxServerarray  = $LinuxServerString.split(",")

					# Check the Windows servers, if it empty run this with local user
					if ([string]::IsNullOrEmpty($LinuxServerarray)) {
						Linux_Activator $LinuxServerarray
					}
					else {
						$Credential = $host.ui.PromptForCredential("Silk BP credentials", "Please enter your Linux username and password.", "", "")
						Linux_Activator $LinuxServerarray $Credential 
					}
				}
				
				# Windows
				"Windows" {
					Write-Host -ForegroundColor Yellow "This script gets Windows servers as input and validates servers parameters according to Silk's best practices."	
					[string]$WindowsServerString  = ""
					[string[]]$WindowsServerarray = @()
					$WindowsServerString = read-host  ("Windows Server - Specify the Server name/s or IP adress/es to connect to (comma as a separation between them).`nPress enter if you want check local server with logon user")
					$WindowsServerString = TrimHostNames $WindowsServerString
					$WindowsServerarray  = $WindowsServerString.split(",")

					# Check the Windows servers, if it empty run this with local user
					if ([string]::IsNullOrEmpty($WindowsServerarray)) {
						Windows_Activator $WindowsServerarray
					}
					else {
						# Choose user for the Activator
						$WinCredential = read-host ("Windows Credential - using $(whoami) Login user (Y/N), N = or diffrenet user")

						while (($WinCredential -notmatch "[yY]") -and ($WinCredential -notmatch "[nN]")) {
							write-host -ForegroundColor Red "Invalid entry, please enter 'Y' or 'N' to continue"
							$WinCredential = read-host ("Windows Credential - using $(whoami) Login user (Y/N), N = or diffrenet user")
						}

						if($WinCredential -match "[yY]") {
							Windows_Activator $WindowsServerarray
						}
						else {
							$Credential = $host.ui.PromptForCredential("Silk Windows BP credentials", "Please enter your Windows username and password.", "", "NetBiosUserName")
							Windows_Activator $WindowsServerarray $Credential 
						}
					}
				}
			}

			# Begin and End Times
			$eDate = Get-date
			$tDate = New-TimeSpan -Start $bDate -End $eDate

			# Add end and total time to HTML
			$SDPBPHTMLBody += "<div id='host_space'>Validator Execution Time</div>"
			InfoMessage "Time - Validator starting time is - $($bDate)"
			InfoMessage "Time - Validator ending time is - $($eDate)"
			InfoMessage "Time - Validator total time (Sec) - $($tDate.TotalSeconds)"

			# Generate HTML Report File
			InfoMessage "Creating HTML Report..."
			GenerateHTML
		}
	}

	# Script has complted, Exit the script
	$MessageCurrentObject = "Silk Activator Ended, Good Bye!"
	GoodMessage "Silk Activator Ended, Good Bye!"
	start-sleep -seconds 3
}
#endregion
##################################### End Main #############################################################################