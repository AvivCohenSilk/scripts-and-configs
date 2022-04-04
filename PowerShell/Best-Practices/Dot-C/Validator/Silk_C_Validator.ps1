<#
 .SYNOPSIS
 This script gets various arguments and checks the Silk BP against the input.

 .DESCRIPTION
 This script gets a Host Type as inputs and validation according to Silk's best practices. 
 This script validates Windows and Linux operation system types.

 Versions:
 09-Dec-2021 - Current version V1.0.0
 12-Dec-2021 - Current version V1.0.1
 20-Dec-2021 - Current version V1.0.2
 01-Jan-2022 - Current version V1.0.3
 22-Feb-2022 - Current version V1.0.4
    
 .NOTES
 Dec 2021
 Script Silk Validator for DotC product created 

 Jan 2022
 * (Win) Adjust MPIO DiskTimeoutValue value 45 -> 100
 * (Lin) Adjust multipath.conf to support new vendor and product
 
 Feb 2022 
 * (Lin) Fix recursive_bracket_parser function to handle "#" marks.
#>

# Ensure the minimum version of the PowerShell Validator is 5 and above
#Requires -Version 5

##################################### Silk Validator begin of the script - Validate ########################################
#region Validate Section
# Configure general the SDP Version
[string]$SDP_Version = "1.0.4"

# Checking the PS version and Edition
[string]$ValidatorProduct  = "DotC"
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
# Must be desktop and on Windows env
elseif($PSVersionTable.PSEdition -eq "Desktop") {	
	if(!($Platfrom_Windows)){Set-Variable Platfrom_Windows -option Constant -Scope Script -value "Win32NT"}
	$PSPlatform = "Win32NT"
}
else {
	# PowerShell PSEdition is not Core or Desktop, Not supported.
	$bExitMenu = $true
}
#endregion
##################################### End Silk Validator begin of the script - validate ####################################

##################################### Global functions #####################################################################
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
	Write-host "$($MessageCurrentObject) - [Data] - $args"
	$host.ui.RawUI.ForegroundColor = $OrigColor
	$SDPBPHTMLBody += "<div id='DataMessage'>$($MessageCurrentObject) - [Data] - $args</div>"
}

Function DataMessageBlock {
	$host.ui.RawUI.ForegroundColor = "Cyan"
	Write-host "$($MessageCurrentObject) - [Data] - $args"
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
	$OutputFilename = "SDP_$($ValidatorProduct)_$($HostType)_Validation_$($CurrentDate.Month)-$($CurrentDate.Day)-$($CurrentDate.Year)_$($CurrentDate.Hour)-$($CurrentDate.Minute)-$($CurrentDate.Second).html"
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
	Write-Output "<title>Silk Best Practices Validator - $($CurrentDate.Month)-$($CurrentDate.Day)-$($CurrentDate.Year)_$($CurrentDate.Hour)-$($CurrentDate.Minute)-$($CurrentDate.Second)</title>" | Out-File -Append $OutputFile
	
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
	Write-Output "<div id='Headline'>Silk Data Platform host validation script running version - $($SDP_Version).</div>" | Out-File -Append $OutputFile
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

#region Main Functions Helpers
# CheckAdminUserCrossPlatform Function - Checking the current user in Windows and Linux environment. You must run as administrator (Windows)
function CheckAdminUserCrossPlatform {
	if ($PSPlatform -eq $Platfrom_Linux) {
		if ($(whoami) -eq "root") {
			GoodMessage "Running with a root user on Linux OS" 
			return $True
		}
		else {
			WarningMessage "The script is not running with a root admin - but with a user $(whoami)" 
			return $true
		}
	}
	elseif ($PSPlatform -eq $Platfrom_Windows) {
		if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))	{
			WarningMessage "The script is not running as administrator - switching to run as administrator and run again"
			return $False
		}
		else {
			GoodMessage "Running as an Administrator, on Windows OS version - $((Get-CimInstance Win32_OperatingSystem).version)" 
			return $True
		}
	}
	else {
		BadMessage "The platform is not Windows or Linux, Please rerun the validator script on one of those platforms." 
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
##################################### End Global functions #################################################################

##################################### Validator Main functions #############################################################
#region Windows_Validator
function Windows_Validator {
	[cmdletbinding()] 
	Param(	
		[parameter()]
		[String[]]$WinServerArray,	
		[System.Management.Automation.PSCredential]	
		$Credential = [System.Management.Automation.PSCredential]::Empty
		)

	#region Get-SilkSessions
	function Get-SilkSessions {
		[cmdletbinding()] 
		Param(	
			[parameter()]
			[CimSession]$CIMsession	
		)

		$allConnections = Get-IscsiConnection -CimSession $CIMsession

		$returnArray = @()

		$allTargetIPs = ($allConnections | Select-Object TargetAddress -Unique).TargetAddress

		foreach ($i in $allTargetIPs) {
			$o = New-Object psobject
			$o | Add-Member -MemberType NoteProperty -Name "CNode IP" -Value $i
			$o | Add-Member -MemberType NoteProperty -Name "Host IP" -Value ($allConnections | Where-Object {$_.TargetAddress -eq $i} | Select-Object InitiatorAddress -Unique).InitiatorAddress
			$configured = ($allConnections | Where-Object {$_.TargetAddress -eq $i} | Get-IscsiSession -CimSession $CIMsession | Where-Object {$_.IsDiscovered}).count
			if ($configured) {
				$o | Add-Member -MemberType NoteProperty -Name "Configured Sessions" -Value $configured
			} else {
				$o | Add-Member -MemberType NoteProperty -Name "Configured Sessions" -Value 0
			}

			$connected = ($allConnections | Where-Object {$_.TargetAddress -eq $i}).count
			if ($connected) {
				$o | Add-Member -MemberType NoteProperty -Name "Connected Sessions" -Value $connected
			} else {
				$o | Add-Member -MemberType NoteProperty -Name "Connected Sessions" -Value 0 
			}
			$o | Add-Member -MemberType NoteProperty -Name "Silk IQN" -Value ($allConnections | Where-Object {$_.TargetAddress -eq $i} |Get-IscsiSession -CimSession $CIMsession | Select-Object TargetNodeAddress -Unique).TargetNodeAddress

			$returnArray += $o
		}

		if ($returnArray) {
			return $returnArray | Format-Table
		} else {
			return $null
		}
	}
	#endregion

	# Start script initialization	
	$MessageCurrentObject = "Windows Validator"
	InfoMessage "Validating Windows Server"

	# Function Local variables
	[Boolean]$bool_local_user = $false

	# Write the user name to the HTMl
	if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
		InfoMessage "Using $($Credential.UserName) login user for Windows Validator"
	}
	else {
		InfoMessage "using $(whoami) login user for Windows Validator"
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
		$HeadlineMessage = "<div id='Headline'>Running validation for Windows host(s) `"$($WinServerArray)`".</div>"

		foreach ($WinServer in $WinServerArray)	{
			PrintDelimiter

			# Trim the server name
			$WinServer = $WinServer.Trim()
			
			# initialization Windows Server for Messages Function
			$MessageCurrentObject = $WinServer
			
			# Test coneection to the windows server, if no ping that is meaning that we could not reach it, script finish.
			if (-not (Test-Connection -ComputerName $WinServer -Count 2 -Quiet)) {
				BadMessage "The windows Server $($WinServer) not responding to ping (Checking 2 times), skipping this server..."
			}
			else {
				# Write that ping was sucessfully
				GoodMessage "Pinging to $($WinServer) was successfully"

				if($bool_local_user) {
					$pssessions = New-PSSession
				}
				else {
					# Initialization pssessions
					if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
						$pssessions = New-PSSession -ComputerName $WinServer -Credential $Credential -Authentication Negotiate -ErrorAction Stop
					}
					else {
						$pssessions = New-PSSession -ComputerName $WinServer -Authentication Kerberos -ErrorAction Stop
					}
				}

				# Reseting the counter message sections
				[int]$MessageCounter = 1

				# Write to html the OS version and caption
				InfoMessage "$MessageCounter - Windows Server Information"
				$WinOSVersionCaption = (Invoke-Command -Session $pssessions -ScriptBlock {(Get-WmiObject -class Win32_OperatingSystem).Caption})
				$WinOSVersion        = (Invoke-Command -Session $pssessions -ScriptBlock {[Environment]::OSVersion})
				DataMessage "Windows OS Caption is - $($WinOSVersionCaption)"
				DataMessage "Windows OS Version is - $($WinOSVersion.VersionString)"

				# Write the Windows Server Extra data (CPU & Memory)
				$WinOSCPU    = (Invoke-Command -Session $pssessions -ScriptBlock {(Get-CimInstance Win32_ComputerSystem)})
				$WinOSMemory = (Invoke-Command -Session $pssessions -ScriptBlock {((Get-CimInstance CIM_PhysicalMemory).Capacity | Measure-Object -Sum).Sum / (1024 * 1024 * 1024)})

				DataMessage "Number Of Processors (Sockets) - $($WinOSCPU.NumberOfProcessors)"
				DataMessage "Number Of Logical Processors (vCPUs) - $($WinOSCPU.NumberOfLogicalProcessors)"
				DataMessage "Total Physical Memory (GiB) - $($WinOSMemory)"

				$MessageCounter++
				PrintDelimiter 

				#validating iSCSI BP
				InfoMessage "$MessageCounter - Running validation for iSCSI configuration"
				$MSiSCSI = (invoke-Command -Session $pssessions -ScriptBlock {Get-WmiObject -Class Win32_Service -Filter "Name='MSiSCSI'"})
				if($MSiSCSI) {
					if ($MSiSCSI.State -match "Running") {
						GoodMessage "MSiSCSI service is running"

						# Checking if the service startup type is set to automatic
						if ($MSiSCSI.StartMode -eq "Auto") {
							GoodMessage "MSiSCSI service is set to start automatically"	
						}
						else {
							BadMessage "MSiSCSI service is not set to start automatically but set to $($MSiSCSI.StartMode)"
						} 
					}
					else { 
						BadMessage "MSiSCSI service is not running, Current state is - $($MSiSCSI.State)"
					}
				}
				else { 
					BadMessage "iSCSI service not found"
				}

				$MessageCounter++
				PrintDelimiter

				# Validating core services and MPIO
				InfoMessage "$MessageCounter - Running validation for Multipath configuration (Windows Feature and Optional Feature)"
				$MultipathIO = (invoke-Command -Session $pssessions -ScriptBlock {Get-WindowsFeature -Name Multipath-IO})
				
				# Multipath-IO Feature
				if($MultipathIO) {
					if ($MultipathIO.InstallState -eq "Installed") {
						GoodMessage "Multipath value is Installed properly and configured according to Silk's BP"

						# Multipath-IO Optional Feature
						$MultipathIOFeature = (invoke-Command -Session $pssessions -ScriptBlock {(get-WindowsOptionalFeature -Online -FeatureName MultipathIO)})
						if($MultipathIOFeature) {
							if ($MultipathIOFeature.State -match "Enabled")	{
								GoodMessage "Multipath Windows Optional Feature is properly configured according to Silk's BP"
							}
							else { 
								BadMessage "Multipath Windows Optional Feature is not properly configured according to Silk's BP, The current state is $($MultipathIOFeature.State), Please Enabled it and if needed reboot the server!"
							}
						}
						else { 
							BadMessage "Multipath Optional Feature is not with Enabled state"
						}
					}
					else { 
						BadMessage "Multipath is not installed, The current state is $($MultipathIO.InstallState), Please installed it and if needed reboot the server!"
					}
				}
				else { 
					BadMessage "Multipath Feature is not installed"
				}
			
				# MPIO sections  Continully only if the Multipath-IO and MultipathIO Feature are installed and enabled
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
					InfoMessage "MPIO Settings Section :"

					# Print the MPIO into the html
					handle_string_array_messages $MPIO_out "Data"

					# Checking the MSDSM supported hardware list
					$MSDSMSupportedHW = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMSupportedHW -VendorId MSFT2005 -ProductId iSCSIBusType_0x9})
					if ($MSDSMSupportedHW) {
						GoodMessage "MPIO DSM value is properly configured according to Silk's BP"
					}
					else {
						BadMessage "MPIO DSM is not set to -VendorId MSFT2005 -ProductId iSCSIBusType_0x9, or could not found it, try to run Get-MSDSMSupportedHW command"
					}

					if ($PathVerificationState -match "Enabled") {
						GoodMessage "PathVerificationState value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "PathVerificationState is not Enabled, Current Value is $($PathVerificationState)"
					}
					
					if ($PathVerificationPeriod -match "1")	{
						GoodMessage "PathVerificationPeriod value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "PathVerificationPeriod value is not set 1, Current Value is $($PathVerificationPeriod)"
					}
						
					if ($RetryCount -match "3")	{
						GoodMessage "RetryCount value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "RetryCount value is not set 3, Current Value is $($RetryCount)"
					}
					
					if ($DiskTimeOutValue -match "100") {
						GoodMessage "DiskTimeOutValue value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "DiskTimeOutValue value is not set 100, Current Value is $($DiskTimeOutValue)"
					}
					
					if ($RetryInterval -match "3") {
						GoodMessage "RetryInterval value is properly configured according to Silk's BP."
					}
					else { 
						BadMessage "RetryInterval value is not set 3, Current Value is $($RetryInterval)"
					}
					
					if ($PDORemovePeriod -match "20") {
						GoodMessage "PDORemovePeriod value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "PDORemovePeriod value is not set 20, Current Value is $($PDORemovePeriod)"
					}

					if ($UseCustomPathRecoveryTime -match "Enabled") {
						GoodMessage "UseCustomPathRecoveryTime value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "UseCustomPathRecoveryTime value is not set Enabled, Current Value is $($UseCustomPathRecoveryTime)"
					}

					if ($CustomPathRecoveryTime -match "20") {
						GoodMessage "CustomPathRecoveryTime value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "CustomPathRecoveryTime value is not set 20, Current Value is $($CustomPathRecoveryTime)"
					}

					# Load Balance and Failover Policy
					$MSDSMGlobalDefaultLoadBalancePolicy = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMGlobalDefaultLoadBalancePolicy})
					if($MSDSMGlobalDefaultLoadBalancePolicy) {
						if($MSDSMGlobalDefaultLoadBalancePolicy -match "LQD") {
							GoodMessage "Microsoft Global load balance policy value is properly configured according to Silk's BP"
						}
						else { 
							BadMessage "Microsoft Global load balance policy is not set to LQD but set to - $($MSDSMGlobalDefaultLoadBalancePolicy)"
						}
					}
					else { 
						BadMessage "Could not get the state of server global load balance policy, run Get-MSDSMGlobalDefaultLoadBalancePolicy command for more details." 
					}

					# MSDSMAutomaticClaimSettings - Gets settings for MSDSM automatically claiming SAN disks for MPIO.
					$MSDSMAutomaticClaimSettings = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMAutomaticClaimSettings})
					if($MSDSMAutomaticClaimSettings["iSCSI"]) {
						GoodMessage "MSDSM automatically claiming SAN disks for MPIO value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "MSDSM automatically claiming SAN disks for MPIO value is not properly configured according to Silk's BP - iSCSI is set to false or not found."
					}
				}
				else {
					BadMessage "MPIO is not fully installed or Enabled, because of that, we can't continue with validate the MPIO Settings"
				}

				$MessageCounter++
				PrintDelimiter

				# Load Balance and Failover Policy for Individual Volumes
				InfoMessage "$MessageCounter - Running validation for Load Balance and Failover Policy for Individual Volumes"
				$Server_KMNRIO_PD = (invoke-Command -Session $pssessions -ScriptBlock {(Get-PhysicalDisk | Where-Object {$_.FriendlyName -match "KMNRIO KDP"} | Sort-Object DeviceID | `
				Select-object SerialNumber,@{N="DiskNumber";E={($_ | Get-PhysicalDiskStorageNodeView | Select-Object DiskNumber).DiskNumber}},`
				@{N="LoadBalancePolicy";E={($_ | Get-PhysicalDiskStorageNodeView | Select-Object LoadBalancePolicy).LoadBalancePolicy}})})

				# Check the PD count 
				if($Server_KMNRIO_PD) {
					foreach ($PD_Temp in $Server_KMNRIO_PD)	{
						# Check for each Individual if it LQD or not
						if ($PD_Temp.LoadBalancePolicy -match "Least Queue Depth")	{
							GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Least Queue Depth)"
						}
						else {
							BadMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (Least Queue Depth) but set to - $($PD_Temp.LoadBalancePolicy)" 
						}
					}
				}
				else {
					InfoMessage "No SILK SDP Disks found on the server."
				}
				
				$MessageCounter++
				PrintDelimiter 
				
				InfoMessage "$MessageCounter - Running validation for Disk Defrag configuration" 
				$ScheduledDefragTask = (invoke-Command -Session $pssessions -ScriptBlock {(Get-ScheduledTask ScheduledDefrag).state})
				if($ScheduledDefragTask) {
					if($ScheduledDefragTask.value -match "disabled") {
						GoodMessage " Scheduled Disk Fragmentation policy value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "Scheduled Disk Fragmentation is not set to Disabled but to $($ScheduledDefragTask.value)" 
					}
				}
				else { 
					BadMessage "Scheduled Disk Fragmentation is not found on the windows Scheduled Task" 
				}

				$MessageCounter++
				PrintDelimiter

				InfoMessage "$MessageCounter - Running validation for Silk iSCSI Sessions" 
				# Get the silk sessions	
				if($bool_local_user) {
					$CIMsession = New-CimSession
				}
				else {
					# Initialization pssessions
					if($Credential -ne [System.Management.Automation.PSCredential]::Empty)	{
						$CIMsession = New-CimSession -ComputerName $WinServer -Credential $Credential -Authentication Negotiate
					}
					else {
						$CIMsession = New-CimSession -ComputerName $WinServer -Authentication Kerberos
					}
				}

				# Get the silk iSCSI Sessions
				$SilkSessions = Get-SilkSessions -CIMsession $CIMsession
				if($SilkSessions) {
					handle_string_array_messages ($SilkSessions | Out-String).Trim() "Data"
				}
				else {
					InfoMessage "No Silk iSCSI Sessions found."
				}

				$MessageCounter++
				PrintDelimiter

				InfoMessage "$MessageCounter - Running validation for Network Adapter" 
				# Get the silk iSCSI Sessions
				$NetAdapters = Get-NetAdapter -CIMsession $CIMsession
				if($NetAdapters) {
					handle_string_array_messages ($NetAdapters | Out-String).Trim() "Data"
				}
				else {
					InfoMessage "Could not get the network adapters"
				}

				PrintDelimiter
				
				# Remove the CIM session
				if(![string]::IsNullOrEmpty($CIMsession.Id)) {
					#Disconwnect from the server
					Get-CimSession -Id $($CIMsession.Id) | Remove-CimSession -Confirm:$false -ErrorAction SilentlyContinue
					$CIMsession = $null
					InfoMessage "Remove the CimSession"
				}

				# Remove the PSSession
				if(![string]::IsNullOrEmpty($pssessions.Id)) {
					#Remove the Session from the server
					Get-PSSession -Id $($pssessions.Id) | Remove-PSSession -Confirm:$false -ErrorAction SilentlyContinue
					$pssessions = $null
					InfoMessage "Disconnected from $($WinServer) and remove the PSSession"
				}
			}
			
			InfoMessage "Validation for $($WinServer) completed."

			PrintDelimiter
			$SDPBPHTMLBody += "<div id='host_space'></div>"
		}
	}
	catch {
		# Get the exception messages
		$ExceptionMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		BadMessage "Caught exception during Windows Validator at line: $($line)"
		BadMessage $ExceptionMessage
	}
	
	Finally {
		# Once all data is collected - output into HTML
		$MessageCurrentObject = "Finished Validating`n"

		PrintDelimiterServer

		if(![string]::IsNullOrEmpty($pssessions.Id)) {
			#Disconwnect from the server
			Get-PSSession -Id $($pssessions.Id) | Remove-PSSession -Confirm:$false -ErrorAction SilentlyContinue
			$pssessions = $null
			InfoMessage "Disconnected from $($WinServer)"
		}
	}
}
#endregion

#region Linux_Validator
function Linux_Validator {	
	[cmdletbinding()] 
	Param(
		[parameter()]
		[string[]]$ServerArray,
		[System.Management.Automation.PSCredential] 
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	#region InternalSubFunctions
	# Internal Sub Functions
	Function ValidatePlinkExecutable {
		InfoMessage "Validate Plink Executable."
		$Plink_Installed = $false

		try	{
			# get the plink command
			$Plink_command = Get-Command -Name plink

			if ($Plink_command) {
				$Plink_min_version =  0.74
				$Plink_Source  = $Plink_command.Source
				$Plink_release = (&$plink_source -V | select-string "plink: Release").ToString().replace("plink: Release ","").trim()
				
				# Check if the version is only numbers
				if($Plink_release -match "^[\d\.]+$") {
					if($Plink_release -ge $Plink_min_version) {
						InfoMessage "plink (version - $($Plink_release)) is installed at $Plink_Source, and we can continue to validate Linux initiator/s."
						GoodMessage "Plink Command checks passed."
						$Plink_Installed = $True
					}
					else {
						BadMessage "plink is installed at $Plink_Source,yet it version must be above version $($Plink_min_version)"
					}
				}
				else {
					BadMessage "plink is installed at $Plink_Source,yet can't determine the plink version $($Plink_release)"
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

	#region ValidateAttrinuteInIoschedulers
	Function ValidateAttrinuteInMpio {
		Param(
		[string]$Mpio_Section_Name,
		[string[]]$Mpio_Section_Data,
		[string]$Parameter_name,
		[string[]]$Parameter_value_array
		)

		[System.Boolean]$bFound = $false

		$Mpio_Checking_Value = ($Mpio_Section_Data) -match ($Parameter_name)
		if ($Mpio_Checking_Value) {
			foreach($mpioRow in $Mpio_Checking_Value.Trim().Split("`n").Trim()) {
				if(($mpioRow -match $Parameter_value_array[0]) -or ($mpioRow -match [regex]::escape($Parameter_value_array[0]))) {
					GoodMessage "Section $($Mpio_Section_Name) - Parameter $($Parameter_name) - value is properly configured according to Silk's BP"
					$bFound = $true
					break
				}
			}

			if(!$bFound) {
				BadMessage "Section $($Mpio_Section_Name) - Parameter $($Parameter_name) value with $($Parameter_value_array[1]) value is missing or configured wrongly, Please check the Silk BP."
			}
		}
		else { 
			BadMessage "Section $($Mpio_Section_Name) - Parameter $($Parameter_name) is missing in the multipath.conf file"
		}
	}
	#endregion

	#region ValidateAttrinuteInIoschedulers
	Function ValidateAttrinuteInIoschedulers {
		Param(
		[string[]]$ioschedulers_Section,
		[string]$Parameter_name,
		[string[]]$Parameter_value_array
		)

		[System.Boolean]$bFound = $false

		$Parameter_Display_name = $Parameter_name.Replace("}.*","-")
		$ioschedulers_Checking_Value = ($ioschedulers_Section) -match ($Parameter_name)
		if ($ioschedulers_Checking_Value) {
			foreach($ioschedulersRow in $ioschedulers_Checking_Value.Trim().Split("`n").Trim())	{
				if(($ioschedulersRow -match $Parameter_value_array[0]) -or ($ioschedulersRow -match [regex]::escape($Parameter_value_array[0]))) {
					GoodMessage "$($Parameter_name) value is properly configured according to Silk's BP"
					$bFound = $true
					break
				}
			}

			if(!$bFound) {
				BadMessage "$($Parameter_name) value with $($Parameter_value_array[1]) value is missing or configured wrongly, Please check the Silk BP."
			}
		}
		else { 
			BadMessage "ioschedulers.conf is missing $($Parameter_Display_name) parameter"
		}
	}
	#endregion

	#region recursive_bracket_parser
	Function recursive_bracket_parser {
		Param(
		$s,$i,$level
		)

		while ($i -lt $s.length) {
			if (($s[$i].trim() -match '{') -and (!$s[$i].trim().startswith("#"))) {
				$i = $i+1
				$level = $level+=1
				
				if($level -eq 1) {
					$outItems.Add($s[$i-1])
					$outItems.Add($i)
				}
				$i = recursive_bracket_parser $s $i $level
			}
			elseif (($s[$i].trim() -match '}') -and (!$s[$i].trim().startswith("#"))) {
				$i = $i+1
				if($level -eq 1) {
					$outItems.Add($i)
				}
				$level = $level -=1
			}
			else {
				$i= $i + 1
			}
		}
		return $i
	}
	#endregion

	#region Checking_Package
	Function Checking_Package {
		Param(		
		[string]$Pacakge,
		[string]$LinuxOSType
		)

		# Checking the PREREQUISITES of the packages that must be installed on the machine (device-mapper-multipath* / lsscsi  / scsi-initiator-utils*)
		switch -Wildcard ($LinuxOSType)	{
			'rhel*' {
				$command = "sudo rpm -qa | grep $($Pacakge)"
				if($bLocalServer) {
					$rpmCheck = Invoke-Expression $command
				}
				else {
					$rpmCheck = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
				}
				if ($rpmCheck) {
					GoodMessage "package $($Pacakge) Installed - version:"
					handle_string_array_messages ($rpmCheck | Out-String).trim() "Data"
				}
				else {
					BadMessage "package $($Pacakge) not Installed"
				}
			}

			'debian*' {
				$command = "sudo dpkg -s | grep $($Pacakge)"
				if($bLocalServer) {
					$rpmCheck = Invoke-Expression $command
				}
				else {
					$rpmCheck = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
				}
				if ($rpmCheck) {
					GoodMessage "package $($Pacakge) Installed - version:"
					handle_string_array_messages ($rpmCheck | Out-String).trim() "Data"
				}
				else {
					BadMessage "package $($Pacakge) not Installed"
				}
			}
		}
	}
	#endregion

	#region Checking_Service
	Function Checking_Service {
		Param(
		[string]$Service,
		[string]$LinuxOSType
		)

		# Checking the MPIO and iSCSI Services on the machine
		[string]$ServiceActive  = "active"
		[string]$ServiceEnabled = "enabled"

		$command = "sudo systemctl is-active $($Service); sudo systemctl is-enabled $($Service)"
		if($bLocalServer) {
			$CheckingServiceStatus = Invoke-Expression $command
		}
		else {
			$CheckingServiceStatus = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
		}
		
		# Check if it null
		if($CheckingServiceStatus) {
			$CheckingServiceStatus = $CheckingServiceStatus -join " "
			if(($CheckingServiceStatus -match $ServiceActive) -AND ($CheckingServiceStatus -match $ServiceEnabled))	{
				GoodMessage "$($Service) serivce is running and enabled..."
			}
			else {
				BadMessage "$($Service) service is not running or enabled, current state is - $($CheckingServiceStatus)"
			}
		}
		else {
			BadMessage "$($Service) serivce not found, Please installed it."
		}
	}
	#endregion

	# Local Variable - Main Validator function
	[boolean]$bLocalServer = $false

	# We will use the vmhost variable as a dummy to hold the "Initialization" string.
	$MessageCurrentObject = "Linux Validator"
	InfoMessage "Validating Linux Server/s"

	# Check the Windows servers, if it empty run this with local user
	if ([string]::IsNullOrEmpty($ServerArray)) {
		# Get the user name
		$linux_username = $(whoami)

		# Local user True
		$bLocalServer = $True

		# Set local server name - $ServerArray
		$ServerArray = hostname
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
		InfoMessage "Using $($linux_username) login user for Linux Validator"

		PrintDelimiter

		# Write the headline messages into HTML report
		$HeadlineMessage
		$HeadlineMessage = "<div id='Headline'>Running validation for Linux host(s) `"$($ServerArray)`".</div>"

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
					
					if($bLocalServer) {
						$checking_lsb_comm = Invoke-Expression $command
					}
					else {
						$checking_lsb_comm = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					if($checking_lsb_comm) {
						# Checking the data
						$command  = "lsb_release -a | grep -E 'Release:|Distributor ID:'"
						$Splinter = ":"
						if($bLocalServer) {
							$Linux_Distro_info = Invoke-Expression $command | Sort-Object
						}
						else {
							$Linux_Distro_info = (plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command) | Sort-Object
						}
					}
					else {
						$command  = "cat /etc/os-release | grep -E '\bID=|\bVERSION_ID='"
						$Splinter = "="
						if($bLocalServer) {
							$Linux_Distro_info = Invoke-Expression $command | Sort-Object
						}
						else {
							$Linux_Distro_info = (plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command) | Sort-Object
						}

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
								if($Linux_OS_Version -ge 7)	{
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
								if($Linux_OS_Version -ge 7)	{
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6)	{
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
								if($Linux_OS_Version -ge 7)	{
									$linuxtype = "debian7"
								}
								elseif($Linux_OS_Version -ge 6)	{
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
								if($Linux_OS_Version -ge 7)	{
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6)	{
									$linuxtype = "rhel6"
								}
								else {
									$linuxtype = $false
								}
							}
							# Oracle Linux Server
							"OracleServer" {
								if($Linux_OS_Version -ge 7)	{
									$linuxtype = "rhel7"
								}
								elseif($Linux_OS_Version -ge 6)	{
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

					InfoMessage "Silk Validator script will validate according to Linux distribution - $($linuxtype)"

					PrintDelimiter					

					# Print the CPU & Memory and Kernel Version
					InfoMessage "$MessageCounter - Print Server Kernel version / CPU / Memory / Network"
					$command = "sudo uname -r"
					if($bLocalServer) {
						$Kernel_Data = Invoke-Expression $command
					}
					else {
						$Kernel_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Print the data
					DataMessage "kernel version is: $($Kernel_Data)"			 

					# Print the CPU & Memory and Kernel Version
					$command = "lscpu | grep -E '^CPU|Thread|Socket|Core'"
					if($bLocalServer) {
						$CPU_Data = Invoke-Expression $command
					}
					else {
						$CPU_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Print the data
					InfoMessage "CPU Server Information is:"
					handle_string_array_messages ($CPU_Data | Out-String).Trim() "Data"

					$command = "cat /proc/meminfo | grep MemTotal"
					if($bLocalServer) {
						$Mem_Data = Invoke-Expression $command
					}
					else {
						$Mem_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Print the data
					InfoMessage "Total Server Memory is:"
					handle_string_array_messages ($Mem_Data | Out-String).Trim() "Data"

					$command = "sudo lshw -class network"
					if($bLocalServer) {
						$Network_Data = Invoke-Expression $command
					}
					else {
						$Network_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Checking about the lshw tool 
					if($Network_Data) {
						# Print the data
						InfoMessage "Server Network is:"
						handle_string_array_messages ($Network_Data | Out-String).Trim() "Data"
					}
					else {
						WarningMessage "Could not read the Network Cards, missing lshw tool."
					}

					$MessageCounter++
					PrintDelimiter

					# Checking the PREREQUISITES of the packages that must be installed on the machine (device-mapper-multipath* / lsscsi  / scsi-initiator-utils*)
					InfoMessage "$MessageCounter - Validate Server Pckages and Services according to Silk BP"

					switch -Wildcard ($linuxtype) {
						'rhel*' {
							Checking_Package "device-mapper-multipath" $linuxtype
							Checking_Package "lsscsi" $linuxtype
							Checking_Package "iscsi-initiator-utils" $linuxtype
						}
						'debian*' {
							Checking_Package "multipath-tools" $linuxtype
							Checking_Package "lsscsi" $linuxtype
							Checking_Package "open-iscsi" $linuxtype
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

					# Get multipath.conf file from server 
					InfoMessage "$MessageCounter - Running validation for MPIO configuration"
					$command = "test -f /etc/multipath.conf && echo true || echo false"
					if($bLocalServer) {
						$multipathconffileexists = Invoke-Expression $command
					}
					else {
						$multipathconffileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					if ($multipathconffileexists -match "true")	{
						$command = "cat /etc/multipath.conf"
						if($bLocalServer) {
							$multipathconf = Invoke-Expression $command
						}
						else {
							$multipathconf = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}
						
						# 	Write the Multipath into the HTML file
						InfoMessage "File - /etc/multipath.conf - Content:"
						handle_string_array_messages ($multipathconf |out-string).Trim() "Data"

						#global values- not changing per distro
						# defaults section
						$user_friendly_names_param  = '\byes\b' , "yes"
						$find_multipaths_param      = '\byes\b' , "yes"
						$polling_interval_param     = '\b1\b' , "1"
						$verbosity_param            = '\b2\b' , "2"	
						
						# blacklist section
						$devnode_param1             = "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*","^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"
						$devnode_param2             = "^hd[a-z]","^hd[a-z]"
						$devnode_param3             = "^sda$","^sda$"

						# blacklist Device section
						#$obj                        = new-object PSObject -Property @{"vendor"="NVME"; "product"='"Microsoft NVMe Direct Disk"'}
						#$obj2                       = new-object PSObject -Property @{"vendor"="Msft"; "product"='"*"'}
						# $blacklist_devices          = @($obj,$obj2);
						
						# devices sesction
						$vendor_param_KMNRIO        = '\"KMNRIO"' , "KMNRIO"
						$vendor_param_SILK          = '\"SILK"' , "SILK"
						$product_param_KDP          = '\"KDP"' , "KDP"
						$product_param_SDP          = '\"SDP"' , "SDP"
						$path_grouping_policy_param = '\bmultibus\b' , "multibus"
						$path_checker_param         = '\btur\b' , "tur"
						$path_selector_parm         = '\"queue-length 0"',"queue-length 0"
						$no_path_retry_param        = '\bfail\b' , "fail"
						$hardware_handler_param     = '\"0"' , "0"
						$failback_param             = '\bimmediate\b',"immediate"
						$fast_io_fail_tmo_param     = '\b2\b' , "2"
						$dev_loss_tmo_param         = '\b3\b' , "3"
						$max_sectors_kb_param       = '\b1024\b' , "1024"

						# devices section helpers
						$venodr_param_SILK_KDP      = $False
						$venodr_param_SILK_SDP      = $False

						# blacklist exceptions
						$property_parm              = "(ID_SCSI_VPD|ID_WWN|ID_SERIAL)","(ID_SCSI_VPD|ID_WWN|ID_SERIAL)"

						# Start validation process and validating multipath.conf

						# Remove empty space and line from multipath file
						$multipathconf = $multipathconf.Trim() | where-object {$_}

						# Divide the data by sections
						$outItems = New-Object System.Collections.Generic.List[String]
						[string[]]$outItems_array = @{}

						# Check if the section found or not
						recursive_bracket_parser $multipathconf 0 0 | Out-Null
						$outItems_array = $outItems.ToArray()

						# Checked that the multipath contain all 4 sesctions.
						$defaults_line_check  = $outItems_array | Select-String -Pattern 'defaults {' | Select-Object -ExpandProperty LineNumber
						$blacklist_line_check = $outItems_array | Select-String -Pattern 'blacklist {' | Select-Object -ExpandProperty LineNumber
						$devices_line_check   = $outItems_array | Select-String -Pattern 'devices {' | Select-Object -ExpandProperty LineNumber
						$blacklist_exceptions_line_check   = $outItems_array | Select-String -Pattern 'blacklist_exceptions {' | Select-Object -ExpandProperty LineNumber

						InfoMessage "Running validation for Multipath configuration"

						if(!$defaults_line_check) {
							BadMessage "Could not found the defaults section in Multipath.conf, skipping checking Multipath defaults Section"
						}
						else {
							# Get the lines
							$defaults_line_b = $outItems_array[($outItems_array | Select-String -Pattern 'defaults {' | Select-Object -ExpandProperty LineNumber)]
							$defaults_line_e = $outItems_array[($outItems_array | Select-String -Pattern 'defaults {' | Select-Object -ExpandProperty LineNumber)+1]
							$defaults_data   = ($multipathconf[($defaults_line_b-1) .. ($defaults_line_e -1)]).trim()

							# Multipath defaults Parameters Section
							ValidateAttrinuteInMpio -Mpio_Section_Name "defaults" -Mpio_Section_Data $defaults_data -Parameter_name "user_friendly_names" -Parameter_value_array $user_friendly_names_param
							ValidateAttrinuteInMpio -Mpio_Section_Name "defaults" -Mpio_Section_Data $defaults_data -Parameter_name "polling_interval" -Parameter_value_array $polling_interval_param
							ValidateAttrinuteInMpio -Mpio_Section_Name "defaults" -Mpio_Section_Data $defaults_data -Parameter_name "find_multipaths" -Parameter_value_array $find_multipaths_param
							ValidateAttrinuteInMpio -Mpio_Section_Name "defaults" -Mpio_Section_Data $defaults_data -Parameter_name "verbosity" -Parameter_value_array $verbosity_param
						}

						if(!$blacklist_line_check) {
							BadMessage "Could not found the blacklist section in Multipath.conf, skipping checking Multipath blacklist Section"
						}
						else {
							$blacklist_line_b = $outItems_array[($outItems_array | Select-String -Pattern 'blacklist {' | Select-Object -ExpandProperty LineNumber)]
							$blacklist_line_e = $outItems_array[($outItems_array | Select-String -Pattern 'blacklist {' | Select-Object -ExpandProperty LineNumber)+1]
							$blacklist_data  = ($multipathconf[($blacklist_line_b-1) .. ($blacklist_line_e -1)]).trim()

							$blacklist_device_line = $blacklist_data | Select-String -Pattern 'device {' | Select-Object -ExpandProperty LineNumber

							# Multipath blacklist Parameters Section
							ValidateAttrinuteInMpio -Mpio_Section_Name "blacklist" -Mpio_Section_Data $blacklist_data -Parameter_name "devnode" -Parameter_value_array $devnode_param1
							ValidateAttrinuteInMpio -Mpio_Section_Name "blacklist" -Mpio_Section_Data $blacklist_data -Parameter_name "devnode" -Parameter_value_array $devnode_param2
							ValidateAttrinuteInMpio -Mpio_Section_Name "blacklist" -Mpio_Section_Data $blacklist_data -Parameter_name "devnode" -Parameter_value_array $devnode_param3

							# Multipath blacklist_devices devices Parameters Section
							For ($i=0; $i -lt ($blacklist_device_line.count); $i++) {
								# Reset the temp device
								$device = $NULL

								if (($i+1) -eq $blacklist_device_line.count) {
									$device = ($blacklist_data[($blacklist_device_line[$i]-1) .. (($blacklist_data.Length) -2)]).trim()
								}
								else {
									$device = ($blacklist_data[($blacklist_device_line[$i]-1) .. (($blacklist_device_line[$i+1] -2))]).trim()
								}

								InfoMessage "Running validation for Multipath configuration - blacklist devices number - $($i+1)"
								
								[System.Boolean]$bFound = $false
								$vendor = ($device) -match ("vendor")
								if ($vendor) {
									switch  -wildcard ($vendor)	{
										"*NVME*" {
											GoodMessage "Device vendor NVME value is properly configured according to Silk's BP, continue with other properties"
										
											# Multipath device Parameters Section
											ValidateAttrinuteInMpio -Mpio_Section_Name "blacklist_Device" -Mpio_Section_Data $device -Parameter_name "product" -Parameter_value_array "Microsoft NVMe Direct Disk"	
											break
										}
										"*Msft*" {
											GoodMessage "Device vendor Msft value is properly configured according to Silk's BP, continue with other properties"
										
											# Multipath device Parameters Section
											ValidateAttrinuteInMpio -Mpio_Section_Name "blacklist_Device" -Mpio_Section_Data $device -Parameter_name "#product" -Parameter_value_array """*"""
											break
										}
										default { 
											WarningMessage "Device vendor value is not among list of - NVME / Msft, but to - $($vendor), skipping this device"
										}
									}
								}
								else { 
									BadMessage "multipath.conf - Device $($i+1) is missing vendor, skipping this device"
								}
							}
						}

						if(!$devices_line_check) {
							BadMessage "Could not found the devices section in Multipath.conf, skipping checking devices Multipath Section"
						}
						else {
							$devices_line_b = $outItems_array[($outItems_array | Select-String -Pattern 'devices {' | Select-Object -ExpandProperty LineNumber)]
							$devices_line_e = $outItems_array[($outItems_array | Select-String -Pattern 'devices {' | Select-Object -ExpandProperty LineNumber)+1]
							$devices_data   = ($multipathconf[($devices_line_b-1) .. ($devices_line_e -1)]).trim()

							# Get the data for devices
							$device_line = $devices_data | Select-String -Pattern 'device {' | Select-Object -ExpandProperty LineNumber
							
							# Multipath devices Parameters Section, Run over loop until we find the vendor "KMNRIO" / "SILK"
							For ($i=0; $i -lt ($device_line.count); $i++) {
								# Reset the temp device
								$device = $NULL

								if (($i+1) -eq $device_line.count) {
									$device = ($devices_data[($device_line[$i]-1) .. (($devices_data.Length) -2)]).trim()
								}
								else {
									$device = ($devices_data[($device_line[$i]-1) .. (($device_line[$i+1] -2))]).trim()
								}

								InfoMessage "Running validation for Multipath configuration - Devices Device number - $($i+1)"

								$vendor = ($device) -match ("vendor")
								if ($vendor) {
									if(!($vendor -match $vendor_param_KMNRIO[0]) -AND !($vendor -match $vendor_param_SILK[0])) {
										WarningMessage "Device vendor value is not set to - $($vendor_param_KMNRIO[1]) or $($vendor_param_SILK[1]), but to - $($vendor), skipping this device"
									}
									else {									
										# Multipath device Parameters Section
										if($vendor -match $vendor_param_KMNRIO[0]) {
											GoodMessage "Device vendor $($vendor_param_KMNRIO[1]) or is properly configured according to Silk's BP, continue with other device properties"
											ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "product" -Parameter_value_array $product_param_KDP
										}
										else {
											GoodMessage "Device vendor $($vendor_param_SILK[1]) or is properly configured according to Silk's BP, continue with other device properties"
											if($device -match $product_param_KDP[0]) {
												ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "product" -Parameter_value_array $product_param_KDP
												$venodr_param_SILK_KDP = $True
											}
											elseif($device -match $product_param_SDP[0]){
												ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "product" -Parameter_value_array $product_param_SDP
												$venodr_param_SILK_SDP = $True
											}
											else {
												BadMessage "Could not found product $($product_param_KDP[1]) or $($product_param_SDP[1]) in the current device with vendor $($vendor_param_SILK[1])"
											}
										}
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "path_grouping_policy" -Parameter_value_array $path_grouping_policy_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "path_checker" -Parameter_value_array $path_checker_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "path_selector" -Parameter_value_array $path_selector_parm
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "no_path_retry" -Parameter_value_array $no_path_retry_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "hardware_handler" -Parameter_value_array $hardware_handler_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "failback" -Parameter_value_array $failback_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "fast_io_fail_tmo" -Parameter_value_array $fast_io_fail_tmo_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "dev_loss_tmo" -Parameter_value_array $dev_loss_tmo_param
										ValidateAttrinuteInMpio -Mpio_Section_Name "devices_device" -Mpio_Section_Data $device -Parameter_name "max_sectors_kb" -Parameter_value_array $max_sectors_kb_param
									}
								}
								else { 
									BadMessage "multipath.conf - Device $($i+1) is missing vendor, skipping this device"
								}
							}	
						}

						if((!($venodr_param_SILK_KDP)) -OR (!($venodr_param_SILK_SDP)))	{
							BadMessage "Vendor SILK with products KDP (Found = $venodr_param_SILK_KDP) & SDP (Found = $venodr_param_SILK_SDP), Please validate and fix the multipath.conf!"
						}

						if(!$blacklist_exceptions_line_check) {
							BadMessage "Could not found the blacklist exceptions section in Multipath.conf, skipping checking blacklist_exceptions Multipath Section"
						}
						else {
							$blacklist_exceptions_line_b = $outItems_array[($outItems_array | Select-String -Pattern 'blacklist_exceptions {' | Select-Object -ExpandProperty LineNumber)]
							$blacklist_exceptions_line_e = $outItems_array[($outItems_array | Select-String -Pattern 'blacklist_exceptions {' | Select-Object -ExpandProperty LineNumber)+1]
							$blacklist_exceptions_data   = ($multipathconf[($blacklist_exceptions_line_b-1) .. ($blacklist_exceptions_line_e -1)]).trim()

							# Multipath blacklist exceptions Parameters Section
							ValidateAttrinuteInMpio -Mpio_Section_Name "blacklist_exceptions" -Mpio_Section_Data $blacklist_exceptions_data -Parameter_name "property" -Parameter_value_array $property_parm
						}
					}
					else {
						BadMessage "multipath.conf not found on /etc/multipath.conf"
					}

					$MessageCounter++
					PrintDelimiter

					InfoMessage "$MessageCounter - Running the Validator for UDEV configuration"

					# Get /usr/lib/udev/rules.d/98-sdp-io.rules file from server 
					$ID_SERIAL_scheduler_param_noop = '\"noop"' , "noop"
					$DM_UUID_scheduler_param_noop   = '\"noop"' , "noop"
					$ID_SERIAL_scheduler_param_none = '\"none"' , "none"
					$DM_UUID_scheduler_param_none   = '\"none"' , "none"

					# Get multipath.conf file from server 
					$command = "test -f /usr/lib/udev/rules.d/98-sdp-io.rules && echo true || echo false"
					if($bLocalServer) {
						$ioschedulersfileexists = Invoke-Expression $command
					}
					else {
						$ioschedulersfileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					
					if($ioschedulersfileexists -match "true") {
						$command = "cat /usr/lib/udev/rules.d/98-sdp-io.rules"
						if($bLocalServer) {
							$ioschedulers = Invoke-Expression $command
						}
						else {
							$ioschedulers = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						# 	Write the 98-sdp-io.rules into the HTML file
						InfoMessage "File - /usr/lib/udev/rules.d/98-sdp-io.rules - Content:"
						handle_string_array_messages ($ioschedulers |out-string).trim() "Data"

						# Cleanup empty spaces and rows
						$ioschedulers = $ioschedulers.Trim() | where-object {$_}

						# Get only the relavant rows
						# We have definations of 20024* (need to be 4)
						$ioschedulers = $ioschedulers -match "20024*"

						# Validate 98-sdp-io.rules - Example
						#ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="20024*",ATTR{queue/scheduler}="noop"
						#ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-20024*",ATTR{queue/scheduler}="noop"
						#ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="20024*",ATTR{queue/scheduler}="none"
						#ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-20024*",ATTR{queue/scheduler}="none"

						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "ID_SERIAL}.*queue/scheduler" -Parameter_value_array $ID_SERIAL_scheduler_param_noop
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "DM_UUID}.*queue/scheduler" -Parameter_value_array $DM_UUID_scheduler_param_noop
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "ID_SERIAL}.*queue/scheduler" -Parameter_value_array $ID_SERIAL_scheduler_param_none
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "DM_UUID}.*queue/scheduler" -Parameter_value_array $DM_UUID_scheduler_param_none
					}
					else {
						BadMessage "98-sdp-io.rules not found on /usr/lib/udev/rules.d/98-sdp-io.rules"
					}

					$MessageCounter++
					PrintDelimiter

					InfoMessage "$MessageCounter - iSCSI IQN & Sessions Section"

					# IQN Name
					# cat /etc/iscsi/initiatorname.iscsi
					$command = "sudo cat /etc/iscsi/initiatorname.iscsi | grep InitiatorName="
					if($bLocalServer) {
						$IQN_Data = Invoke-Expression $command
					}
					else {
						$IQN_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Write it:
					if($IQN_Data) {
						DataMessage "IQN Name is - $($IQN_Data)"
					}
					else {
						DataMessage "IQN InitiatorName parameter not found on /etc/iscsi/initiatorname.iscsi"
					}

					# Number of iSCSI sessions 
					# iscsiadm -m session | grep tcp | wc -l
					$command = "sudo iscsiadm -m session | grep tcp | wc -l"
					if($bLocalServer) {
						$iSCSISession_Data = Invoke-Expression $command
					}
					else {
						$iSCSISession_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Write it:
					DataMessage "Total Number of iSCSI session is - $($iSCSISession_Data)"

					if($iSCSISession_Data -ne 0) {
						# Number of sessions per c-node
						InfoMessage "How iSCSI Sessions distributed between c-nodes"
						$command = "sudo netstat -antup | grep 3260 | grep ESTABLISHED | tr -s ' ' | cut -f5 -d ' ' | cut -f1 -d ':' | sort | uniq -c"
						if($bLocalServer) {
							$iSCSISession_Per_Cnode = Invoke-Expression $command
						}
						else {
							$iSCSISession_Per_Cnode = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						# Write it:
						handle_string_array_messages ($iSCSISession_Per_Cnode | ForEach-Object { $_.Trim() } | out-string).Trim() "Data"
						
						$MessageCounter++
						PrintDelimiter

						InfoMessage "$MessageCounter - Devices MPIO Setttings Section"

						# Multipath Configuration
						# cat /etc/iscsi/initiatorname.iscsi
						$command = "sudo multipath -ll | grep -i KMNRIO -A 2"
						if($bLocalServer) {
							$Multipath_dm_data = Invoke-Expression $command
						}
						else {
							$Multipath_dm_data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						# Write it:
						handle_string_array_messages ($Multipath_dm_data | Out-String).Trim() "Data"

						# Verify that the scheduler is configured to noop
						InfoMessage "UDEV Rules settings per dm device (If there is)"
						$command1 = 'sudo multipath -ll | grep KMNRIO | awk ''{print $3}'' | sort -n'
						$command  = 'sudo bash -c ''for dm in XXXXX ; do (echo -ne "$dm" - ; echo $(sudo cat /sys/class/block/"$dm"/queue/scheduler)) ;done | sort -n'''
						if($bLocalServer) {
							$Device_IO_Rule = ((Invoke-Expression $command1) -join " ").trim()
							$command        = $command.replace("XXXXX",$Device_IO_Rule)
							$Device_IO_Rule = Invoke-Expression $command

						}
						else {
							$Device_IO_Rule = ((plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command1) -join " ").trim()
							$command        = $command.replace("XXXXX",$Device_IO_Rule)
							$Device_IO_Rule = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						# Write it:
						handle_string_array_messages ($Device_IO_Rule |Out-String).Trim() "Data"
					}
					
					$MessageCounter++
					PrintDelimiter
				}
			}

			InfoMessage "Validation for $($Server) completed."

			PrintDelimiter
			$SDPBPHTMLBody += "<div id='host_space'></div>"
		}
	}
	
	catch {
		# Get the exception messages
		$ExceptionMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber

		BadMessage "Caught exception during Linux Validator at line: $($line)"
		BadMessage $ExceptionMessage
	}
	
	Finally {
		# Once all data is collected - output into HTML
		$MessageCurrentObject = "Finished Validating`n"
		
		PrintDelimiterServer
	}
}
#endregion
##################################### End Validator functions ##############################################################

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

	$MessageCurrentObject = "Silk Validator pre-Checking"

	# Print the PowerShell versions and edtion
	InfoMessage "Silk Validator for Prodcut - $($ValidatorProduct)"
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

		$optiontitle    = 'The Silk Best Practices Validator Script'
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
					Write-Host -ForegroundColor Yellow "This script gets Linux servers as inputs and validates servers parameters according to Silk's best practices."
					[string]$LinuxServerString  = ""
					[string[]]$LinuxServerarray = @()
					$LinuxServerString = read-host  ("Linux Server -Specify the Servers names or IP addresses to connect to (comma as a separation between them).`nPress enter if you want check local server with logon user")
					$LinuxServerString = TrimHostNames $LinuxServerString
					$LinuxServerarray  = $LinuxServerString.split(",")
	
					# Check the Windows servers, if it empty run this with local user
					if ([string]::IsNullOrEmpty($LinuxServerarray)) {
						Linux_Validator $LinuxServerarray
					}
					else {
						$Credential = $host.ui.PromptForCredential("Silk BP credentials", "Please enter your Linux username and password.", "", "")
						Linux_Validator $LinuxServerarray $Credential 
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
						Windows_Validator $WindowsServerarray
					}
					else {
						# Choose user for the validator
						$WinCredential = read-host ("Windows Credential - using $(whoami) Login user (Y/N), N = or diffrenet user")

						while (($WinCredential -notmatch "[yY]") -and ($WinCredential -notmatch "[nN]")) {
							write-host -ForegroundColor Red "Invalid entry, please enter 'Y' or 'N' to continue"
							$WinCredential = read-host ("Windows Credential - using $(whoami) Login user (Y/N), N = or diffrenet user")
						}

						if($WinCredential -match "[yY]") {
							Windows_Validator $WindowsServerarray
						}
						else {
							$Credential = $host.ui.PromptForCredential("Silk Windows BP credentials", "Please enter your Windows username and password.", "", "NetBiosUserName")
							Windows_Validator $WindowsServerarray $Credential 
						}
					}
				}
			}

			# Generate HTML Report File
			InfoMessage "Creating HTML Report..."
			GenerateHTML
		}
	}

	# Script has complted, Exit the script
	$MessageCurrentObject = "Silk Validator Ending"
	GoodMessage "Done, Good Bye!"
	start-sleep -seconds 4
}
#endregion
##################################### End Main #############################################################################