<#
 .SYNOPSIS
 This script gets various arguments and checks the Silk BP against the input.

 .DESCRIPTION
 This script gets a Host Type as inputs and validation according to Silk's best practices. 
 This script validates VMware, Linux, and Windows OS tpyes.

 Versions:  
  May-2021 - Current version V1.6.6
  Jun-2021 - Current version V1.7.0
  Aug-2021 - Current version V2.0.0
  Dec-2021 - Current version V2.0.4
  Jan-2022 - Current version V2.1.0
  Feb-2022 - Current version V2.1.1
  Apr-2022 - Current version V2.1.2
  May-2022 - Current version V2.1.3
  Jun-2022 - Current version V2.1.4
  Jul-2022 - Current version V2.1.5
    
 .NOTES
  Feb 2022 
  * (Lin) Fix recursive_bracket_parser function to handle "#" marks. 

  Apr 2022 
  * (Win) Print the MSDSM output data 
  * (Win) Print the iSCSI Adapter/s output data 
  * (Win) Improve the query of Silk disks in "Load Balance and Failover Policy for Individual Volumes" section

  May 2022
  * (Win) Checking and Validate the CTRL LU
  * (ESX) Fix the SATP pspoption to support policy options

  Jun 2022
  * (Lin) Fixing open-iscsi and iscsid handling

  Jul 2022
  * (Win/Lin) Added validation regarding TRIM/Unmap in Windows and Linux.
#>

# Ensure the the minimum version of the PowerShell Validator is 5 and above
#Requires -Version 5

##################################### Silk Validator begin of the script - Validate ########################################
#region Validate Section
# Configure general the SDP Version
[string]$SDP_Version = "2.1.5"

# Checking the PS version and Edition
[string]$ValidatorProduct  = "Dot6"
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
# CheckAdminUserCrossPlatform Function - Checking the current user in Windows and Linux environment. You must run as administrator (Windows) or root (linux)
function CheckAdminUserCrossPlatform {
	if ($PSPlatform -eq $Platfrom_Linux) {
		if ($(whoami) -eq "root") {
			GoodMessage "Running with a root user on Linux OS" 
			return $True
		}
		else {
			WarningMessage "The script is not running with a root admin - but with user $(whoami)" 
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

#region QLogic_HBA_Settings_Check
# QLogic_HBA_Settings_Check Function Check the internal parameters of QLogic HBA Settings – FC Only 
function QLogic_HBA_Settings_Check {
	[cmdletbinding()] 
	Param(
		$HBA_Port_Parameters
	)

	#qlogic HBA parameter 
	$Operation_Mode_param        = "^6 - Interrupt when Interrupt Delay Timer expires"
	$Interrupt_Delay_Timer_param = "^1"
	$Execution_Throttle_param    = "^400"

	if($HBA_Port_Parameters) {
		$qauclioutput = $HBA_Port_Parameters | Select-String "^Operation Mode|^Interrupt Delay Timer|^Execution Throttle"

		$opertaionmode = $qauclioutput -match "^Operation Mode"
		if($opertaionmode) {
			$opertaionmode_value = $opertaionmode.line.split(":")[1].trim()
			if($opertaionmode_value -match $Operation_Mode_param) {
				GoodMessage "QLogic HBA Operation Mode is properly configured according to Silk's BP"
			}
			else {
				BadMessage "QLogic HBA adapter Operation Mode value is not set to $($Operation_Mode_param), Current Value is ($opertaionmode_value)"
			}
		}
		else {
			WarningMessage "QLogic HBA adapter Operation Mode property not found"
		}
		
		$InterruptDelay = $qauclioutput -match "^Interrupt Delay Timer"
		if($InterruptDelay) {
			$InterruptDelay_value = $InterruptDelay.line.split(":")[1].trim()
			if($InterruptDelay_value -match $Interrupt_Delay_Timer_param) {
				GoodMessage "QLogic HBA Interrupt Delay Timer is properly configured according to Silk's BP"
			}
			else {
				BadMessage "QLogic HBA Interrupt Delay Timer value is not set to $($Interrupt_Delay_Timer_param), Current Value is ($InterruptDelay_value)"
			}
		}
		else {
			WarningMessage "QLogic HBA Interrupt Delay property not found"
		}
		
		$ExecutionThrottle  = $qauclioutput -match "^Execution Throttle"
		if($ExecutionThrottle) {
			$ExecutionThrottle_value = $ExecutionThrottle.line.split(":")[1].trim()
			if($ExecutionThrottle_value -match $Execution_Throttle_param) {
				GoodMessage "QLogic HBA Execution Throttle is properly configured according to Silk's BP"
			}
			else {
				BadMessage "QLogic HBA Execution Throttle value is not set to $($Execution_Throttle_param), Current Value is ($ExecutionThrottle_value)"
			}
		}
		else {
			WarningMessage "QLogic HBA Execution Throttle property not found"
		}
	}
	else {
		BadMessage "qlogic qaucli command (qaucli -pr fc -c) return null"
	}
}
#endregion
##################################### End Global functions #################################################################

##################################### Validator Main functions #############################################################
#region ESXI validator as subfunction
function VMware_Validator {  
	[cmdletbinding()] 
	Param(
		[parameter()][String]$vCenter,
		[parameter()][String]$Cluster,
		[parameter()][String]$ESXHost,
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]		
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)
	
	Process	{	

		#region PrintUsage
		Function PrintUsage	{
			Write-Warning "Validation Parameters Error, Available arguments are:"
			Write-Warning "	-vCenter    : Specify the vCenter name to connect to. Can be combined with -ESXHost and/or -Cluster."
			Write-Warning "	-Cluster    : Specify the ESXi cluster to validate. Requires the -vCenter argument."
			Write-Warning "	-ESXHost    : Specify the ESXi host to validate. Can be combined with the -vCenter argument."
			Write-Warning "	-Credential : Specify the user and password to authenticate with."
			Write-Host "`n"
		}
		#endregion PrintUsage

		#region ValidatePowerCLI
		Function ValidatePowerCLI {
			InfoMessage "Validate the PowerCLI version."
			$PowerCLI_Installed = $True
			
			try {
				$VMwareMoudleCount = (Get-Module -ListAvailable VMware.VimAutomation.Core).count
				if($VMwareMoudleCount -eq 0) {
					BadMessage "No VMware Modules found, please check that PowerCLI 6.5 is installed, Silk BP Script Ending."
					$PowerCLI_Installed = $False
				}
				else {
					if($VMwareMoudleCount -eq 1) {
						Get-Module -ListAvailable VMware.VimAutomation.Core | Import-Module | Out-Null
					}
					else {
						(Get-Module -ListAvailable VMware.VimAutomation.Core | Sort-Object Version -Descending)[0] | Import-Module | Out-Null
					}
					
					if((((Get-Module -ListAvailable VMware.VimAutomation.Core ).Version).Major -lt 6) -or (((Get-Module -ListAvailable VMware.PowerCLI ).Version).Major -eq 6) -and (((Get-Module -ListAvailable VMware.PowerCLI ).Version).Minor -lt 5)) {
						BadMessage "The minimum PowerCLI version needed is 6.5, Silk BP Script Ending."						
						$PowerCLI_Installed = $False
					}
					
					if(((Get-Module -ListAvailable VMware.VimAutomation.Core ).Version).Major -ge 10) {
						set-PowerCLIConfiguration -invalidCertificateAction "ignore" -confirm:$False | Out-Null
					}
				}
			}
			catch {
				BadMessage "No VMware Modules found or errors during import Powercli modules, please check that PowerCLI 6.5 is installed, Silk BP Script Ending."				
				$PowerCLI_Installed = $False
			}

			GoodMessage "The PowerCLI version check passed."
			return $PowerCLI_Installed
		}
		#endregion
		
		# We will use the vmhost variable as a dummy to hold the "Initialization" string.
		$MessageCurrentObject = "Validating VMware ESXI"

		# Connection VMware Section
		Try {
			# Validate PowerCLI exists and in use
			if(ValidatePowerCLI) {
				
				PrintDelimiter

				# PowerCLI Configure general variables 
				Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP $False -Confirm:$False | Out-Null

				# Local VMware validator variables
				$VMwareConnect   = $null
				$HeadlineMessage = $null

				# finding combination for 3 boolean variables
				[int]$condition = 0
				if (![string]::IsNullOrEmpty($vCenter)) { $condition += 1 }
				if (![string]::IsNullOrEmpty($Cluster)) { $condition += 2 }
				if (![string]::IsNullOrEmpty($ESXHost)) { $condition += 4 }

				switch ($condition)
				{
					0 {	PrintUsage 
						return}
					1 {	PrintUsage 
						return}
					2 { PrintUsage 
						return}
					3 { 
						$VMwareConnect   = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop | Out-Null
						$HeadlineMessage = "<div id='Headline'>Running validation for ESXi Cluster `"$($Cluster)`" from vCenter `"$($vCenter)`".</div>"
						$vmhosts         = @(Get-VMHost -Server $vCenter -Location $Cluster)
					}
					4 { 
						$VMwareConnect   = Connect-VIServer -Server $ESXHost -Credential $Credential -ErrorAction Stop | Out-Null
						$HeadlineMessage = "<div id='Headline'>Running validation for ESXi host `"$($ESXHost)`" Only`".</div>"
						$vmhosts         = @(Get-VMHost -Name $ESXHost)
					}
					5 {
						$VMwareConnect   = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop | Out-Null
						$HeadlineMessage = "<div id='Headline'>Running validation for ESXi host `"$($ESXHost)`" located in vCenter `"$($vCenter)`".</div>"
						$vmhosts         = @(Get-VMHost -Server $vCenter -Name $ESXHost)
					}
					6 { PrintUsage 
						return}
					7 {
						$VMwareConnect   = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop | Out-Null
						$HeadlineMessage = "<div id='Headline'>Running validation for ESXi Host `"$($ESXHost)`" located in ESXi Cluster(s) `"$($Cluster)`" from vCenter `"$($vCenter)`".</div>"
						$vmhosts         = @(Get-VMHost -Server $vCenter -Location $Cluster -Name $ESXHost)
					}
					default {
						PrintUsage 
						return}
				}

				InfoMessage "Running validation for ESXi"
				
				# Start validation process
				foreach ($vmhost in ($vmhosts | Sort-Object name)) {

					# Reseting the counter message sections
					[int]$MessageCounter = 1
					
					$MessageCurrentObject = $vmhost
					InfoMessage "$MessageCounter - Start Processing ESX host $($MessageCurrentObject)"

					# Only perform these actions on hosts are available
    				If ((Get-VMhost -Name $vmhost.Name).ConnectionState -eq "NotResponding") {
						WarningMessage "ESXi host - $($vmhost.Name) ConnectionState is NotResponding, Skipping this host"

						# add a spacer for the HTML output 
						PrintDelimiter
						$SDPBPHTMLBody += "<div id='host_space'></div>"

						continue  # <- skip just this iteration, but continue loop
					}
					else{
						# Get the ESXi version
						$esxVersion = $vmhost | Select-Object Version,Build
						InfoMessage "$MessageCounter - ESXi version $($esxVersion.Version) build $($esxVersion.Build)"
						
						$MessageCounter++
						PrintDelimiter
						
						# Validate Disk.SchedQuantum Value
						# ================================
						InfoMessage "$MessageCounter - Running validation for Disk.SchedQuantum"
						$SchedQuantum = $vmhost | Get-AdvancedSetting -Name Disk.SchedQuantum
						$Silk_SchedQuantum = 64

						if ($SchedQuantum.Value -eq $Silk_SchedQuantum)	{
							GoodMessage "Disk.SchedQuantum is properly configured according to Silk's BP (Disk.SchedQuantum=$Silk_SchedQuantum)"
						} 
						else {
							BadMessage "Silk BP recommends setting Disk.SchedQuantum to 64. Current value is $($SchedQuantum.Value)."
						}
						
						$MessageCounter++
						PrintDelimiter
						
						# Validate Disk.DiskMaxIOSize Value
						# =================================
						InfoMessage "$MessageCounter - Running validation for Disk.DiskMaxIOSize"
						$DiskMaxIOSize = $vmhost | Get-AdvancedSetting -Name Disk.DiskMaxIOSize
						$Silk_DiskMaxIOSize = 1024
						if($DiskMaxIOSize.Value -eq $Silk_DiskMaxIOSize) {
							GoodMessage "Disk.DiskMaxIOSize is properly configured according to Silk's BP (Disk.DiskMaxIOSize=$Silk_DiskMaxIOSize)"
						}
						else {
							BadMessage "Silk BP recommends setting Disk.DiskMaxIOSize to 1024. Current value is $($DiskMaxIOSize.Value)."
						}

						$MessageCounter++
						PrintDelimiter
						
						# Validate Disk.SchedNumReqOutstanding Value
						# ==========================================
						InfoMessage "$MessageCounter - Running validation for Disk.SchedNumReqOutstanding"
						if ($esxVersion.Version -ge 5.5) {
							InfoMessage "Note - In ESXi version $($esxVersion.Version) the SchedNumReqOutstanding parameter is set per disk."
							
							$esxcli     = Get-EsxCli -VMHost $vmhost -V2
							$K2DiskList = $esxcli.storage.core.device.list.invoke() |Where-Object {$_.Vendor -eq "KMNRIO"}| Select-Object Device,Vendor,NoofoutstandingIOswithcompetingworlds

							$SchedNumReqOutstandingBP = 32
							InfoMessage "Note - In ESXi version $($esxVersion.Version) the SchedNumReqOutstanding parameter recommended value is $($SchedNumReqOutstandingBP)"

							foreach ($K2Disk in $K2DiskList | Sort-Object Device) {
								if ($K2Disk.NoofoutstandingIOswithcompetingworlds -ne $SchedNumReqOutstandingBP) {
									BadMessage "Silk Disk $($K2Disk.Device) is not properly configured according to Silk's BP. Current value is $($K2Disk.NoofoutstandingIOswithcompetingworlds)."
								} 
								else {
									GoodMessage "Silk Disk $($K2Disk.Device) is properly configured according to Silk's BP (NoofoutstandingIOswithcompetingworlds=$($SchedNumReqOutstandingBP))."
								}
							}
						}
						else {
							WarningMessage "Note - In ESXi version $($esxVersion.Version) the Disk.SchedNumReqOutstanding parameter is a global parameter."	
							$OldSchedNumReqOutstanding = $vmhost | Get-AdvancedSetting -Name Disk.SchedNumReqOutstanding
							if ($OldSchedNumReqOutstanding.Value -eq 32) {
								GoodMessage "Parameter Disk.SchedNumReqOutstanding value is 32 and is properly configured according to Silk's BP"
							}
							else {
								BadMessage "Parameter Disk.SchedNumReqOutstanding value is not 32 and is not properly configured according to Silk's BP"
							}
						}
						$MessageCounter++
						PrintDelimiter

						# Validate Print iSCSI Configurtion that are related to kaminario target
						# =====================================================================
						InfoMessage "$MessageCounter - Running validation for iSCSI settings - Only print"
						if($systemConnectivitytype -eq "iscsi") {
							
							# Connect to the EsxCli instance for the current host
							$EsxCli = Get-EsxCli -VMHost $vmhost -V2

							 # Get a list of all of the Silk Storage iSCSI targets
							$targets = $esxcli.iscsi.adapter.target.portal.list.Invoke().where{$_.Target -Like "*kaminario*"}
							InfoMessage "List of all of the Silk Storage iSCSI targets are:"
							handle_string_array_messages ($targets | Format-table -AutoSize |Out-String).Trim() "Data"

							# Run over each target and get his internal infromation
							foreach($target in $targets | select-object Adapter | Get-Unique | Sort-Object)
							{	
								# Get iSCSI Software Adaper in a variable
								$iscsihba = $vmhost | Get-VMHostHba | Where-Object{($_.Model -eq "iSCSI Software Adapter") -and ($_.Device -eq $target.Adapter)}
								InfoMessage "iSCSI Software Adaper is:"
								handle_string_array_messages ($iscsihba | Format-table -AutoSize  |Out-String).Trim() "Data"
																
								# Port Binding Configuration
								$iSCSInics     = $Esxcli.iscsi.networkportal.list.invoke()
								$iSCSInicsData = $iSCSInics | where-object {$_.Adapter -eq $target.Adapter} | Select-Object Adapter,CompliantStatus,CurrentSpeed,IPv4,MTU,PathStatus,PortGroup,Vmknic,Vswitch
								InfoMessage "Port Binding Configuration is:"
								handle_string_array_messages ($iSCSInicsData | Format-table -AutoSize  |Out-String).Trim() "Data"								
								
								if($iSCSInicsData)
								{
									$vSwitchName = $iSCSInicsData | Select-Object vSwitch
									$vSwitch     = get-VirtualSwitch -Name $vSwitchName | Select-Object Name,Mtu,Nic
									$physicalNic = $esxcli.network.nic.pauseParams.list.Invoke() | Select-Object NIC,PauseRX,PauseTX | where-object {$_.Nic -match $vSwitch.Nic }									
									InfoMessage "Physical Nic and Flow-Control are:"
									handle_string_array_messages ($physicalNic | Format-table -AutoSize |Out-String).Trim() "Data"		
								}
							}

							# Checking VMware software iSCSI adapter using the following command:
							$VMHostStorage = Get-VMHostStorage -VMHost $vmhost
							InfoMessage "VMware software iSCSI adapter enabled - $($VMHostStorage.SoftwareIScsiEnabled)"
						}
						else {
							InfoMessage "Validation for iSCSI settings is only valid for iSCSI connectivity"
						}

						$MessageCounter++
						PrintDelimiter

						# Validate Qlogic Settings 
						# ========================
						InfoMessage "$MessageCounter - Running validation for Qlogic settings"
						if($systemConnectivitytype -eq "fc") { 							
							$QlogicOptions = $vmhost | Get-VMHostModule -Name "ql*" -ErrorAction SilentlyContinue | Select-Object Options
							if ($QlogicOptions) {
								$HBA_ql2xmaxqdepth = 256

								if ($QlogicOptions.Options -notlike "*ql2xoperationmode=6*" -Or $QlogicOptions.Options -notlike "*ql2xintrdelaytimer=1*" -Or $QlogicOptions.Options -notlike "*ql2xmaxqdepth=$($HBA_ql2xmaxqdepth)*") {
									BadMessage "Qlogic option is not set according to Silk's BP. Current settings: $($QlogicOptions.options)."
									InfoMessage "Silk's BP recommendation is ql2xintrdelaytimer=1 ql2xoperationmode=6 ql2xmaxqdepth=$($HBA_ql2xmaxqdepth)"
								} 
								else {
									GoodMessage "Qlogic Options are properly configured according to Silk's BP ($($QlogicOptions.options))"
								}
							} 
							else {
								InfoMessage "The Qlogic module was not found."
							}
						}
						else {
							InfoMessage "Validation for Qlogic settings is only valid for FC connectivity"
						}
						
						$MessageCounter++
						PrintDelimiter

						# Validate VAAI Primitives enabled
						# ================================
						InfoMessage "$MessageCounter - Running validation for VAAI Primitives"
						$HardwareAcceleratedMove    = $vmhost | Get-AdvancedSetting -Name DataMover.HardwareAcceleratedMove | Select-Object Value
						$HardwareAcceleratedInit    = $vmhost | Get-AdvancedSetting -Name DataMover.HardwareAcceleratedInit | Select-Object Value
						$HardwareAcceleratedLocking = $vmhost | Get-AdvancedSetting -Name VMFS3.HardwareAcceleratedLocking  | Select-Object Value
						if (($HardwareAcceleratedMove.Value + $HardwareAcceleratedInit.Value + $HardwareAcceleratedLocking.Value) -ne 3 ) {
							BadMessage "VAAI Primitives are not configured according to Silk's BP."
							BadMessage "Current settings are HardwareAcceleratedMove=$($HardwareAcceleratedMove.Value), HardwareAcceleratedInit=$($HardwareAcceleratedInit.Value), HardwareAcceleratedLocking=$($HardwareAcceleratedLocking.Value)"
						} 
						else {
							GoodMessage "VAAI Primitives are properly configured according to Silk's BP"
							GoodMessage "Current settings are HardwareAcceleratedMove=$($HardwareAcceleratedMove.Value), HardwareAcceleratedInit=$($HardwareAcceleratedInit.Value), HardwareAcceleratedLocking=$($HardwareAcceleratedLocking.Value)"
						}

						$MessageCounter++
						PrintDelimiter
						
						# Validate all Silk’s volumes are set to Round Robin 
						# ==================================================
						InfoMessage "$MessageCounter - Running validation for Round-Robin (Multipath configuration)"
						$BadRRVolumes          = $vmhost | Get-ScsiLun -LunType "disk" | Where-Object {$_.Vendor -eq "KMNRIO"}
						$Silk_MultipathPolicy  = "RoundRobin"
						$Silk_CommandsToSwitchPath = 2
						if ($BadRRVolumes) {
							foreach ($BadRRVolume in $BadRRVolumes | Sort-Object) {
								if (($BadRRVolume.MultipathPolicy -ne $Silk_MultipathPolicy) -Or ($BadRRVolume.CommandsToSwitchPath -ne $Silk_CommandsToSwitchPath)) {
									if ([string]::IsNullOrEmpty($BadRRVolume.CommandsToSwitchPath)) {
										BadMessage "Silk disk $($BadRRVolume) is set to MultipathPolicy=$($BadRRVolume.MultipathPolicy) and CommandsToSwitchPath=null"
									} 
									else {
										BadMessage "Silk disk $($BadRRVolume) is set to MultipathPolicy=$($BadRRVolume.MultipathPolicy) and CommandsToSwitchPath=$($BadRRVolume.CommandsToSwitchPath)"
									}
								}
								else {
									GoodMessage "Silk disk $($BadRRVolume) is set to MultipathPolicy=$($BadRRVolume.MultipathPolicy) and CommandsToSwitchPath=$($BadRRVolume.CommandsToSwitchPath)"
								}
							}
						} 
						else {
							InfoMessage "No Silk volumes were found."
						}
						$MessageCounter++
						PrintDelimiter
						
						# Validate Space Reclamation.
						# ===========================
						InfoMessage "$MessageCounter - Running validation for Space Reclamation (Priority Level)"
						if ($esxVersion.Version -ge 6.5) {
							$DatastoreInfo = $vmhost | Get-Datastore | Where-Object{$_.Type -eq "VMFS"} | Select-Object Name, @{N="CanonicalName";E={($_.ExtensionData.Info.Vmfs.Extent[0]).DiskName}}, `
							@{N="UnmapPriority";E={$_.ExtensionData.Info.Vmfs.UnmapPriority}},@{N="Version";E={$_.ExtensionData.Info.Vmfs.MajorVersion}},@{N="Uuid";E={$_.ExtensionData.Info.Vmfs.Uuid}} `
							| Where-Object {$_.CanonicalName -match "0024f400"}

							$Silk_UnmapPriority = "low"  
							$Silk_UnmapMethod   = "priority"
							$esxcli             = get-esxcli -VMHost $vmhost -v2
							
							foreach ($Datastore in $DatastoreInfo | Sort-Object CanonicalName) {
								if($Datastore.Version -ge 6) {
									if($Datastore.UnmapPriority -eq $Silk_UnmapPriority) {
										if($esxVersion.Version -ge 6.7) {	
											$unmapresult          = $null
											$DS_UnmapMethod       = $null
											$unmapargs            = $esxcli.storage.vmfs.reclaim.config.get.createargs()
											$unmapargs.volumeuuid = $Datastore.Uuid
											$unmapresult          = $esxcli.storage.vmfs.reclaim.config.get.invoke($unmapargs)
											$DS_UnmapMethod       = $unmapresult.ReclaimMethod

											if ($DS_UnmapMethod -ne $Silk_UnmapMethod) {
												BadMessage "CanonicalName - $($Datastore.CanonicalName) | Datastore - $($Datastore.Name) - is not properly configured according to Silk's BP. Reclaim Priority is - $($Datastore.UnmapPriority) | Reclaim Method is - $($DS_UnmapMethod) | Reclaim Bandwidth is - $($unmapresult.ReclaimBandwidth)"	
											}
											else {
												GoodMessage "CanonicalName - $($Datastore.CanonicalName) | Datastore - $($Datastore.Name) - is properly configured according to Silk's BP. Reclaim Priority is - $($Datastore.UnmapPriority) | Reclaim Method is - $($DS_UnmapMethod) | Reclaim Bandwidth is - $($unmapresult.ReclaimBandwidth)"
											}
										}
										else {
											GoodMessage "CanonicalName - $($Datastore.CanonicalName) | Datastore - $($Datastore.Name) - is properly configured according to Silk's BP. Reclaim Priority is - $($Datastore.UnmapPriority)."
										}
									}
									else {
										BadMessage "CanonicalName - $($Datastore.CanonicalName) | Datastore - $($Datastore.Name) - is not properly configured according to Silk's BP. Reclaim Priority is - $($Datastore.UnmapPriority)."
									}
								}	
								else {
									WarningMessage "CanonicalName - $($Datastore.CanonicalName) | Datastore - $($Datastore.eName) - VMFS Version is below 6, Automated Storage Space Reclamation feature is supported only on VMFS6 datastores."
								}	
							}  
						}
						else {
							WarningMessage "ESX Version is $($esxVersion.Version), and it is supported with ESXi version 6.5 and above"
						}

						$MessageCounter++
						PrintDelimiter

						# Validate SATP rule is configured
						# ================================
						InfoMessage "$MessageCounter - Running validation for SATP"
						$esxcli = Get-EsxCli -VMHost $vmhost -V2
						$SATP_Values = $esxcli.storage.nmp.satp.rule.list.invoke() | Where-Object {($_.Vendor -eq "KMNRIO") -and ($_.Model -eq "K2")}
						$issuecount  = 0

						if ($SATP_Values.Count -ge 1) {
							if ($SATP_Values.Count -gt 1) {
								BadMessage "There is more than one KMNRIO SATP rule. The last rule found will be the one in use."	
							}
							else {
								if ($SATP_Values.DefaultPSP -ne "VMW_PSP_RR") {
									BadMessage "Silk BP recommends setting SATP default psp to VMW_PSP_RR. Current value is $($SATP_Values.DefaultPSP)."
									$issuecount = $issuecount + 1
								}
								if ($SATP_Values.PSPOptions -NotMatch "\biops=2\b") {
									BadMessage "Silk BP recommends setting SATP default pspoption to iops=2. Current value is $($SATP_Values.PSPOptions)."
									$issuecount = $issuecount + 1
								}
								if ($SATP_Values.Model -ne "K2") {
									BadMessage "Silk BP recommends setting SATP Model to K2. Current value is $($SATP_Values.Model)."
									$issuecount = $issuecount + 1
								}
								if ($SATP_Values.Vendor -ne "KMNRIO") {
									BadMessage "Silk BP recommends setting SATP Vendor to KMNRIO. Current value is $($SATP_Values.Vendor)."
									$issuecount = $issuecount + 1
								}
								if ($SATP_Values.Name -ne "VMW_SATP_DEFAULT_AA") {
									BadMessage "Silk BP recommends setting SATP name to VMW_SATP_DEFAULT_AA. Current value is $($SATP_Values.Name)."
									$issuecount = $issuecount + 1
								}
								if ($SATP_Values.ClaimOptions -ne "tpgs_off") {
									BadMessage "Silk BP recommends setting SATP ClaimOptions to tpgs_off. Current value is $($SATP_Values.ClaimOptions)."
									$issuecount = $issuecount + 1
								}
								if ($issuecount -ge 1) {
									BadMessage "Silk SATP rule found, yet without the right values : "
									handle_string_array_messages $(($SATP_Values | out-string).trim()) "Data"
								}
								else {
									GoodMessage "Silk SATP rule found and with right values : " 
									handle_string_array_messages $(($SATP_Values | out-string).trim()) "Data"									
								}
							}
						}
						else {
							BadMessage "Silk SATP rule is missing"
						}
						$MessageCounter++
						PrintDelimiter

						# Validate EnableBlockDelete
						# ==========================
						InfoMessage "$MessageCounter - Running validation for EnableBlockDelete"
						if ($esxVersion.Version -ge 6) {
							$EnableBlockDelete = $vmhost | Get-AdvancedSetting -Name VMFS3.EnableBlockDelete
							if ($EnableBlockDelete.Value -eq 1) {
								GoodMessage "EnableBlockDelete setting is enabled."
							}
							else {
								BadMessage "EnableBlockDelete is disabled."
							}
						}
						else {
							WarningMessage "The current host is not version 6.x.* Skipping (EnableBlockDelete)..."
						}
						$MessageCounter++
						PrintDelimiter

						# Validate CBRC 
						# =============
						InfoMessage "$MessageCounter - Running validation for CBRC"
						$CBRCEnable = $vmhost | Get-AdvancedSetting -Name CBRC.Enable | Select-Object Value
						if ($CBRCEnable.Value -like "True") {
							GoodMessage "CBRC is Enabled."
							InfoMessage "Running validation for CBRC DCacheMemReserved parameter"
							$CBRCCache_Silk_BP_Value = 2048
							$CRBC_DCacheMemReserved_Value = ($vmhost | Get-AdvancedSetting -Name CBRC.DCacheMemReserved).Value
							if ($CRBC_DCacheMemReserved_Value -eq $CBRCCache_Silk_BP_Value) {
								GoodMessage "CBRC DCacheMemReserved is properly configured according to Silk's BP - $($CBRCCache_Silk_BP_Value)."
							}
							else {
								BadMessage "CBRC DCacheMemReserved is not set properly configured according to Silk's BP - $($CRBC_DCacheMemReserved_Value)"
							}
						}
						else  {
							BadMessage "CBRC is Disabled"
						}

						InfoMessage "Validation for $($vmhost) completed."
						
						# add a spacer for the HTML output 
						PrintDelimiter
						$SDPBPHTMLBody += "<div id='host_space'></div>"
					}
				}
			}
		}
		catch {
			# Get the exception messages
			$ExceptionMessage = $_.Exception.Message
			$line             = $_.InvocationInfo.ScriptLineNumber
			BadMessage "Caught exception during VMware validator at line: $($line)"
			BadMessage $ExceptionMessage
		}
		Finally {
			# Once all data is collected - output into HTML
			$MessageCurrentObject = "Finished Validating`n"
			
			PrintDelimiterServer
			
			if($VMwareConnect) {
				if($VMwareConnect.IsConnected) {
					Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$False -Force -ErrorAction SilentlyContinue
					InfoMessage "Disconnected from VM $($VMwareConnect.Name)"
				} 
				else  {
					InfoMessage "$($VMwareConnect.Name) is not connect, nothing to Disconnect"
				}
			}
		}
	}
}
#endregion

#region Windows_Validator
function Windows_Validator {
	[cmdletbinding()] 
	Param(	
		[parameter()][String[]]$WinServerArray,	
		[System.Management.Automation.PSCredential]	
		$Credential = [System.Management.Automation.PSCredential]::Empty
		)

	# Start script initialization	
	# We will use the vmhost variable as a dummy to hold the "Initialization" string.
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

				$MessageCounter++
				PrintDelimiter 
				
				InfoMessage "$MessageCounter - Running validation for Multipath configuration (Get-MPIOSetting)"
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
							'PDORemovePeriod'           { $PDORemovePeriod = $($MPIOobject.Split(':')[1]) } # 20 FC / 80 iSCSI
							'RetryCount'                { $RetryCount = $($MPIOobject.Split(':')[1]) } # 3
							'RetryInterval'             { $RetryInterval = $($MPIOobject.Split(':')[1]) } # 3
							'UseCustomPathRecoveryTime' { $UseCustomPathRecoveryTime = $($MPIOobject.Split(':')[1]) } # Disabled
							'CustomPathRecoveryTime'    { $CustomPathRecoveryTime = $($MPIOobject.Split(':')[1]) }	# 40
							'DiskTimeoutValue'          { $DiskTimeOutValue = $($MPIOobject.Split(':')[1]) } # 60
						}
					}

					# Print the MPIO Settings
					InfoMessage "MPIO Settings Section are:"

					# Print the MPIO into the html
					handle_string_array_messages $MPIO_out "Data"

					# Checking the MSDSM supported hardware list
					$MSDSMSupportedHW_out = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMSupportedHW})
					$MSDSMSupportedHW_out = ($MSDSMSupportedHW_out | Select-Object ProductId, VendorId | Format-Table * | Out-String).Trim()

					# Print the MPIO Settings
					InfoMessage "MSDSM supported hardware list Section :"

					# Print the MPIO into the html
					handle_string_array_messages $MSDSMSupportedHW_out "Data"

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
					
					if ($DiskTimeOutValue -match "60") {
						GoodMessage "DiskTimeOutValue value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "DiskTimeOutValueDiskTimeOutValue value is not set 45, Current Value is $($DiskTimeOutValue)"
					}
					
					if ($RetryInterval -match "3") {
						GoodMessage "RetryInterval value is properly configured according to Silk's BP."
					}
					else { 
						BadMessage "RetryInterval value is not set 3, Current Value is $($RetryInterval)"
					}
					
					if ($UseCustomPathRecoveryTime -match "Disabled") {
						GoodMessage "UseCustomPathRecoveryTime value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "UseCustomPathRecoveryTime value is not set Enabled, Current Value is $($UseCustomPathRecoveryTime)"
					}

					if ($CustomPathRecoveryTime -match "40") {
						GoodMessage "CustomPathRecoveryTime value is properly configured according to Silk's BP"
					}
					else { 
						BadMessage "CustomPathRecoveryTime value is not set 20, Current Value is $($CustomPathRecoveryTime)"
					}

					# Checking values that depend on connectivity type
					switch($systemConnectivitytype)	{
						"fc" {
							if ($PDORemovePeriod -match "20") {
								GoodMessage "PDORemovePeriod value is properly configured according to Silk's BP"
							}
							else { 
								BadMessage "PDORemovePeriod value is not set 20, Current Value is $($PDORemovePeriod)"
							}
						}
						"iscsi" {
							if ($PDORemovePeriod -match "80") {
								GoodMessage "PDORemovePeriod value is properly configured according to Silk's BP"
							}
							else { 
								BadMessage "PDORemovePeriod value is not set 80, Current Value is $($PDORemovePeriod)"
							}

							# Checking the MSDSM supported hardware list					
							$MSDSMSupportedHW = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMSupportedHW -VendorId MSFT2005 -ProductId iSCSIBusType_0x9})
							if ($MSDSMSupportedHW) {
								GoodMessage "MPIO DSM value is properly configured according to Silk's BP"
							}
							else {
								BadMessage "MPIO DSM is not set to -VendorId MSFT2005 -ProductId iSCSIBusType_0x9, or could not found it, try to run Get-MSDSMSupportedHW command"
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
					}					

					# Checking the KMNRIO supported hardware list - Associating Silk Data Platform Volumes with MPIO DSM				
					$MSDSMSupportedHW = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMSupportedHW -VendorId KMNRIO -ProductId K2})
					if ($MSDSMSupportedHW) {
						GoodMessage "MPIO DSM KMNRIO & K2 DSM value is properly configured according to Silk's BP"
					}
					else {
						BadMessage "MPIO DSM is not set to -VendorId KMNRIO -ProductId K2, or could not found it, try to run Get-MSDSMSupportedHW command"
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
				}
				else {
					BadMessage "MPIO is not fully installed or Enabled, because of that, we can't continue with validate the MPIO Settings"
				}

				$MessageCounter++
				PrintDelimiter

				# Load Balance and Failover Policy for Individual Volumes
				InfoMessage "$MessageCounter - Running validation for Load Balance and Failover Policy for Individual Volumes"
				$Server_KMNRIO_PD = (invoke-Command -Session $pssessions -ScriptBlock {(Get-PhysicalDisk | Where-Object {($_.FriendlyName -match "KMNRIO K2") -OR ($_.FriendlyName -match "SILK K2") -OR ($_.FriendlyName -match "SILK SDP")} | Sort-Object DeviceID | `
				Select-object DeviceId,SerialNumber,FriendlyName,@{N="LoadBalancePolicy";E={($_ | Get-PhysicalDiskStorageNodeView | Select-Object LoadBalancePolicy).LoadBalancePolicy}}, `
				CanPool,OperationalStatus,HealthStatus,@{Name="Size, Gb"; Expression={$_.Size/1Gb}},@{N="DriveLetter";E={($_ | Get-Disk | Get-Partition | Where-Object {$_.DriveLetter}).DriveLetter}}, `
				@{N="DiskStatus";E={($_ | Get-Disk | select-object OperationalStatus).OperationalStatus}},@{N="PartitionStyle";E={($_ | Get-Disk | select-object PartitionStyle).PartitionStyle}})})

				# Check the PD count 
				if($Server_KMNRIO_PD) {

					# Print the MPIO Settings
					InfoMessage "Silk Disks Settings Section :"
					$Server_KMNRIO_PD_out = ($Server_KMNRIO_PD | Select-Object DeviceId,SerialNumber,FriendlyName,LoadBalancePolicy,CanPool,OperationalStatus,HealthStatus,Size-Gb,DriveLetter,DiskStatus,PartitionStyle | Format-Table * | Out-String).Trim() 

					# Print the MPIO into the html
					handle_string_array_messages $Server_KMNRIO_PD_out "Data"

					foreach ($PD_Temp in $Server_KMNRIO_PD)	{
						# Check for each Individual if it LQD or not
						if ($PD_Temp.LoadBalancePolicy -match "Least Queue Depth")	{
							GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DeviceId) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Least Queue Depth)"
						}
						else {
							BadMessage "Silk Disk (DiskNumber - $($PD_Temp.DeviceId) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (Least Queue Depth) but set to - $($PD_Temp.LoadBalancePolicy)" 
						}
					}
				}
				else {
					InfoMessage "No SILK SDP Disks found on the server"
				}
				
				$MessageCounter++
				PrintDelimiter

				# Check that CTRL volume is OFFLINE
				InfoMessage "$MessageCounter - Running validation for Silk CTRL LU..."
				if($Server_KMNRIO_PD) {
					# Run over the CTRL disks and verify that each disk is with Offline state
					foreach ($PD_Temp in ($Server_KMNRIO_PD | Where-Object {$_.SerialNumber.EndsWith("0000")})) {
						# Check for each Individual if it Offline or not
						if ($PD_Temp.DiskStatus -match "Offline") {
							GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DeviceId) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Disk Status Offline)"
						}
						else {
							BadMessage "Silk Disk (DiskNumber - $($PD_Temp.DeviceId) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (Disk Status Offline) but set to - $($PD_Temp.DiskStatus)"
						}
					}
					
				}
				else {
					InfoMessage "No SILK SDP Disks found on the server, Could not verify the CTRL LU state"
				}

				$MessageCounter++
				PrintDelimiter 

				# Check that TRIM/UNMAP Registry Key
				InfoMessage "$MessageCounter - Running validation for Windows TRIM/UNMAP Registry Key..."
				$WindowsrimUnampRegData = (invoke-Command -Session $pssessions -ScriptBlock {Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name DisableDeleteNotification})
				if($WindowsrimUnampRegData) {					
					if ($WindowsrimUnampRegData.DisableDeleteNotification -eq 1) {
						GoodMessage "Trim / UNMAP registry key Disable Update Notification set properly (to 1)"
					}
					else {
						BadMessage "Trim / UNMAP registry key Disable Update Notification is not set properly (to 1) but to - $($WindowsrimUnampRegData.DisableDeleteNotification)"
					}
				}
				else {
					InfoMessage "No DisableDeleteNotification was found in registry under HKLM:\System\CurrentControlSet\Control\FileSystem location"
				}

				$MessageCounter++
				PrintDelimiter 

				switch($systemConnectivitytype) {
					"fc" {
						#validating FC BP
						InfoMessage "$MessageCounter - Running validation for FC configuration"

						$HBA_hbas = invoke-Command -Session $pssessions -ScriptBlock {
							$Namespace = "root\WMI"
							Get-WmiObject -List -Namespace $Namespace | Where-Object { $_.Name -eq 'MSFC_FCAdapterHBAAttributes' }
						}

						if(!$HBA_hbas) {
							BadMessage "Could not Query WMI objects of MSFC classes"
						}
						else{
							$hbaArray = invoke-Command -Session $pssessions -ErrorAction 'SilentlyContinue' -ScriptBlock {
								$Namespace = "root\WMI"
								
								try{
									$colHBA = Get-WmiObject -Class MSFC_FCAdapterHBAAttributes -Namespace $Namespace @PSBoundParameters
								}
								catch {
									return $null
								}
								
								# Create empty array of FC cards
								$ReturnhbaArray = @()

								foreach ($objHBA in $colHBA) 
								{
									$objDeets = [PSCustomObject] @{
										"Computername"      = $objComputer
										"Node_WWN"          = (($objHBA.NodeWWN) | ForEach-Object {"{0:X2}" -f $_}) -join ""
										"Model"             = $objHba.Model
										"MfgDomain"         = $objHBA.MfgDomain
										"Manufacturer"      = $objHBA.Manufacturer
										"Model_Description" = $objHBA.ModelDescription
										"Driver_Version"    = $objHBA.DriverVersion
										"Firmware_Version"  = $objHBA.FirmwareVersion
										"Active"            = $objHBA.Active
									}
									$ReturnhbaArray += $objDeets
								}

								$ReturnhbaArray
							}

							if(!$hbaArray) {
								BadMessage "WMI MSFC_FCAdapterHBAAttributes class are not supported, and coould not check FC cards"
							}
							else {								
								# Check if one of the FC ports is qlogic.
								if($hbaArray.MfgDomain -match "qlogic")	{
									# Find location of the qLogic installation
									$QConvergeCliLocation  = (invoke-Command -Session $pssessions -ScriptBlock {(get-command qaucli.exe).source})
									
									if(!$QConvergeCliLocation) {
										BadMessage "qconvergeconsole cli (qaucli.exe) service tool is not installed, Please check the Qlogic manually"
									}
									else {
										# Get the list of all qLogic HBA instances
										$qauclioutput_hba = (invoke-Command -Session $pssessions -Args $QConvergeCliLocation -ScriptBlock {Invoke-Expression "& '$args' -pr fc -g"})

										if($qauclioutput_hba) {
											$qauclioutput_hba = $qauclioutput_hba | Select-String "HBA Instance" | Select-Object -Property @{ Name = 'Row';  Expression = {$_}}, `
											@{ Name = 'HBA_Instance'; Expression = { ($_.ToString().split(")")[0].trim().split(" "))[-1]}}, `
											@{ Name = 'HBA_Status'; Expression = { ($_.ToString().split(")"))[1].trim()}}

											foreach($hba in $qauclioutput_hba) {
												# Check if the link is Online
												if($hba.HBA_Status -eq "Online") {
													InfoMessage "Working on HBA - $($hba.Row.ToString().trim())"
													$hba_temp_instance = $hba.HBA_Instance

													# Get the data for all qlogic HBA ports
													$qauclioutput = (invoke-Command -Session $pssessions -ArgumentList  $QConvergeCliLocation,$hba_temp_instance -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -c '$a2'"})

													# Calling to comman function of QLogic HBA checking
													QLogic_HBA_Settings_Check $qauclioutput
												}
												else {
													WarningMessage "Skipping  HBA - $($hba.Row.ToString().trim()) becouse is status is not Online, but - $($hba.HBA_Status)"	
												}
											}
										}
										else {
											BadMessage "qlogic quacli command (qaucli -pr fc -g) could not found any HBA ports"
										}
									}
								}
								else {
									InfoMessage "Skipping FC check since HBA card/s is/are not Qlogic type"
								}
							}
						}
					}
					"iscsi" {
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
						
						InfoMessage "$MessageCounter - Running validation for iSCSI Network Adapter/s" 
						if (($MSiSCSI.State -match "Running") -And ($MSiSCSI.Status -match "OK"))
						{
							$iscsieth = invoke-Command -Session $pssessions -ScriptBlock {(Get-IscsiTargetPortal).InitiatorPortalAddress | Sort-Object -Unique}
							if(!$iscsieth) {
								WarningMessage "Could not find active iSCSI Network Adapters"
							}
							else {
								# Run over the ISCSI network card
								foreach($iscsiadapter in $iscsieth) {
									# For each ISCSI netork card get his properies
									$iscsinetadapter                 = invoke-Command -Session $pssessions -Args $iscsiadapter -ScriptBlock {(Get-NetIPAddress -IPAddress $args[0]).InterfaceAlias}
									$iscsinetadapteradvancedproperty = invoke-Command -Session $pssessions -Args $iscsinetadapter -ScriptBlock {(get-netadapteradvancedproperty -name $args[0])}
									
									# Write that we are working on iscsinetadapter
									InfoMessage "Checking full setings for iSCSI Adapter - $($iscsinetadapter)"

									$iscsinetadapteradvancedproperty_out = ($iscsinetadapteradvancedproperty | Select-object ifAlias,InterfaceAlias,ValueName,ValueData | Format-table * | Out-String).Trim()
									# Print the MPIO into the html
									handle_string_array_messages $iscsinetadapteradvancedproperty_out "Data"

									# Jambo Property section
									$iSCSI_jumbo = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "jumbo"})
									if($iSCSI_jumbo) {
										if ($iSCSI_jumbo.RegistryValue -match "9014") {
											GoodMessage "iSCSI network adapter $iscsinetadapter Jumbo Packet is properly configured according to Silk's BP"
										}
										else { 
											BadMessage "iSCSI network adapter $iscsinetadapter is not set to run Jumbo Packets 9014 but set to $($iSCSI_jumbo.RegistryValue)"
										}
									}
									else {
										WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Jumbo Property"
									}
									
									# Flow Property section
									$iSCSI_flow = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "flow"})
									if($iSCSI_flow) {
										if ($iSCSI_flow.DisplayValue -match "Rx & Tx Enabled") {
											GoodMessage "iSCSI network adapter $iscsinetadapter Flow Control is properly configured according to Silk's BP"
										}
										else { 
											BadMessage "iSCSI network adapter $iscsinetadapter Flow Control is not set to 'Rx & Tx Enabled' but set to $($iSCSI_flow.DisplayValue)"
										}
									}
									else {
										WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Flow Property"
									}

									# duplex Property section
									$iSCSI_duplex = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "duplex"})
									if($iSCSI_duplex) {
										if ($iSCSI_duplex.DisplayValue -match "10 Gbps Full Duplex") {
											GoodMessage "iSCSI network adapter $iscsinetadapter speed and duplex is properly configured according to Silk's BP"
										}
										else { 
											BadMessage "iSCSI network adapter $iscsinetadapter speed and duplex is not set to 10 Gbps full Duplex but set to $($iSCSI_duplex.DisplayValue)"
										}
									}
									else {
										WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Duplex Property"
									}

									# side scaling Property section
									$iSCSI_side_scaling = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "side scaling"})
									if($iSCSI_side_scaling) {
										if ($iSCSI_side_scaling.DisplayValue -match "Disabled") {
											GoodMessage "iSCSI network adapter $iscsinetadapter Receive Side Scaling  is properly configured according to Silk's BP"
										}
										else { 
											BadMessage "iSCSI network adapter $iscsinetadapter Receive Side Scaling is not set to Disabled but set to $($iSCSI_side_scaling.DisplayValue)"
										}
									}
									else {
										WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Side Scaling Property"
									}

									# Power Saving Property section
									$adapter_power_saving = invoke-Command -Session $pssessions -Args $iscsinetadapter -ScriptBlock {(Get-NetAdapterPowerManagement -Name $args[0]).AllowComputerToTurnOffDevice}
									if($adapter_power_saving) {
										if ($adapter_power_saving -match "Disabled") {
											GoodMessage "iSCSI network adapter $iscsinetadapter Power Saving is properly configured according to Silk's BP"
										}
										else { 
											BadMessage "iSCSI network adapter $iscsinetadapter Power Saving is not set to Disabled but set to $($adapter_power_saving)"
										}
									}
									else {
										WarningMessage "Could not get the iSCSI network adapter $iscsinetadapter network adapter power management and validate if it contain Power Saving Property"
									}
								}
							}
						}
						else {
							BadMessage "The MSiSCSI service has not been started, could not check iSCSI Network Adapters"
						}
					}
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
		[parameter()][string[]]$ServerArray,
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
		[string[]]$Mpio_Section,
		[string]$Parameter_name,
		[string[]]$Parameter_value_array
		)

		[System.Boolean]$bFound = $false

		$Mpio_Checking_Value = ($Mpio_Section) -match ($Parameter_name)
		if ($Mpio_Checking_Value) {
			foreach($mpioRow in $Mpio_Checking_Value.Trim().Split("`n").Trim()) {
				if(($mpioRow -match $Parameter_value_array[0]) -or ($mpioRow -match [regex]::escape($Parameter_value_array[0]))) {
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
			BadMessage "multipath.conf is missing $($Parameter_name) parameter"
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
				$command = "sudo dpkg -l | grep $($Pacakge)"
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

	#region Checking_File_Content
	Function Checking_File_Content {
		Param(
		[string]$FilePath,
		[string]$FileConParameter,
		[string]$FileConSeparator,
		[string]$FileConValue
		)
		
		# Boolean helper
		$bFileFound = $false

		# Note: make sure iscsi is set for automatic login:
		# in /etc/iscsi/iscsid.conf , key “node.startup = automatic”
		if($bLocalServer) {
			# Test the path of the the file
			if (-not (Test-Path -Path $FilePath)) {
				BadMessage "File - $($FilePath) not found!"
			} else {
				# Checking the content found, if yes, checking the value
				$FileConFound = (Get-Content -Path $FilePath | Select-String -Pattern $("^$FileConParameter")).Line.Trim()			
				$bFileFound = $True
			}
		}
		else {
			$command     = "sudo cat $($FilePath)"
			$FileContent = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command	
			if (-not ($FileContent)) {
				BadMessage "File - $($FilePath) not found!"
			} else {
				# Checking the content found, if yes, checking the value
				$FileConFound = ($FileContent | Select-String -Pattern $("^$FileConParameter")).Line.Trim()
				$bFileFound = $True
			}
		}

		if($bFileFound) {
			if(-not ($FileConFound)) {
				BadMessage "File - $($FilePath) Don't contain $($FileConParameter)!"
			} else {
				$FileConFoundValue = $FileConFound.Split($FileConSeparator)[1].Trim()
				if(-not ($FileConFoundValue -eq $FileConValue)) {
					BadMessage "File - $($FilePath) contain - $($FileConParameter), Yet value is not $($FileConValue) but a $($FileConFoundValue)"
				} else {
					GoodMessage "File - $($FilePath) contain - $($FileConParameter), With value of a $($FileConValue)"
				}
			}
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
								elseif($Linux_OS_Version -ge 5)
								{
									$linuxtype = "rhel5"
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
						write-host -ForegroundColor Black -BackgroundColor White "Option A - RedHat 5.x" 
						write-host -ForegroundColor Black -BackgroundColor White "Option A - RedHat 6.x, CentOS 6.x, Oracle 6.x, Suse 11.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option B - RedHat 7.x, CentOS 7.x, CentOS 8.x, Suse 12.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option C - Debian 6.x, Ubuntu 12.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option D - Debian 7.x, Ubuntu 14.x"

						# Choose the Linux distributions 
						$linuxtitle   = "Please select a Linux distribution"
						$linuxmessage = "Please select from the following options"
						$rhel5 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &A", "Configuring settings according to a RedHat 5 system best practices."
						$rhel6 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &B", "Configuring settings according to a RedHat 6 system best practices."
						$rhel7 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &C", "Configuring settings according to a RedHat 7 system best practices."
						$debian6 	  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &D", "Configuring settings according to a Debian 6 system best practices."
						$debian7 	  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &E", "Configuring settings according to a Debian 7 system best practices."

						$linuxoptions = [System.Management.Automation.Host.ChoiceDescription[]]($rhel5,$rhel6, $rhel7, $debian6, $debian7)
						$linuxresult  = $host.ui.PromptForChoice($linuxtitle, $linuxmessage, $linuxoptions,0) 
						
						switch ($linuxresult) {
							0 {$linuxtype = "rhel6"}
							1 {$linuxtype = "rhel7"}
							2 {$linuxtype = "debian6"}
							3 {$linuxtype = "debian7"}
						}
					}

					InfoMessage "$MessageCounter - Silk Validator script will validate according to Linux distribution - $($linuxtype)"
					
					$MessageCounter++
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

					switch ($systemConnectivitytype) {
						"fc" {							
							$command = "sudo lspci | grep -i 'Fibre Channel'"
							if($bLocalServer) {
								$Network_Data = Invoke-Expression $command
							}
							else {
								$Network_Data = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
							}
							
							# Checking about the lshw tool 
							if($Network_Data) {
								# Print the data
								InfoMessage "Server FC Network is:"
								handle_string_array_messages ($Network_Data | Out-String).Trim() "Data"
							}
							else {
								WarningMessage "Could not read the FC Network Cards using lspci command."
							}
						}
						"iscsi" {
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
								InfoMessage "Server iSCSI Network is:"
								handle_string_array_messages ($Network_Data | Out-String).Trim() "Data"
							}
							else {
								WarningMessage "Could not read the Network Cards, missing lshw tool."
							}
						}
					}
					$MessageCounter++
					PrintDelimiter

					# Checking the PREREQUISITES of the packages that must be installed on the machine (device-mapper-multipath* / lsscsi  / scsi-initiator-utils*)
					InfoMessage "$MessageCounter - Validate Server Pckages and Services according to Silk BP"

					switch -Wildcard ($linuxtype) {
						'rhel*' {
							Checking_Package "device-mapper-multipath" $linuxtype
							Checking_Service "multipathd" $linuxtype
						}
						'debian*' {
							Checking_Package "multipath-tools" $linuxtype
							Checking_Package "multipath-tools-boot" $linuxtype
							Checking_Service "multipathd" $linuxtype
						}
					}

					# Addtional packages and Services for iSCSI cnnectivity
					if($systemConnectivitytype -eq "iscsi")	{
						switch -Wildcard ($linuxtype) {
							'rhel*' {							
								Checking_Package "lsscsi" $linuxtype
								Checking_Package "iscsi-initiator-utils" $linuxtype
								Checking_Service "iscsid" $linuxtype
							}
							'debian*' {
								#Checking_Package "lsscsi" $linuxtype
								Checking_Package "open-iscsi" $linuxtype
								Checking_Service "iscsid" $linuxtype
								Checking_Service "open-iscsi" $linuxtype
							}
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

						# Define BP parameters for MPIO (multipath.conf) and scheduler (62-io-schedulers.rules) according to the OS type
						switch -Wildcard ($linuxtype) {
							'rhel*' {
								switch ($linuxtype) {
									#Rhel 7 params
									rhel7 {
										$path_selector_param    = '\"queue-length 0"' , "queue-length 0"
										$failback_param         = '\bimmediate\b' , "immediate"
										$fast_io_fail_tmo_param = '\b2\b' , "2"
										$dev_loss_tmo_param     = '\b3\b' , "3"
									}
									#Rhel 6 params
									rhel6 {
										$getuid_callout_param   ='\"/lib/udev/scsi_id --whitelisted --device=/dev/%n"' ,"/lib/udev/scsi_id --whitelisted --device=/dev/%n"
										$path_selector_param    = '\"queue-length 0"' ,"queue-length 0"
										$failback_param         = '\b15\b' , "15"
										$fast_io_fail_tmo_param = '\b5\b' , "5"
										$dev_loss_tmo_param     = '\b8\b' , "8"
									}
									#Rhel 5 params
									rhel5 {
										$getuid_callout_param = '\"/sbin/scsi_id -g -u -s /block/%n"',"/sbin/scsi_id -g -u -s /block/%n"
										$path_selector_param  =  '\"round-robin 0"' ,"round-robin 0"
										$failback_param       = '\b15\b' , "15"
									}
								}
							}
							'debian*' {
								switch ($linuxtype) {
									#debian 6 params
									debian6 {
										$getuid_callout_param   ='\"/lib/udev/scsi_id --whitelisted --device=/dev/%n"' ,"/lib/udev/scsi_id --whitelisted --device=/dev/%n"
										$path_selector_param    = '\"queue-length 0"' ,"queue-length 0"
										$failback_param         = '\b15\b' , "15"
										$fast_io_fail_tmo_param = '\b5\b' , "5"
										$dev_loss_tmo_param     = '\b8\b' , "8"
									}
									#debian 7 params 
									debian7 {
										$path_selector_param = '\"queue-length 0"' ,"queue-length 0"
										$failback_param      = '\b15\b' , "15"
									}
								}
							}
						}


						#global values- not changing per distro
						# defaults section
						$user_friendly_names_param  = '\byes\b' , "yes"
						$polling_interval_param     = '\b1\b' , "1"
						$find_multipaths_param      = '\byes\b' , "yes"
						
						# blacklist section
						$devnode_param              = "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"
						
						# devices sesction
						$vendor_param               = '\"KMNRIO"' , "KMNRIO"
						$product_param              = '\"K2"' , "K2"
						$path_grouping_policy_param = '\bmultibus\b' , "multibus"
						$path_checker_param         = '\btur\b' , "tur"
						$no_path_retry_param        = '\bfail\b' , "fail"
						$hardware_handler_param     = '\"0"' , "0"
						$rr_weight_param            = '\bpriorities\b' , "priorities"
						$rr_min_io_param            = '\b1\b' , "1"

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
							ValidateAttrinuteInMpio -Mpio_Section $defaults_data -Parameter_name "user_friendly_names" -Parameter_value_array $user_friendly_names_param
							ValidateAttrinuteInMpio -Mpio_Section $defaults_data -Parameter_name "polling_interval" -Parameter_value_array $polling_interval_param
							ValidateAttrinuteInMpio -Mpio_Section $defaults_data -Parameter_name "find_multipaths" -Parameter_value_array $find_multipaths_param							
						}

						if(!$blacklist_line_check) {
							BadMessage "Could not found the blacklist section in Multipath.conf, skipping checking Multipath blacklist Section"
						}
						else {
							$blacklist_line_b = $outItems_array[($outItems_array | Select-String -Pattern 'blacklist {' | Select-Object -ExpandProperty LineNumber)]
							$blacklist_line_e = $outItems_array[($outItems_array | Select-String -Pattern 'blacklist {' | Select-Object -ExpandProperty LineNumber)+1]
							$blacklist_data  = ($multipathconf[($blacklist_line_b-1) .. ($blacklist_line_e -1)]).trim()

							# Multipath blacklist Parameters Section
							ValidateAttrinuteInMpio -Mpio_Section $blacklist_data -Parameter_name "devnode" -Parameter_value_array $devnode_param
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
							
							# Multipath devices Parameters Section, Run over loop until we find the vendor "KMNRIO"
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
									if(!($vendor -match $vendor_param[0])) {
										WarningMessage "Device vendor value is not set to - $($vendor_param[1]), but to - $($vendor), skipping this device"
									}
									else {
										GoodMessage "Device vendor $($vendor_param[1]) is properly configured according to Silk's BP, continue with other properties"

										# Multipath device Parameters Section
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "product" -Parameter_value_array $product_param
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "path_grouping_policy" -Parameter_value_array $path_grouping_policy_param
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "path_checker" -Parameter_value_array $path_checker_param
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "no_path_retry" -Parameter_value_array $no_path_retry_param
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "hardware_handler" -Parameter_value_array $hardware_handler_param
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "rr_weight" -Parameter_value_array $rr_weight_param
										ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "rr_min_io" -Parameter_value_array $rr_min_io_param
										
										# Define BP parameters for MPIO (multipath.conf) and scheduler (62-io-schedulers.rules) according to the OS type
										switch -Wildcard ($linuxtype) {
											'rhel*' {
												switch ($linuxtype) {
													#Rhel 7 params
													rhel7 {
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "path_selector" -Parameter_value_array $path_selector_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "failback" -Parameter_value_array $failback_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "fast_io_fail_tmo" -Parameter_value_array $fast_io_fail_tmo_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "dev_loss_tmo" -Parameter_value_array $dev_loss_tmo_param
													}
													#Rhel 6 params
													rhel6 {
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "getuid_callout" -Parameter_value_array $getuid_callout_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "failback" -Parameter_value_array $failback_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "fast_io_fail_tmo" -Parameter_value_array $fast_io_fail_tmo_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "dev_loss_tmo" -Parameter_value_array $dev_loss_tmo_param
													}
													#Rhel 5 params
													rhel5 {
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "getuid_callout" -Parameter_value_array $getuid_callout_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "path_selector" -Parameter_value_array $path_selector_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "failback" -Parameter_value_array $failback_param
													}
												}
											}
											'debian*' {
												switch ($linuxtype) {
													#debian 6 params
													debian6 {
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "getuid_callout" -Parameter_value_array $getuid_callout_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "path_selector" -Parameter_value_array $path_selector_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "failback" -Parameter_value_array $failback_param	
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "fast_io_fail_tmo" -Parameter_value_array $fast_io_fail_tmo_param	
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "dev_loss_tmo" -Parameter_value_array $dev_loss_tmo_param	
													}
													#debian 7 params 
													debian7 {
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "path_selector" -Parameter_value_array $path_selector_param
														ValidateAttrinuteInMpio -Mpio_Section $device -Parameter_name "failback" -Parameter_value_array $failback_param
													}
												}
											}
										}
									}
								}
								else { 
									BadMessage "multipath.conf - Device $($i+1) is missing vendor, skipping this device"
								}
							}	
						}
					}
					else {
						BadMessage "multipath.conf not found on /etc/multipath.conf"
					}

					$MessageCounter++
					PrintDelimiter

					InfoMessage "$MessageCounter - Running the Validator for UDEV IO schedulers.rules configuration"

					# Variables that need to be caheck 
					$ID_SERIAL_scheduler_param      = '\"noop"' , "noop"
					$DM_UUID_scheduler_param        = '\"noop"' , "noop"

					switch -Wildcard ($linuxtype) {
						'rhel*' {
							#IO-schdulre-params_rhel
							$ID_SERIAL_max_sectors_kb_param = '\"1024"' , "1024"
							$DM_UUID_max_sectors_kb_param   = '\"1024"' , "1024"
						}
						'debian*' {
							#IO-schdulre-params_debian							
							$ID_SERIAL_max_sectors_kb_param = '\"4096"' , "4096"
							$DM_UUID_max_sectors_kb_param   = '\"4096"' , "4096"
						}
					}				

					# Path file variable 
					[string]$IOschedulersPath = "/etc/udev/rules.d/62-io-schedulers.rules"

					# Get multipath.conf file from server 
					$command = "test -f $($IOschedulersPath) && echo true || echo false"
					if($bLocalServer) {
						$ioschedulersfileexists = Invoke-Expression $command
					}
					else {
						$ioschedulersfileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					
					if($ioschedulersfileexists -match "true") {
						$command = "cat $($IOschedulersPath)"
						if($bLocalServer) {
							$ioschedulers = Invoke-Expression $command
						}
						else {
							$ioschedulers = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						# 	Write the udev rules into the HTML file
						InfoMessage "File - $($IOschedulersPath) - Content:"
						handle_string_array_messages ($ioschedulers |out-string).trim() "Data"

						# Cleanup empty spaces and rows
						$ioschedulers = $ioschedulers.Trim() | where-object {$_}

						# Get only the relavant rows
						$ioschedulers = $ioschedulers -match "20024f400*"

						# ValidateAttrinuteInIoschedulers for each one of the rows.
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "ID_SERIAL}.*queue/scheduler" -Parameter_value_array $ID_SERIAL_scheduler_param
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "ID_SERIAL}.*queue/max_sectors_kb" -Parameter_value_array $ID_SERIAL_max_sectors_kb_param
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "DM_UUID}.*queue/scheduler" -Parameter_value_array $DM_UUID_scheduler_param
						ValidateAttrinuteInIoschedulers -ioschedulers_Section $ioschedulers -Parameter_name "DM_UUID}.*queue/max_sectors_kb" -Parameter_value_array $DM_UUID_max_sectors_kb_param
					}
					else {
						BadMessage "62-io-schedulers.rules not found on $($IOschedulersPath)"
					}

					$MessageCounter++
					PrintDelimiter

					# LINUX TRIM/UNMAP
					InfoMessage "$MessageCounter - Running validation for Linux TRIM/UNmap (fstrim) option"
					
					$command = "cat /etc/fstab | grep -i 'discard'"
					if($bLocalServer) {
						$fstab = Invoke-Expression $command
					}
					else {
						$fstab = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					if($fstab) {
							WarningMessage "Please check if the rows that contain the discard are Silk Devices"
					}
					else {
						InfoMessage "fstab Silk mount file system not contain rows with discard!"
					}

					$MessageCounter++
					PrintDelimiter

					InfoMessage "$MessageCounter - Running validation for noatime option on debian distro OS"

					# Linux Debian Check the noatime Option
					if(($linuxtype) -match ("debian")) {
						$command = "cat /etc/fstab | grep -E '/dev/sda7|/chroot'"
						if($bLocalServer) {
							$fstab = Invoke-Expression $command
						}
						else {
							$fstab = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						if($fstab -match "noatime") {
							if($fstab -match "noatime.*1 2") {
								GoodMessage "noatime value is properly configured according to Silk's BP"
							}
							else {
								BadMessage "fstab Silk mount file system is missing the noatime option"
							}
						}
						else {
							BadMessage "fstab Silk mount file system is missing the noatime option"
						}
					}
					else {
						InfoMessage "Skipping Running validation for noatime option on debian distro OS, OS type is not debian distro"
					}

					$MessageCounter++
					PrintDelimiter

					switch ($systemConnectivitytype) {
						"fc" {
							if($linux_username -ne "root") {
								WarningMessage "$MessageCounter - We don't support the qLogic FC validation with user that it not root user (Locally / Remote)"
							}
							else {
								#validating qlogic
								InfoMessage "$MessageCounter - Running validation for FC QLogic configuration"
								$command = "lspci | grep -i qlogic | grep -i 'Fibre Channel'"
								if($bLocalServer) {
									$qlogic = Invoke-Expression $command
								}
								else {
									$qlogic = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
								}

								if($qlogic) {
									$command = "test -d /opt/QLogic_Corporation/QConvergeConsoleCLI && echo true || echo false"
									if($bLocalServer) {
										$qaucliexists = Invoke-Expression $command
									}
									else {
										$qaucliexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
									}

									if ($qaucliexists -match "true") {
										$command = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -pr fc -g"
										if($bLocalServer) {
											$qaucli_hba = Invoke-Expression $command
										}
										else {
											$qaucli_hba = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
										}

										if($qaucli_hba) {
											# $qaucli_hba = $qaucli_hba | Select-String "HBA Instance" | select-string "Online"| Select-Object -Property @{ Name = 'Row';  Expression = {$_}}, @{ Name = 'HBA_Instance'; Expression = { $_.ToString().split(" ")[-2].Replace(")","")}}
											$qaucli_hba = $qaucli_hba | Select-String "HBA Instance" | Select-Object -Property @{ Name = 'Row';  Expression = {$_}}, `
											@{ Name = 'HBA_Instance'; Expression = { ($_.ToString().split(")")[0].trim().split(" "))[-1]}}, `
											@{ Name = 'HBA_Status'; Expression = { ($_.ToString().split(")"))[1].trim()}}

											foreach($hba in $qaucli_hba) {
												# Check if the link is Online
												if($hba.HBA_Status -eq "Online") {
													InfoMessage "Working on HBA - $($hba.Row.ToString().trim())"

													$command = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -pr fc -c $($hba.HBA_Instance)"
													if($bLocalServer) {
														$qaucli = Invoke-Expression $command
													}
													else {
														$qaucli = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
													}

													# Calling to comman function of QLogic HBA checking
													QLogic_HBA_Settings_Check $qaucli
												}
												else {
													WarningMessage "Skipping  HBA - $($hba.Row.ToString().trim()) becouse is status is not Online, but - $($hba.HBA_Status)"
												}
											}
										}	
										else {
											BadMessage "qlogic quacli command (qaucli -pr fc -g) could not found HBA FC ports"
										}
									}
									else {
										BadMessage "/opt/QLogic_Corporation/QConvergeConsoleCLI folder not found, need it to install and also the qaucli executable"
									}
								}
								else {
									InfoMessage "Skipping FC check since FC HBA of Qlogic not found in lspci"
								}
							}
						}
						"iscsi" {
							InfoMessage "$MessageCounter - iSCSI Configurtion & IQN & Sessions Section"

							# Checking the iscsid.conf file
							Checking_File_Content -FilePath "/etc/iscsi/iscsid.conf" -FileConParameter "node.startup" -FileConSeparator "=" -FileConValue "automatic"

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
								handle_string_array_messages ($iSCSISession_Per_Cnode |out-string).Trim() "Data"
							}
						}
					}

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

					# Verify that the scheduler is configured to noop and to 1024/4096
					InfoMessage "UDEV Rules settings per dm device (If there is)"
					$command1 = 'sudo multipath -ll | grep KMNRIO | awk ''{print $3}'' | sort -n'
					$command  = 'sudo bash -c ''for dm in XXXXX ; do (echo -ne "$dm" - ; echo $(sudo cat /sys/class/block/"$dm"/queue/scheduler; sudo cat /sys/class/block/"$dm"/queue/max_sectors_kb)) ;done | sort -n'''					
					if($bLocalServer) {
						$Device_IO_Rule = ((Invoke-Expression $command1) -join " ").trim()
						$command = $command.replace("XXXXX",$Device_IO_Rule)
						$Device_IO_Rule = Invoke-Expression $command
					}
					else {
						$Device_IO_Rule = ((plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command1) -join " ").trim()
						$command = $command.replace("XXXXX",$Device_IO_Rule)
						$Device_IO_Rule = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}

					# Write it:
					handle_string_array_messages ($Device_IO_Rule |Out-String).Trim() "Data"					
					
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
	Set-Variable -Name systemConnectivitytype -Option AllScope -Scope Script

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
		[string]$HostType               = ""
		[string]$systemConnectivitytype = ""

		#region Script Choice Selection Host Type
		$optionVMWare  = New-Object System.Management.Automation.Host.ChoiceDescription '&VMWare' , 'Host Type: VMWare'
		$optionLinux   = New-Object System.Management.Automation.Host.ChoiceDescription '&Linux'  , 'Host Type: Linux'
		$optionWindows = New-Object System.Management.Automation.Host.ChoiceDescription '&Windows', 'Host Type: Windows'
		$optionExit    = New-Object System.Management.Automation.Host.ChoiceDescription "&Exit"   , "Exit"

		$optionsContainer = [System.Management.Automation.Host.ChoiceDescription[]]($optionVMWare,$optionLinux, $optionWindows,$optionExit)

		$optiontitle    = 'The Silk Best Practices Validator Script'
		$optionmessage  = 'Choose your Host Type'
		$HostTypeResult = $host.ui.PromptForChoice($optiontitle, $optionmessage, $optionsContainer, 3)
		$bExit          = $False

		switch ($HostTypeResult) {
			0 { $HostType = "VMware"  }
			1 { $HostType = "Linux"   }
			2 { $HostType = "Windows" }
			3 { 
				Write-Host "Exiting, Good Bye." -ForegroundColor Yellow
				$bExit    = $True
				$HostType = "Exit"
				start-sleep -seconds 1
			}
		}
		#endregion

		if(-not($bExit)) {
			# Print to the console what the customer choose
			InfoMessage "Customer choose operation system type: $($HostType)"

			#region Script Choice Selection K2 Connectivity (FC / iSCSI)
			$optionfc 	 = New-Object System.Management.Automation.Host.ChoiceDescription '&FC', "Validating settings according to an FC system best practices."
			$optioniscsi = New-Object System.Management.Automation.Host.ChoiceDescription '&ISCSI', "Validating settings according to an iSCSI system best practices."
			$optionExit  = New-Object System.Management.Automation.Host.ChoiceDescription "&Exit"   , "Exit"

			$optionsContainer1 = [System.Management.Automation.Host.ChoiceDescription[]]($optionfc, $optioniscsi,$optionExit)

			$optiontitle        = "System connectivity type"
			$optionmessage      = "What type of SAN connectivity is your system?"
			$ConnectivityResult = $host.ui.PromptForChoice($optiontitle, $optionmessage, $optionsContainer1, 0) 

			switch ($ConnectivityResult)
			{
				0 {$systemConnectivitytype = "FC"}
				1 {$systemConnectivitytype = "ISCSI"}
				2 { 
					Write-Host "Exiting, Good Bye." -ForegroundColor Yellow
					$bExit = $True
					$systemConnectivitytype = "Exit"
					start-sleep -seconds 1
			}
			}
			InfoMessage "Customer choose Connectivity type: $($systemConnectivitytype)"
			#endregion

			# Write console empty row
			write-host

			# Print Delimiter 
			PrintDelimiterServer
			$SDPBPHTMLBody += "<div id='host_space'></div>"
			
			if(-not($bExit)) {
				switch($HostType) {
					#VMware
					"VMware"{
						Write-Host -ForegroundColor Yellow "According to Silk best practices, this script gets vCenter and a Cluster name as inputs, and it validates all ESXi servers.`nThere is also an option to specify just specific servers with the ESXi parameter."
						$vCenter    = read-host "vCenter -Specify the vCenter name to connect to. Can be combined with -ESXHost and/or -Cluster"
						$Cluster    = read-host "Cluster -Specify the ESXi cluster to validate. Requires the -vCenter argument"
						$ESXHost    = read-host "ESXHost -Specify the ESXi host to validate. Can be combined with the -vCenter argument"
						$Credential = $host.ui.PromptForCredential("Silk BP credentials", "Please enter your VMware username and password.", "", "")
						VMware_Validator $vCenter $Cluster $ESXHost $Credential
					}
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
	}

	# Script has complted, Exit the script
	$MessageCurrentObject = "Silk Validator Ending"
	GoodMessage "Done, Good Bye!"
	start-sleep -seconds 4
}
#endregion
##################################### End Main #############################################################################