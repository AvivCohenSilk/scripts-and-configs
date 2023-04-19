<#
    ===========================================================================================================================================
    Release version: 3.0.0.0
    -------------------------------------------------------------------------------------------------------------------------------------------
    Maintained by:  Aviv.Cohen@Silk.US
    Organization:   Silk.us, Inc.
    Filename:       Silk_6_Activator.ps1
    As Known As:    Silk Dot 6 Activator PowerShell Script
    Copyright       (c) 2023 Silk.us, Inc.
    Description:    Activate and align Initiator with Silk Best Practices settings
	Host Types:     Valid for VMware, Windows , Linux environments
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

# Ensure the the minimum version of the PowerShell Validator is 5 and above
#Requires -Version 5

##################################### Silk Validator begin of the script - Activator #####################################
#region Validate Section
# Configure general the SDP Version
[string]$SDP_Version = "3.0.0.0"

# Checking the PS version and Edition
[string]$ActivatorProduct  = "Dot6"
[string]$PSPlatform        = ""
[System.Boolean]$bExitMenu = $false
if($PSVersionTable.PSEdition -eq "Core" ) {
	if ($PSVersionTable.PSVersion.Major -ge 7) {
		# Platform Section - Powershell Core 7 (Win32NT / Unix)
		if(!($Platfrom_Windows)) {Set-Variable Platfrom_Windows -option Constant -Scope Script -value "Win32NT"}
		if(!($Platfrom_Linux)) {Set-Variable Platfrom_Linux -option Constant -Scope Script -value "Unix"}
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
##################################### End Silk Validator begin of the script - Activator #################################

##################################### Global functions #####################################################################
#region PrintDescription
# Functions PrintDescription, print to the customer a short description about the parameter that he need to change.
Function PrintDescription {
	param(
        [parameter(Mandatory)]
        [string] $description
	)

	Write-host ""
	Write-host "---------------------------------------------"
	$host.ui.RawUI.ForegroundColor = "Yellow"
	Write-host "$description"
	$host.ui.RawUI.ForegroundColor = $OrigColor
}
#endregion

#region HTML Variables and Functions
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
Function GenerateHTML
{
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
	Write-Output "#BadMessage {color: red;}" | Out-File -Append $OutputFile
	Write-Output "#GoodMessage {color: limegreen;}" | Out-File -Append $OutputFile
	Write-Output "#InfoMessage {color: magenta;}" | Out-File -Append $OutputFile
	Write-Output "#DataMessage {color: SlateBlue;}" | Out-File -Append $OutputFile
	Write-Output "#WarningMessage {color: yellow;}" | Out-File -Append $OutputFile
	Write-Output "#Headline {color: DodgerBlue;}" | Out-File -Append $OutputFile
	Write-Output "#host_space {font-size: 0; height: 25px; line-height: 0;}" | Out-File -Append $OutputFile
	Write-Output "hr.server {border: 3px solid grey; border-radius: 3px;}" | Out-File -Append $OutputFile
	Write-Output "</style>" | Out-File -Append $OutputFile
	
	# Close the HTML head
	Write-Output "</head><body>" | Out-File -Append $OutputFile
	
	# Create the headline
	Write-Output "<div id='Headline'>Silk Data Platform Activation script running version $($SDP_Version).</div>" | Out-File -Append $OutputFile
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
	$host.ui.RawUI.ForegroundColor = "Magenta"
	Write-Output "Summary report was written into $OutputFile"
	Write-Output "Link - Host Connectivity and Networking Best Practice Guide -  $($BP_Link)"
	$host.ui.RawUI.ForegroundColor = $OrigColor	

	# Opening the file (only on windows)
	if ($PSPlatform -eq $Platfrom_Windows) {
		Invoke-Expression "& '$OutputFile'"
	}
}
#endregion

#region Check Admin User Cross Platform
# CheckAdminUserCrossPlatform Function - Checking the current user in windows and linux env, you must run as administartor (Windows) or root (linux)
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
        [parameter(Mandatory)]
        [string] $title,
        [parameter()]
        [string] $defaultValue
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
#region ESXI Activator as subfunction
function VMware_Activator {
	[cmdletbinding()]
	Param(
		[parameter()][String]$vCenter,
		[parameter()][String]$Cluster,
		[parameter()][String]$ESXHost,
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)
	
	#region PrintUsage
	Function PrintUsage 
	{
		Write-Warning "Validation Error. Available arguments are:"
		Write-Warning "	-vCenter    : Specify the vCenter name to connect to. Can be combined with -ESXHost and/or -Cluster."
		Write-Warning "	-Cluster    : Specify the ESXi cluster to validate. Requires the -vCenter argument."
		Write-Warning "	-ESXHost    : Specify the ESXi host to validate. Can be combined with the -vCenter argument."
		Write-Warning "	-Credential : Specify the Credential user and password to authenticate with."
		Write-Host "`n"
	}
	#endregion

	#region ValidatePowerCLI
	Function ValidatePowerCLI {
		InfoMessage "Validate the PowerCLI version"
		$PowerCLI_Installed = $True
		
		try {
			$VMwareMoudleCount = (Get-Module -ListAvailable VMware.VimAutomation.Core).count
			if($VMwareMoudleCount -eq 0) {
				BadMessage "No VMware Modules found, please check that PowerCLI 6.5+ is installed and then rerun"
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
					BadMessage "The minimum PowerCLI version needed is 6.5+,Please installed and then rerun."
					$PowerCLI_Installed = $False
				}
				
				if(((Get-Module -ListAvailable VMware.VimAutomation.Core ).Version).Major -ge 10) {
					set-PowerCLIConfiguration -invalidCertificateAction "ignore" -confirm:$False | Out-Null
				}
			}
		}
		catch {
			BadMessage "No VMware Modules found or errors during import Powercli modules, please check that PowerCLI 6.5+ is installed and then rerun"
			$PowerCLI_Installed = $False
		}

		if($PowerCLI_Installed) {
			GoodMessage "The PowerCLI version check passed."
		}
		else {
			BadMessage "The PowerCLI version check not passed."			
		}		
		return $PowerCLI_Installed
	}
	#endregion
	
	# We will use the vmhost variable as a dummy to hold the "Initialization" string.
	$MessageCurrentObject = "Activator VMware ESXi"

	# Connection VMware Section
	Try {
		# Validate PowerCLI exists and in use
		if(ValidatePowerCLI) {
			PrintDelimiter

			# PowerCLI Configure general variables 
			Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP $False -Confirm:$False | Out-Null

			# Local VMware variables
			$VMwareConnect   = $null
			$HeadlineMessage = $null

			# finding combination for 3 boolean variables
			[int]$condition = 0
			if (![string]::IsNullOrEmpty($vCenter)) { $condition += 1 }
			if (![string]::IsNullOrEmpty($Cluster)) { $condition += 2 }
			if (![string]::IsNullOrEmpty($ESXHost)) { $condition += 4 }

			switch ($condition) {
				0 {	PrintUsage 
					return}
				1 {	PrintUsage 
					return}
				2 { PrintUsage 
					return}
				3 { 
					$VMwareConnect   = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop | Out-Null
					$HeadlineMessage = "<div id='Headline'>Running Activation for ESXi Cluster `"$($Cluster)`" from vCenter `"$($vCenter)`".</div>"
					$vmhosts         = @(Get-VMHost -Server $vCenter -Location $Cluster)
				}
				4 { 
					$VMwareConnect   = Connect-VIServer -Server $ESXHost -Credential $Credential -ErrorAction Stop | Out-Null
					$HeadlineMessage = "<div id='Headline'>Running Activation for ESXi host `"$($ESXHost)`" Only`".</div>"
					$vmhosts         = @(Get-VMHost -Name $ESXHost)
				}
				5 {
					$VMwareConnect   = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop | Out-Null
					$HeadlineMessage = "<div id='Headline'>Running Activation for ESXi host `"$($ESXHost)`" located in vCenter `"$($vCenter)`".</div>"
					$vmhosts         = @(Get-VMHost -Server $vCenter -Name $ESXHost)
				}
				6 { PrintUsage 
					return}
				7 {
					$VMwareConnect   = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop | Out-Null
					$HeadlineMessage = "<div id='Headline'>Running Activation for ESXi Host `"$($ESXHost)`" located in ESXi Cluster(s) `"$($Cluster)`" from vCenter `"$($vCenter)`".</div>"
					$vmhosts         = @(Get-VMHost -Server $vCenter -Location $Cluster -Name $ESXHost)
				}
				default {
					PrintUsage 
					return}
			}

			InfoMessage "Running Activation for ESXi"
	
			PrintDescription "Category: Performance related.`nParameter type: The Disk.SchedQuantum parameter is a global parameter and may impact other attached storage arrays.`nDescription: The Disk.SchedQuantum parameter defines the maximum number of consecutive commands issued from the same virtual machine, even though there might be I/O from another virtual machine."
			$SchedQuantum=UserSelections "Disk.SchedQuantum" "64" 
			
			PrintDescription "Category: Performance related.`nParameter type: The DiskMaxIOSize setting is a global parameter and may impact other attached storage arrays.`nDescription: The Disk.MaxIO setting is defined by Silk best practices and is set to work optimally with the Silk Data Platform."
			$MaxIO=UserSelections "Disk.DiskMaxIOSize" "1024"

			PrintDescription "Category: Performance related.`nParameter type: From ESXi 5.5 and on the Disk.SchedNumReqOutstanding parameter is set on a per disk basis and has no impact on other attached storage arrays.`nDescription: The Disk.SchedNumReqOutstanding defines the maximum number of outstanding I/O commands for that specific datastore and for all virtual machines on the datastore. This definition is set at the ESXi level and is relative per datastore. If there is a single virtual machine on a datastore, the limit is set by the HBA queue depth limit. The recommended value is 32 across all ESXi versions. `nNOTE: If running ESX 6.5, for this parameter is between 1 and the HBA queue depth."
			$SchedNumReqOutstanding=UserSelections "Disk.SchedNumReqOutstanding"
				
			if($systemConnectivitytype-eq "fc") {
				PrintDescription "Category: Performance related.`nParameter type: The HBA settings are global parameters and may impact other attached storage arrays.`nDescription: The HBA settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
				$Qlogic = UserSelections "Qlogic" "ql2xintrdelaytimer=1 ql2xoperationmode=6 ql2xmaxqdepth=256"
			}

			PrintDescription "Category: Performance related.`nParameter type: VAAI settings are global parameters and may impact other attached storage arrays.`nDescription: vStorage APIs for Array Integration (VAAI), is a VMware API that enables storage vendors to better integrate with vSphere and to offload storage related tasks to the storage array."
			$VAAI=UserSelections "VAAI" 

			PrintDescription "Category: Performance related. High Availability related.`nParameter type: The Round-Robin settings are set on a per disk basis thus are specific to Silk Data Platform and has no impact on other attached storage arrays.`nDescription: Setting Silk Data Platform devices with Round-Robin path policy allows better utilization of the infrastructure and allows better peformance and availability. In addition, setting the CommandsToSwitchPath=2 allows better use of the Silk Data Platform sub 1ms latency and to enjoy maximum performance."
			$RoundRobin=UserSelections "Round Robin" "MultipathPolicy=RoundRobin and CommandsToSwitchPath=2"

			PrintDescription "Category: High Availability related.`nParameter type: The SATP rule addition is unique to the Silk Data Platform and has no impact on other attached storage arrays.`nDescription: Setting the Silk Data Platform SATP rule allows automatic configuration of path policy for future attached Data Platform drives to the ESXi host. Among other things, this will set the IO limit/path change to 2. For Windows Clustered environments, this parameter is highly recommended."
			$SATP=UserSelections "SATP"
			
			PrintDescription "Category: Capacity management related.`nParameter type: From ESXi 6*, enable block delete setting is a global parameter and may impact other attached storage arrays.`nDescription: Enable VMFS block delete when UNMAP is issued from guest OS allows to reclaim space from within the guest OS"
			$EnableBlockDelete=UserSelections "VMFS3.EnableBlockDelete" "1"

			PrintDescription "Category: Performance related.`nParameter type: The CBRC parameter is a global parameter and may impact other attached storage arrays.`nDescription: VMware's Content-Based Read Cache (CBRC) technology is a self-cache mechanism intended to offload read I/Os from the storage array and to minimize latency for common read requests. Enabling this feature is a recommended option. If enabled, the recommended DCacheMemReserved parameter is 2048."
			$CBRC=UserSelections "CBRC"
			
			if($CBRC) {
				$CBRCCache=UserSelections "CBRC DCacheMemReserved" "2048"
			}

			# Start activation process , Runover the vmhosts list.
			foreach ($vmhost in ($vmhosts | Sort-Object Name)) {
				
				# Reseting the counter message sections
				[int]$MessageCounter = 1
				
				$MessageCurrentObject = $vmhost
				InfoMessage "Start Processing host $($MessageCurrentObject)"
				
				# Only perform these actions on hosts are available
				If ((Get-VMhost -Name $vmhost.Name).ConnectionState -eq "NotResponding") {
					WarningMessage "ESXi host - $($vmhost.Name) Connection State is Not Responding, Skipping this host"

					# add a spacer for the HTML output 
					PrintDelimiter
					$SDPBPHTMLBody += "<div id='host_space'></div>"
				}
				else {

					# Get the ESXi version
					$esxVersion = Get-VMHost -Name $vmhost | Select-Object Version,Build
					InfoMessage "$MessageCounter - ESXi version $($esxVersion.Version) build $($esxVersion.Build)"

					$MessageCounter++
					PrintDelimiter

					# Configure Disk.SchedQuantum
					# ===========================
					if ($SchedQuantum) {
						InfoMessage "$MessageCounter - Running Activation for Disk.SchedQuantum"
						$SchedQuantum_Silk_BP_Value = 64
						$SchedQuantum = $vmhost | Get-AdvancedSetting -Name Disk.SchedQuantum

						if ($SchedQuantum.Value -eq $SchedQuantum_Silk_BP_Value) {
							GoodMessage "Disk.SchedQuantum is properly configured according to Silk's BP (Disk.SchedQuantum=$($SchedQuantum_Silk_BP_Value))"
						} 
						else {
							InfoMessage "Configuring Disk.SchedQuantum to $($SchedQuantum_Silk_BP_Value) starting..."
							$SchedQuantum | Set-AdvancedSetting -Value $SchedQuantum_Silk_BP_Value -Confirm:$false | Out-Null
							GoodMessage "Configured Disk.SchedQuantum to $($SchedQuantum_Silk_BP_Value) completed"
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware Disk.SchedQuantum configuration"
					}
					
					$MessageCounter++
					PrintDelimiter

					# Configure Disk.DiskMaxIOSize
					# ============================
					if ($MaxIO) {
						InfoMessage "$MessageCounter - Running Activation for Disk.DiskMaxIOSize"
						$DiskMaxIOSize_Silk_BP_Value = 1024
						$DiskMaxIOSize = $vmhost | Get-AdvancedSetting -Name Disk.DiskMaxIOSize

						if($DiskMaxIOSize.Value -eq $DiskMaxIOSize_Silk_BP_Value) {
							GoodMessage "Disk.DiskMaxIOSize is properly configured according to Silk's BP (Disk.DiskMaxIOSize=$($DiskMaxIOSize_Silk_BP_Value))"
						}
						else {
							InfoMessage "Configuring Disk.DiskMaxIOSize to $($DiskMaxIOSize_Silk_BP_Value)) starting..."
							$DiskMaxIOSize | Set-AdvancedSetting -Value $DiskMaxIOSize_Silk_BP_Value -Confirm:$false | Out-Null
							GoodMessage "Configured Disk.DiskMaxIOSize to $($DiskMaxIOSize_Silk_BP_Value)) completed"
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware Disk.DiskMaxIOSize configuration"
					}

					$MessageCounter++
					PrintDelimiter

					# Configure Disk.SchedNumReqOutstanding
					# =====================================
					if ($SchedNumReqOutstanding) {
						InfoMessage "$MessageCounter - Running activation for Disk.SchedNumReqOutstanding"
						$SchedNumReqOutstandingBP = 32
						
						if ($esxVersion.Version -ge 5.5) {
							InfoMessage "Note - In ESXi version $($esxVersion.Version) the SchedNumReqOutstanding parameter is set per disk."
							$esxcli = Get-EsxCli -VMHost $vmhost -V2
							
							# Query the disk list that the Vendor is KMNRIO and the NoofoutstandingIOswithcompetingworlds not queul to SchedNumReqOutstandingBP (32)
							$K2DiskList = $esxcli.storage.core.device.list.invoke() | Where-Object{$_.Vendor -eq "KMNRIO"} | Where-Object{$_.NoofoutstandingIOswithcompetingworlds -ne $SchedNumReqOutstandingBP} | Select-Object Device,Vendor,NoofoutstandingIOswithcompetingworlds
							
							if($K2DiskList) {
								try {
									# Run over the K2 disks
									foreach ($K2Disk in $K2DiskList) {
										$arguments                        = $esxcli.storage.core.device.set.CreateArgs()
										$arguments.device                 = $K2Disk.Device
										$arguments.schednumreqoutstanding = $SchedNumReqOutstandingBP
										$esxcli.storage.core.device.set.invoke($arguments) | Out-Null
										GoodMessage "Setting Device $($K2Disk.Device) to NoofoutstandingIOswithcompetingworlds=$($SchedNumReqOutstandingBP)"
									}
								}
								catch {
									BadMessage "Unable to set DSNRO for device $($K2Disk.Device). Please check HBA Queue Depth values and rerun again. Skipping..."
								}
							}
							else {
								InfoMessage "Could not found disks that the Vendor is KMNRIO and the NoofoutstandingIOswithcompetingworlds not queul to $($SchedNumReqOutstandingBP)"
							}
						}
						else {
							InfoMessage "Note - In ESXi version $($esxVersion.Version) the Disk.SchedNumReqOutstanding parameter is a global parameter."
							$OldSchedNumReqOutstanding =  $vmhost | Get-AdvancedSetting -Name Disk.SchedNumReqOutstanding
							if ($OldSchedNumReqOutstanding.Value -eq $SchedNumReqOutstandingBP) {
								GoodMessage "Parameter Disk.SchedNumReqOutstanding value is $($SchedNumReqOutstandingBP)) and is properly configured according to Silk's BP"
							}
							else {
								InfoMessage "Parameter Disk.SchedNumReqOutstanding value is not $($SchedNumReqOutstandingBP)) is not properly configured according to Silk's BP"
								$OldSchedNumReqOutstanding | Set-AdvancedSetting -Value $SchedNumReqOutstandingBP -Confirm:$false | Out-Null
								GoodMessage "Parameter Disk.SchedNumReqOutstanding was set to $($SchedNumReqOutstandingBP))"
							}
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware Disk.SchedNumReqOutstanding configuration"
					}

					$MessageCounter++
					PrintDelimiter

					# Configure Qlogic
					# ================
					if ($systemConnectivitytype -eq "fc") {
						InfoMessage "$MessageCounter - Running activation for FC settings"
						if ($Qlogic) {
							InfoMessage "Running activation for Qlogic settings"
							$QlogicModuleData = $vmhost | Get-VMHostModule -Name "ql*" -ErrorAction SilentlyContinue
							
							if ($QlogicModuleData) {
								$HBA_ql2xmaxqdepth = 256
								$QlogicOptions     = $QlogicModuleData | Select-Object Options
								
								if (($QlogicOptions.Options -notlike "*ql2xoperationmode=6*") -Or ($QlogicOptions.Options -notlike "*ql2xintrdelaytimer=1*") -Or ($QlogicOptions.Options -notlike "*ql2xmaxqdepth=$($HBA_ql2xmaxqdepth)*")) {
									InfoMessage "Configuring Qlogic Settings (ql2xintrdelaytimer=1 ql2xoperationmode=6 ql2xmaxqdepth=$($HBA_ql2xmaxqdepth)) starting..." 
									$QlogicModuleData | Set-VMHostModule -Options "ql2xintrdelaytimer=1 ql2xoperationmode=6 ql2xmaxqdepth=$($HBA_ql2xmaxqdepth)" -Confirm:$false | Out-Null
									GoodMessage "Qlogic configured with Silk best practices (ql2xintrdelaytimer=1 ql2xoperationmode=6 ql2xmaxqdepth=$($HBA_ql2xmaxqdepth)) completed. REBOOT required!"
								} 
								else {
									GoodMessage "Qlogic Options are properly configured according to Silk's BP $($QlogicOptions.options)"
								}
							} 
							else {
								BadMessage "Could not find Qlogic module. Perhaps adapter is not Qlogic branded?"
							}
						}
						else {
							InfoMessage "Skipping Qlogic configuration"
						}
					}
					else {
						InfoMessage "$MessageCounter - Connectivity Type is iSCSI and not FC, Skipping..."
					}
					
					$MessageCounter++
					PrintDelimiter

					# Configure VAAI
					# ==============
					if ($VAAI) {
						InfoMessage "$MessageCounter - Running activation for VAAI Primitives"
						$HardwareAcceleratedMove    = $vmhost | Get-AdvancedSetting -Name DataMover.HardwareAcceleratedMove
						$HardwareAcceleratedInit    = $vmhost | Get-AdvancedSetting -Name DataMover.HardwareAcceleratedInit
						$HardwareAcceleratedLocking = $vmhost | Get-AdvancedSetting -Name VMFS3.HardwareAcceleratedLocking
						
						if ($HardwareAcceleratedMove.Value -ne 1) {
							InfoMessage "Setting VAAI Primitive DataMover.HardwareAcceleratedMove=1 starting..."
							$HardwareAcceleratedMove | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-Null
							GoodMessage "Setting VAAI Primitive DataMover.HardwareAcceleratedMove=1 completed"
						}
						else {
							GoodMessage "Skipping VAAI Primitive DataMover.HardwareAcceleratedMove, Value is properly configured according to Silk's BP"
						}

						if ($HardwareAcceleratedInit.Value -ne 1) {
							InfoMessage "Setting VAAI Primitive DataMover.HardwareAcceleratedInit=1 starting..."
							$HardwareAcceleratedInit | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-Null
							GoodMessage "Setting VAAI Primitive DataMover.HardwareAcceleratedInit=1 completed"
						}
						else {
							GoodMessage "Skipping VAAI Primitive DataMover.HardwareAcceleratedInit, Value is properly configured according to Silk's BP"
						}

						if ($HardwareAcceleratedLocking.Value -ne 1) {
							InfoMessage "Setting VAAI Primitive VMFS3.HardwareAcceleratedLocking=1 starting..."
							$HardwareAcceleratedLocking | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-Null
							GoodMessage "Setting VAAI Primitive VMFS3.HardwareAcceleratedLocking=1 completed"
						}
						else {
							GoodMessage "Skipping VAAI Primitive VMFS3.HardwareAcceleratedLocking, Value is properly configured according to Silk's BP"
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware VAAI configuration"
					}
					
					$MessageCounter++
					PrintDelimiter

					# Confiugre Round Robin for pre-allocated SDP volumes
					# ====================================================
					if ($RoundRobin) {
						InfoMessage "$MessageCounter - Running activation for Round-Robin (Multipath configuration)"

						# Varibales
						$CommandsToSwitchPath_Silk_BP = 2

						InfoMessage "Setting Silk volumes to MultipathPolicy=RoundRobin and CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP)." 
						InfoMessage "Please wait. This operation may take a couple of minutes..."
						$K2DiskList = $vmhost | Get-ScsiLun -LunType "disk" | Where-Object {$_.Vendor -eq "KMNRIO"}

						foreach ($K2Disk in $K2DiskList) {
							if (($K2Disk.MultipathPolicy -ne "RoundRobin") -and ($K2Disk.CommandsToSwitchPath -ne $CommandsToSwitchPath_Silk_BP)) {
								InfoMessage "Setting device $($K2Disk.CanonicalName) with MultipathPolicy=RoundRobin and CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP) starting..."
								$K2Disk | Set-ScsiLun -MultipathPolicy RoundRobin -CommandsToSwitchPath $($CommandsToSwitchPath_Silk_BP) -Confirm:$false | Out-Null
								GoodMessage "Setting device $($K2Disk.CanonicalName) with MultipathPolicy=RoundRobin and CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP) completed"
							}
							elseif (($K2Disk.MultipathPolicy -ne "RoundRobin") -and ($K2Disk.CommandsToSwitchPath -eq $CommandsToSwitchPath_Silk_BP)) {
								InfoMessage "Device $($K2Disk.CanonicalName) is already set with CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP), Setting MultipathPolicy=RoundRobin starting..."
								$K2Disk | Set-ScsiLun -MultipathPolicy RoundRobin -Confirm:$false | Out-Null
								GoodMessage "Device $($K2Disk.CanonicalName) is already set with CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP), Setting MultipathPolicy=RoundRobin completed"
							} 
							elseif (($K2Disk.MultipathPolicy -eq "RoundRobin") -and ($K2Disk.CommandsToSwitchPath -ne $CommandsToSwitchPath_Silk_BP)) {
								InfoMessage "Device $($K2Disk.CanonicalName) is already set with MultipathPolicy=RoundRobin. Setting CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP) starting..."
								$K2Disk | Set-ScsiLun -CommandsToSwitchPath $($CommandsToSwitchPath_Silk_BP) -Confirm:$false | Out-Null
								GoodMessage "Device $($K2Disk.CanonicalName) is already set with MultipathPolicy=RoundRobin. Setting CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP) completed"
							} 
							else  {
								GoodMessage  "Device $($K2Disk.CanonicalName) is already configured according to Silk best practices (MultipathPolicy=RoundRobin and CommandsToSwitchPath=$($CommandsToSwitchPath_Silk_BP)))."
							}
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware RoundRobin configuration"
					}

					$MessageCounter++
					PrintDelimiter

					# Configure SATP rule
					# ===================
					if ($SATP) {
						InfoMessage "$MessageCounter - Running activation for SATP"
						$esxcli = Get-EsxCli -VMHost $vmhost -V2
						$SATP_Values = $esxcli.storage.nmp.satp.rule.list.invoke() | Where-Object {($_.Vendor -eq "KMNRIO") -and ($_.Model -eq "K2")}
						
						#Checking if it's NULL if not we delete the current one according to the parameters and recreate it.
						if($SATP_Values) {
							$sRule = @{
								claimoption = $SATP_Values.ClaimOptions
								psp         = $SATP_Values.DefaultPSP
								description = $SATP_Values.Description
								model       = $SATP_Values.Model
								satp        = $SATP_Values.Name
								pspoption   = $SATP_Values.PSPOptions
								vendor      = $SATP_Values.vendor
								}
								$esxcli.storage.nmp.satp.rule.remove.Invoke($sRule) | Out-Null
						}
						
						# Create the new SATP rule+
						$esxcli    = Get-EsxCli -VMHost $vmhost -V2
						$arguments = $esxcli.storage.nmp.satp.rule.add.CreateArgs()
						$arguments.pspoption   = "iops=2"						
						$arguments.description = "Kaminario K2 Active/Active"
						$arguments.vendor      = "KMNRIO"
						$arguments.satp        = "VMW_SATP_DEFAULT_AA"
						$arguments.claimoption = "tpgs_off"
						$arguments.psp         = "VMW_PSP_RR"
						$arguments.model       = "K2"
						$arguments.force       = $true
						$esxcli.storage.nmp.satp.rule.add.invoke($arguments) | Out-Null

						GoodMessage "Setting SATP rule completed"
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware SATP configuration"
					}

					$MessageCounter++
					PrintDelimiter
					
					#Enable Block Delete
					# ==================
					if ($EnableBlockDelete) {
						InfoMessage "$MessageCounter - Running activation for EnableBlockDelete"
						if ($esxVersion.Version -ge 6) {
							$EnableBlockDelete = $vmhost | Get-AdvancedSetting -Name VMFS3.EnableBlockDelete
							if ($EnableBlockDelete.Value -eq 1) {
								GoodMessage "EnableBlockDelete setting is enabled, skipping..."
							}
							else {
								InfoMessage "Enabling Block Delete starting..."
								$EnableBlockDelete | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-Null
								GoodMessage "Enabled the setting for EnableBlockDisk completed"
							}
						}
						else {
							InfoMessage "enabling block delete feature is supported only on ESXi 6 and above, current host version is $($esxVersion.Version), skipping..."
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware EnableBlockDelete configuration"
					}

					$MessageCounter++
					PrintDelimiter
				
					# Configure CBRC and cache size
					# =============================
					if ($CBRC) {
						InfoMessage "$MessageCounter - Running activation for CBRC"
						$CBRCEnable = $vmhost | Get-AdvancedSetting -Name CBRC.Enable
						if ($CBRCEnable.Value -like "True") {
							GoodMessage "CBRC is already Enabled."
						}
						else {
							InfoMessage "Enabling CBRC..."
							$CBRCEnable | Set-AdvancedSetting -Value:$true -Confirm:$false | Out-Null
							GoodMessage "CBRC enabled..."
						}
						
						if ($CBRCCache) {
							$CBRCCache_Silk_BP_Value = 2048
							$CRBC_DCacheMemReserved = get-vmhost -name $vmhost | Get-AdvancedSetting -Name CBRC.DCacheMemReserved

							InfoMessage "Checking CBRC DCacheMemReserved size."
							if ($CRBC_DCacheMemReserved.Value -eq $CBRCCache_Silk_BP_Value) {
								GoodMessage "CBRC DCacheMemReserved is already set."
							}
							else {
								InfoMessage "Setting CBRC DCacheMemReserved to $($CBRCCache_Silk_BP_Value) starting..."
								$CRBC_DCacheMemReserved | Set-AdvancedSetting -Value $CBRCCache_Silk_BP_Value -Confirm:$false | Out-Null
								GoodMessage "CBRC DCacheMemReserved has been set to $($CBRCCache_Silk_BP_Value) completed."
							}
						}
						else {
							IfoMessage "Skipping VMware CBRC cache configuration"
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping VMware CBRC configuration"
					}
				}

				InfoMessage "Validation for $($vmhost) completed."
				
				# add a spacer for the HTML output 
				PrintDelimiter
				$SDPBPHTMLBody += "<div id='host_space'></div>"
			}
		}
	}
	catch {
		# Get the exception messages
		$ExceptionMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		BadMessage "Caught exception during VMware Activator at line: $($line)"
		BadMessage $ExceptionMessage
	}
	Finally {
		# Once all data is collected - output into HTML
		$MessageCurrentObject = "Finished Activation`n"

		PrintDelimiterServer

		if($VMwareConnect) {
			if($VMwareConnect.IsConnected) {
				Disconnect-VIServer -Server $global:DefaultVIServers -Confirm:$False -Force -ErrorAction SilentlyContinue
				InfoMessage "Disconnected from VM $($VMwareConnect.Name)"
			} 
			else {
				InfoMessage "$($VMwareConnect.Name) is not connect, nothing to Disconnect"
			}
		}
	}
}
#endregion

#region Windows_Activator
#Windows Activator as subfunction
function Windows_Activator {
	[cmdletbinding()]
	Param(
		[parameter()][String[]]$WinServerArray,
		[System.Management.Automation.PSCredential]	
		$Credential = [System.Management.Automation.PSCredential]::Empty
		)
	
	
	#region RemoteServerDiskInfo	
	Function RemoteServerDiskInfo {
		param (
			[parameter()]$pssessions_local,
			[parameter()]$cimsession_local
			)

		# Get all disks and their associated physical disks by SerialNumber (using with CimSession for local and remote servers)
		$SilkFriendlyNames = @("KMNRIO K2","SILK K2","SILK SDP")
		$disks = invoke-Command -Session $pssessions_local -ArgumentList $SilkFriendlyNames -ScriptBlock {param($arr) Get-Disk | Where-Object {
			$diskName = $_.FriendlyName
			$arr | ForEach-Object {
				$pattern = [regex]::Escape($_)
				if ($diskName -match $pattern) {
					return $true
				}
			}
		} | Select-Object SerialNumber,Number, FriendlyName, LoadBalancePolicy, OperationalStatus, HealthStatus, Size, PartitionStyle}
		$physicalDisks     = invoke-Command -Session $pssessions_local -ScriptBlock {Get-PhysicalDisk}

		# Create an empty array to store the combined data
		$server_diskInfo = @()

		# Loop through each disk and find its associated physical disk by SerialNumber,
		# Foreach disk we find the PhysicalDiskStorageNodeView and Partition (if exist)
		foreach ($disk in $disks) {
			$serialNumber = $disk.SerialNumber
			$physicalDisk = $physicalDisks | Where-Object { $_.SerialNumber -eq $serialNumber }
			$PhysicalDiskStorageNodeView = get-PhysicalDiskStorageNodeView -CimSession $cimsession_local -PhysicalDisk $physicalDisk
			$disknumber   = $null
			$disknumber   = $disk.Number
			
			if($disknumber)	{
				$partitions  = Get-Partition -CimSession $cimsession_local -DiskNumber $disknumber -ErrorAction SilentlyContinue
				$partition   = $partitions | Where-Object {$_.AccessPaths -ne $null}
				$driveLetter = $null
				
				if ($partition) {
					$driveLetter = $partition.DriveLetter -join ","
				}
			}
			
			$combinedDisk = [PSCustomObject]@{
				DeviceId     = $physicalDisk.DeviceId
				DiskNumber   = $disknumber
				SerialNumber = $serialNumber
				FriendlyName = $disk.FriendlyName
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
	# We will use the vmhost variable as a dummy to hold the "Initialization" string.
	$MessageCurrentObject = "Windows Activation"
	InfoMessage "Activation Windows Server"

	# Function Local variables
	[Boolean]$bool_local_user = $false

	# Write the user name to the HTMl
	if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
		InfoMessage "Using $($Credential.UserName) login user for Windows Validator"
	}
	else {
		InfoMessage "using $(whoami) Login user for Windows Validator"
	}
	
	PrintDelimiterServer

	#connect with remote session to a windows the server 
	Try {
		# ERROR: User selected server only with no username or password
		if ([string]::IsNullOrEmpty($WinServerArray)) {
			
			# If we enter here, this is mean that the server array contain only one server and it's locally.
			InfoMessage "No server/s was Specified, running locally: $($env:COMPUTERNAME) with local user $(whoami)"
			$WinServerArray = $env:COMPUTERNAME

			# Local Server using local user.
			$bool_local_user = $True
		}
		
		# Write the headline messages into HTML report
		$HeadlineMessage
		$HeadlineMessage = "<div id='Headline'>Running Activator for Windows host(s) `"$($WinServerArray)`".</div>"

		foreach ($WinServer in $WinServerArray)	{
			PrintDelimiter
			
			# Trim the server name
			$WinServer = $WinServer.Trim()
			
			# initialization Windows Server for Messages Function
			$MessageCurrentObject = $WinServer
			
			# Reboot checking boolean parameter
			[boolean]$bNeedReboot = $false
			
			# Check that we can pinh to the remote server
			if (-not (Test-Connection -ComputerName $WinServer -Count 2 -Quiet)) {
				WarningMessage "The Windows Server $($WinServer) not responding to ping, skipping this server."
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
				# Check if we were able to connect via PSSession or CimSession
				if ([string]::IsNullOrEmpty($pssessions)) {
					$script:NumOfUnreachableHosts += 1
					WarningMessage "The windows Server $($WinServer) New-PSSession not able to establish (Check the WinRM in the remote server), skipping this server..."
					
				}
				elseif ([string]::IsNullOrEmpty($CIMsession)) { 
					$script:NumOfUnreachableHosts += 1
					WarningMessage "The windows Server $($WinServer) New-CimSession not able to establish (Check the WinRM in the remote server), skipping this server..."
				}
				else {

					# Reseting the counter message sections
					[int]$MessageCounter = 1

					# Global Windows Parameters
					$Qlogic                = $false
					$ISCSI_Service         = $false
					$ISCSI_Network_Adapter = $false

					# FC / iSCSI Section
					if($systemConnectivitytype -eq "FC") {
						PrintDescription "Category: Performance related.`nParameter type: The HBA settings are global parameters and may impact other attached storage arrays.`nDescription: The HBA settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
						$Qlogic = UserSelections "Qlogic" "Operation Mode=6 | Interrupt Delay Timer=1 | Execution Throttle=400"
					}
					else {
						PrintDescription "Category: SAN Connectivity related.`nParameter type: The ISCSI settings are global parameters and may impact other attached storage arrays.`nDescription: The ISCSI settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
						$ISCSI_Service = UserSelections "ISCSI" "Configuring iSCSI services"
						$ISCSI_Network_Adapter = UserSelections "ISCSI" "Configuring iSCSI network Adapter"
					}

					# MPIO Section
					PrintDescription "Category: Multipath Microsoft DSM Connectivity related, High Availability related.`nParameter type: The MPIO framework settings are global parameters and may impact other attached storage arrays.`nDescription: The MPIO framework settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
					$MPIO_Installation = UserSelections "MPIO " "Installing Multipath-IO"
					$MPIO_Configuration = UserSelections "MPIO Configuration" "configure MPIO parameters"
					
					# Settings LQD Silk Disk
					PrintDescription "Category: Multipath Microsoft DSM Connectivity related, High Availability related.`nParameter type: Disk Load Balance Policy Settings.`nDescription: Setting the Silk Disks Load Balance Policy to Least Queue Depth (LQD)" 
					$MPIO_LoadBalancePolicy = UserSelections "MPIO " "Disk Load Balance Policy (LQD)"

					# Settings CTRL Silk Disk OFFLINE
					PrintDescription "Category: SAN Connectivity related.`nParameter type: CTRL LU disk XXXX0000 Settings.`nDescription: Setting the CTRL Silk Disk Offline to avoid LU resets" 
					$CTRL_LU_Offline = UserSelections "Management Lugical Unit" "CTRL Silk Disk"

					# Windows TRIM/Unmap
					PrintDescription "Category: Performance related.`nParameter type: TRIM / UNmap Disablie Disable Delete Notification.`nDescription: The TRIM functionality within Windows is controlled by a registry setting. By default, the setting is enabled which effectively enables auto-unmap."
					$WinTrimUnmapRegistry = UserSelections "Trim / UNmap" "Disable Delete Notification Key"				

					# Defragmentation Scheduled Task
					PrintDescription "Category: Performance related.`nParameter type: Disablie Disk Defragmentation Scheduled Task.`nDescription: In a Windows, Hyperv and even Windows server run as a virtual Machine on ESX environments, it is recommended to Disable Disk Fragmentation Scheduled Task (ScheduledDefrag) to avoid performance issues"
					$Defragmentation = UserSelections "Defragmentation" "Disable Scheduled Task"

					# Configure FC / ISCSI Settings
					if($systemConnectivitytype -eq "FC") {
						if($Qlogic)	{
							InfoMessage "$MessageCounter - Running activation for FC Qlogic service"
							# Find location of the qLogic installation
							$QConvergeCliLocation  = (invoke-Command -Session $pssessions -ScriptBlock {(get-command qaucli.exe).source})

							if(!$QConvergeCliLocation) {
								BadMessage "qconvergeconsole cli (qaucli.exe) tool is not installed, qaucli is mandatory (and found on system path) for extracting the QLogic parameters"
							}
							else {
								$qauclioutput_hba = (invoke-Command -Session $pssessions -Args $QConvergeCliLocation -ScriptBlock {Invoke-Expression "& '$args' -pr fc -g"})
								$qauclioutput_hba = $qauclioutput_hba | Select-String "HBA Instance" | select-string "Online"| Select-Object -Property @{ Name = 'Row';  Expression = {$_}}, @{ Name = 'HBA_Instance'; Expression = { $_.ToString().split(" ")[-2].Replace(")","")}}
								
								$HBA_Online_Array = @()
								foreach($qauclioutput_hba_item in $qauclioutput_hba)
								{
									$obj = New-Object -TypeName PSObject
									$obj | Add-Member -MemberType NoteProperty -Name Row -Value $qauclioutput_hba_item.Row.ToString().Trim()
									$obj | Add-Member -MemberType NoteProperty -Name HBA_Instance -Value $qauclioutput_hba_item.HBA_Instance
									$HBA_Settings = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$qauclioutput_hba_item.HBA_Instance -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -c '$a2'"}) | Select-String "^Operation Mode|^Interrupt Delay Timer|^Execution Throttle"
									$HBA_Settings_Operation_Mode        = ($HBA_Settings -match "^Operation Mode").line.split(":")[1].trim()
									$HBA_Settings_Interrupt_Delay_Timer = ($HBA_Settings -match "^Interrupt Delay Timer").line.split(":")[1].trim()
									$HBA_Settings_Execution_Throttle    = ($HBA_Settings -match "^Execution Throttle").line.split(":")[1].trim()
									$obj | Add-Member -MemberType NoteProperty -Name Operation_Mode -value $HBA_Settings_Operation_Mode
									$obj | Add-Member -MemberType NoteProperty -Name Interrupt_Delay_Timer -value $HBA_Settings_Interrupt_Delay_Timer
									$obj | Add-Member -MemberType NoteProperty -Name Execution_Throttle -value $HBA_Settings_Execution_Throttle
											
									$HBA_Online_Array += $obj
								}
								
								# Print to the HTML report all Online reports
								handle_string_array_messages ($HBA_Online_Array | Format-Table * -AutoSize | Out-String).trim() "Data"

								# Show to the customer only HBA that need to be change
								$HBA_Online_Array_Change = $null
								$HBA_Online_Array_Change = $HBA_Online_Array | Where-Object {($_.Operation_Mode -ne "6 - Interrupt when Interrupt Delay Timer expires") -or ($_.Interrupt_Delay_Timer -ne 1) -or ($_.Execution_Throttle -ne 400)} 
								if($HBA_Online_Array_Change) {
									$HBA_Online_Array_Change | Format-Table * -autosize
									$confirmation = Read-Host "Select specified HBA instance number or select all instances (999)"

									if($confirmation -eq 999) {
										foreach ($HBA_Online_Array_Change_item in $HBA_Online_Array_Change) {
											$temp_HBA_Instance = $HBA_Online_Array_Change_item.HBA_Instance
											$qlogic_hba_OM = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$temp_HBA_Instance -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -n '$a2' OM 6"})
											InfoMessage $qlogic_hba_OM
											$qlogic_hba_ID = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$temp_HBA_Instance -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -n '$a2' ID 1"})
											InfoMessage $qlogic_hba_ID
											$qlogic_hba_ET = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$temp_HBA_Instance -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -n '$a2' ET 400"})
											InfoMessage $qlogic_hba_ET 
											$bNeedReboot = $true
										}
									}
									else {
										$qlogic_hba = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$confirmation -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -c '$a2'"})
										
										while (($qlogic_hba -eq "Unable to locate the specified HBA!") -or ($qlogic_hba -match "Unrecognized"))	{
											WarringMessage "Unable to locate the specified HBA instance!, skipping configuration for QLogic section, try again."
											$confirmation = Read-Host "Select specified HBA instance number"
											$qlogic_hba = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$confirmation -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -c '$a2'"})
										}

										$qlogic_hba_OM = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$confirmation -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -n '$a2' OM 6"})
										InfoMessage $qlogic_hba_OM
										$qlogic_hba_ID = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$confirmation -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -n '$a2' ID 1"})
										InfoMessage $qlogic_hba_ID
										$qlogic_hba_ET = (invoke-Command -Session $pssessions -ArgumentList $QConvergeCliLocation,$confirmation -ScriptBlock {param($a1, $a2) Invoke-Expression "& '$a1' -pr fc -n '$a2' ET 400"})
										InfoMessage $qlogic_hba_ET 
										$bNeedReboot = $true
									}
								}
								else{
									GoodMessage "Skipping Windows Qlogic configuration - All HBA are configured properly as Silk BP"
								}
							}
						}
						else {
							InfoMessage "$MessageCounter - Skipping Windows Qlogic configuration"
						}
					}
					else {
						# Activation iSCSI Service according to BP - NEW
						if($ISCSI_Service) {
							InfoMessage "$MessageCounter - Running activation for iSCSI service"
							# $MSiSCSI = (invoke-Command -Session $pssessions -ScriptBlock {Get-WmiObject -Class Win32_Service -Filter "Name='MSiSCSI'"})
							$MSiSCSI = Get-CimInstance Win32_Service -Filter 'Name = "MSiSCSI"' -CimSession $CIMsession
							
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

						# Configure ISCSI Network Adapter
						if($ISCSI_Network_Adapter) {
							InfoMessage "$MessageCounter - Running activation for iSCSI NIC adapter settings"
							
							#iSCSI network adapter settings 							
							$iscsieth = (Get-IscsiTargetPortal -CimSession $CIMsession).InitiatorPortalAddress | Sort-Object -Unique

							if(!$iscsieth) {
								WarningMessage "Could not find active iSCSI Network Adapters host initiator"
							}
							else {
								
								InfoMessage "Setting iSCSI network Adapters"
								foreach($iscsiadapter in $iscsieth)	{
									# For each ISCSI netork card get his properies
									$iscsinetadapter                 = (Get-NetIPAddress -CimSession $CIMsession -IPAddress $iscsiadapter).InterfaceAlias
									$iscsinetadapteradvancedproperty = get-netadapteradvancedproperty -CimSession $CIMsession -name $iscsinetadapter
									
									$confirmation = Read-Host "configuring iSCSI network Adapter $iscsinetadapter. Are you Sure You Want To Proceed [Yy/Nn] (Default [Nn],This will restart the network card and will cause several disonnects)"
									
									if ($confirmation -match "[yY]") {	
										# Jambo Property section
										$iSCSI_jumbo = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Jumbo"})
										if($iSCSI_jumbo) {
											if ($iSCSI_jumbo.RegistryValue -match "9014") {
												GoodMessage "iSCSI network adapter $iscsinetadapter Jumbo Packet is properly configured according to Silk's BP"
											}
											else { 
												InfoMessage "Setting iSCSI network Adapters $iscsinetadapter to work with Jambo Packets"
												Set-netadapteradvancedproperty -CimSession $CIMsession -name $iscsinetadapter -displayname $($iSCSI_jumbo.DisplayName) -RegistryValue "9014" | Out-Null												
												
												$iscsinetadapteradvancedproperty = get-netadapteradvancedproperty -CimSession $CIMsession -name $iscsinetadapter
												$iSCSI_jumbo = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Jumbo"})
												if ($iSCSI_jumbo.RegistryValue -match "9014") {
													GoodMessage "iSCSI network adapter $iscsinetadapter is set to Jumbo Packet"
												}
												else { 
													BadMessage "Unable to setting iSCSI network adapter $iscsinetadapter to run Jumbo Packets"
												}
											}
										}
										else {
											WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Jambo Property"
										}
										
										# Flow Property section
										$iSCSI_flow = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Flow Control"})
										if($iSCSI_flow) {
											if ($iSCSI_flow.DisplayValue -match "Rx & Tx Enabled") {
												GoodMessage "iSCSI network adapter $iscsinetadapter Flow Control is properly configured according to Silk's BP"
											}
											else { 
												InfoMessage "Enabling Flow Control on iSCSI network Adapters $iscsinetadapter "
												set-NetAdapterAdvancedProperty -CimSession $CIMsession -name $iscsinetadapter -DisplayName $($iSCSI_flow.DisplayName) -DisplayValue  "Rx & Tx Enabled" | Out-Null
												
												$iscsinetadapteradvancedproperty = get-netadapteradvancedproperty -CimSession $CIMsession -name $iscsinetadapter
												$iSCSI_flow = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Flow Control"})
												if ($iSCSI_flow.DisplayValue -match "Rx & Tx Enabled") {
													GoodMessage "Flow Control is enabled iSCSI network adapter $iscsinetadapter"
												}
												else { 
													BadMessage "Couldn't enable Flow Control on iSCSI network adapter $iscsinetadapter"
												}
											}	
										}
										else {
											WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Flow Property"
										}
										
										# duplex Property section
										$iSCSI_duplex = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Speed & Duplex"})
										if($iSCSI_duplex) {
											if ($iSCSI_duplex.DisplayValue -match "10 Gbps Full Duplex") {
												GoodMessage "iSCSI network adapter $iscsinetadapter speed and duplex is properly configured according to Silk's BP"
											}
											else { 
												InfoMessage "Setting iSCSI network Adapters $iscsinetadapter to 10 Gbps Full Duplex"
												set-NetAdapterAdvancedProperty -CimSession $CIMsession -name $iscsinetadapter -DisplayName $($iSCSI_duplex.DisplayName) -DisplayValue  "10 Gbps Full Duplex" | Out-Null
												
												$iscsinetadapteradvancedproperty = get-netadapteradvancedproperty -CimSession $CIMsession -name $iscsinetadapter
												$iSCSI_duplex = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Speed & Duplex"})
												if ($iSCSI_duplex.DisplayValue -match "10 Gbps Full Duplex") {
													GoodMessage "iSCSI network adapter $iscsinetadapter speed and duplex is set to 10 Gbps Full Duplex"
												}
												else { 
													BadMessage "Couldn't set iSCSI network adapter $iscsinetadapter speed and duplex to 10 Gbps full Duplex"
												}
											}
										}
										else {
											WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Duplex Property"
										}
										
										# Disabling RSS on iscsi adapters
										$iSCSI_side_scaling = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Receive Side Scaling"})
										if($iSCSI_side_scaling) {
											if ($iSCSI_side_scaling.DisplayValue -match "Disabled") {
												GoodMessage "iSCSI network adapter $iscsinetadapter Receive Side Scaling is properly configured according to Silk's BP"
											}
											else {
												InfoMessage "Disabling RSS on iSCSI network Adapters $iscsinetadapter"
												Disable-NetAdapterRss -CimSession $CIMsession -name $iscsinetadapter -NoRestart | Out-Null
												
												$iscsinetadapteradvancedproperty = get-netadapteradvancedproperty -CimSession $CIMsession -name $iscsinetadapter
												$iSCSI_side_scaling = ($iscsinetadapteradvancedproperty | Where-Object {$_.DisplayName -match "Receive Side Scaling"})
												if ($iSCSI_side_scaling.DisplayValue -match "Disabled") {
													GoodMessage "iSCSI network adapter $iscsinetadapter Receive Side Scaling is properly configured according to Silk's BP"
												}
												else { 
													BadMessage "Couldn't set iSCSI network adapter $iscsinetadapter RSS (side_scaling)to disabled"
												}
											}
										}
										else {
											WarningMessage "iSCSI network adapter $iscsinetadapter doesn't contain Side Scaling Property"
										}
										
										# Power Saving Property section
										# $adapter_power_saving = invoke-Command -Session $pssessions -Args $iscsinetadapter -ScriptBlock {Get-NetAdapter -Name $args[0] | Get-NetAdapterPowerManagement}
										$adapter_power_saving = (Get-NetAdapterPowerManagement -CimSession $CIMsession -Name $iscsinetadapter)
										if($adapter_power_saving) {
											if ($adapter_power_saving.AllowComputerToTurnOffDevice -match "Disabled") {
												GoodMessage "iSCSI network adapter $iscsinetadapter Power Saving is properly configured according to Silk's BP"
											}
											else { 
												InfoMessage "Disabling Power Saving for iSCSI network Adapters $iscsinetadapter"
												$adapter_power_saving.AllowComputerToTurnOffDevice = "Disabled"
												
												# invoke-Command -Session $pssessions -Args $adapter_power_saving -ScriptBlock {$args[0] | Set-NetAdapterPowerManagement} | Out-Null
												$adapter_power_saving |  Set-NetAdapterPowerManagement -CimSession $CIMsession | Out-Null
												
												$adapter_power_saving = (Get-NetAdapterPowerManagement -CimSession $CIMsession -Name $iscsinetadapter)
												if ($adapter_power_saving.AllowComputerToTurnOffDevice -match "Disabled") {
													GoodMessage "iSCSI network adapter $iscsinetadapter Power Saving is properly configured according to Silk's BP"
												}
												else {
													BadMessage "Couldn't set iSCSI network adapter $iscsinetadapter Power Saving to disabled"
												}
											}
										}
										else {
											WarningMessage "Could not get the iSCSI network adapter $iscsinetadapter network adapter power management and validate if it contain Power Saving Property"
										}
									}
									else {
										InfoMessage "The customer choose no, Skipping configuration for iSCSI network Adapter $iscsinetadapter"
									}
								}
							}
						}
						else {
							InfoMessage "$MessageCounter - Skipping configuration for Windows iSCSI network Adapter"
						}
					}

					$MessageCounter++
					PrintDelimiter
					
					# MPIO Installation - NEW
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
					
					# MPIO Settings and Confioguration - NEW
					if($MPIO_Configuration) {
						InfoMessage "$MessageCounter - Running activation for MPIO Configuration and additional Settings"

						# MPIO sections  Continully only if the Multipath-IO and MultipathIO Feature are installed and enabled
						$MultipathIO        = (invoke-Command -Session $pssessions -ScriptBlock {Get-WindowsFeature -Name Multipath-IO})
						$MultipathIOFeature = (invoke-Command -Session $pssessions -ScriptBlock {(get-WindowsOptionalFeature -Online -FeatureName MultipathIO)})
						if (($MultipathIO.InstallState -match "Installed") -and ($MultipathIOFeature.State -match "Enabled")) {
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
									'PDORemovePeriod'           { $PDORemovePeriod = $($MPIOobject.Split(':')[1]) } # FC 20 / ISCSI 80
									'RetryCount'                { $RetryCount = $($MPIOobject.Split(':')[1]) } # 3
									'RetryInterval'             { $RetryInterval = $($MPIOobject.Split(':')[1]) } # 3
									'UseCustomPathRecoveryTime' { $UseCustomPathRecoveryTime = $($MPIOobject.Split(':')[1]) } # Disabled
									'CustomPathRecoveryTime'    { $CustomPathRecoveryTime = $($MPIOobject.Split(':')[1]) }	# 40
									'DiskTimeoutValue'          { $DiskTimeOutValue = $($MPIOobject.Split(':')[1]) } # 60
								}
							}

							# Print the MPIO Settings
							InfoMessage "MPIO Settings Section"

							# Print the MPIO into the html
							handle_string_array_messages $MPIO_out "Data"
						
							# Checking the MSDSM supported hardware list
							$MSDSMSupportedHW     = (invoke-Command -Session $pssessions -ScriptBlock {Get-MSDSMSupportedHW})
							$MSDSMSupportedHW_out = ($MSDSMSupportedHW | Select-Object ProductId, VendorId | Format-Table * -AutoSize | Out-String).Trim()

							# Print the MPIO Settings
							InfoMessage "MSDSM supported hardware list Section :"

							# Print the MPIO into the html
							handle_string_array_messages $MSDSMSupportedHW_out "Data"

							# Checking the KMNRIO supported hardware list - Associating Silk Data Platform Volumes with MPIO DSM
							$MSDSMSupportedHW_K2 = $MSDSMSupportedHW | where-object {($_.ProductId -eq "K2") -AND ($_.VendorId -eq "KMNRIO")}
							if ($MSDSMSupportedHW_K2) {
								GoodMessage "MPIO DSM KMNRIO & K2 DSM value is properly configured according to Silk's BP"
							}
							else {
								InfoMessage "Associating SDP Vols with MPIO starting..."
								New-MSDSMSupportedHW -CimSession $CIMsession -VendorID KMNRIO -ProductID K2 | Out-Null
								GoodMessage "Associating SDP Vols with MPIO completed"
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

							if ($DiskTimeOutValue -match "60") {
								GoodMessage "DiskTimeOutValue value is properly configured according to Silk's BP"
							}
							else { 
								WarningMessage "DiskTimeOutValue value is not set 60, Current Value is $($DiskTimeOutValue),Configure DiskTimeOutValue parameter starting..."
								(invoke-Command -Session $pssessions -ScriptBlock {set-MPIOSetting -NewDiskTimeout 60}) | Out-Null
								GoodMessage "Configure DiskTimeOutValue parameter completed, server reboot required"
								$bNeedReboot = $true
							}

							if (($RetryInterval -match "3") -OR ($RetryInterval -match "1")) {
								GoodMessage "RetryInterval value is properly configured according to Silk's BP."
							}
							else { 
								WarningMessage "RetryInterval value is not set 3, Current Value is $($RetryInterval), Configure RetryInterval parameter starting..."
								(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewRetryInterval 3 }) | Out-Null
								GoodMessage "Configure RetryInterval parameter completed, server reboot required"
								$bNeedReboot = $true
							}

							if ($UseCustomPathRecoveryTime -match "Disabled") {
								GoodMessage "UseCustomPathRecoveryTime value is properly configured according to Silk's BP"
							}
							else { 
								WarningMessage "UseCustomPathRecoveryTime value is not set Disabled, Current Value is $($UseCustomPathRecoveryTime), Configure UseCustomPathRecoveryTime parameter starting..."
								(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -CustomPathRecovery Disabled}) | Out-Null
								GoodMessage "Configure UseCustomPathRecoveryTime parameter complete, server reboot required"
								$bNeedReboot = $true
							}

							if ($CustomPathRecoveryTime -match "40") {
								GoodMessage "CustomPathRecoveryTime value is properly configured according to Silk's BP"
							}
							else { 
								WarningMessage "CustomPathRecoveryTime value is not set 40, Current Value is $($CustomPathRecoveryTime), Configure CustomPathRecoveryTime parameter starting..."
								(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPathRecoveryInterval 40}) | Out-Null
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
								
							switch($systemConnectivitytype)	{
								"fc" {
									if ($PDORemovePeriod -match "20") {
										GoodMessage "PDORemovePeriod value is properly configured according to Silk's BP"
									}
									else { 
										WarningMessage "PDORemovePeriod value is not set 20, Current Value is $($PDORemovePeriod), Configure PDORemovePeriod parameter starting..."
										(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPDORemovePeriod 20}) | Out-Null
										GoodMessage "Configure PDORemovePeriod parameter complete, server reboot required"
										$bNeedReboot = $true
									}
								}
								"iscsi" {
									if ($PDORemovePeriod -match "80") {
										GoodMessage "PDORemovePeriod value is properly configured according to Silk's BP"
									}
									else { 
										WarningMessage "PDORemovePeriod value is not set 80, Current Value is $($PDORemovePeriod), Configure PDORemovePeriod parameter starting..."
										(invoke-Command -Session $pssessions -ScriptBlock {Set-MPIOSetting -NewPDORemovePeriod 80}) | Out-Null
										GoodMessage "Configure PDORemovePeriod parameter complete, server reboot required"
										$bNeedReboot = $true
									}
									
									# Checking the MSDSM supported hardware list - Adding iSCSI Support
									$MSDSMSupportedHW_iSCSI = $MSDSMSupportedHW | where-object {($_.ProductId -eq "iSCSIBusType_0x9") -AND ($_.VendorId -eq "MSFT2005")}									
									if ($MSDSMSupportedHW_iSCSI) {
										GoodMessage "MPIO DSM value is properly configured according to Silk's BP"
									}
									else {
										WarningMessage "MPIO DSM is not set to VendorId:MSFT2005 and ProductId:iSCSIBusType_0x9, Adding MPIO iSCSI support (Claiming all the iSCSI attached storage for the MPIO) starting..."										
										New-MSDSMSupportedHW -CimSession $CIMsession -VendorID MSFT2005 -ProductID iSCSIBusType_0x9 | Out-Null
										GoodMessage "Adding MPIO iSCSI support complete, server reboot required!"
										$bNeedReboot = $true
									}
									
									# MSDSMAutomaticClaimSettings - Gets settings for MSDSM automatically claiming SAN disks for MPIO. - ISCSI - need to fix
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

					# Load Balance and Failover Policy for Individual Volumes - NEW
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
								$server_diskInfo      = $server_diskInfo | Sort-Object SerialNumber
								$Server_KMNRIO_PD_out = ($server_diskInfo | Select-Object DeviceId,DiskNumber,SerialNumber,FriendlyName,LoadBalancePolicy,CanPool,OperationalStatus,HealthStatus,SizeGB,DriveLetter,DiskStatus,PartitionStyle | Format-Table * -AutoSize | Out-String).Trim() 

								# Print the MPIO into the html
								handle_string_array_messages $Server_KMNRIO_PD_out "Data"

								foreach ($PD_Temp in $server_diskInfo)	{
									# Check for each Individual if it LQD or not
									if ($PD_Temp.LoadBalancePolicy -match "Least Queue Depth") {
										GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Least Queue Depth)"
									}
									else {
										WarningMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (Least Queue Depth) but set to - $($PD_Temp.LoadBalancePolicy)"
										$UniqueID = $PD_Temp.UniqueId.Trim()
										$MPIODisk = (invoke-Command -Session $pssessions -ScriptBlock {(Get-WmiObject -Namespace root\wmi -Class mpio_disk_info).driveinfo | Select-Object Name,SerialNumber})
										$MPIODisk = $MPIODisk | Where-Object {$_.SerialNumber -eq $UniqueID}
										$MPIODiskID = $MPIODisk.Name.Replace("MPIO Disk","")
										(invoke-Command -Session $pssessions -Args $MPIODiskID -ScriptBlock {mpclaim -l -d $args[0] 4}) | out-null
										GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (Least Queue Depth)"
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

						# Checking if the mpclaim found (if not -> mean that MPIO is not installed)						
						if($server_diskInfo.Count -ne 0) {
							# Run over the CTRL disks and verify that each disk is Offline
							foreach ($PD_Temp in ($server_diskInfo | Where-Object {$_.SerialNumber.EndsWith("0000")})) {
								
								# Check for each Individual if it offline or not
								if ($PD_Temp.DiskStatus -match "Offline") {
									GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (DiskStatus - Offline)"
								}
								else {
									WarningMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) is not properly configured according to Silk's BP (DiskStatus - Offline) but set to - $($PD_Temp.DiskStatus)"
									(invoke-Command -Session $pssessions -Args $PD_Temp -ScriptBlock {Get-Disk -SerialNumber $args[0].SerialNumber | Where-Object IsOffline -Eq $False | Set-Disk -IsOffline $True})
									GoodMessage "Silk Disk (DiskNumber - $($PD_Temp.DiskNumber) / SerialNumber - $($PD_Temp.SerialNumber)) properly configured according to Silk's BP (DiskStatus - Offline)"
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

					# Defragmentation Task - NEW
					if($Defragmentation) {
						InfoMessage "$MessageCounter - Running activation for Disk Defrag configuration" 
						$ScheduledDefragTask = (invoke-Command -Session $pssessions -ScriptBlock {(Get-ScheduledTask ScheduledDefrag).state})
						if($ScheduledDefragTask) {
							if($ScheduledDefragTask.value -match "disabled") {
								GoodMessage " Scheduled Disk Fragmentation policy value is properly configured according to Silk's BP"
							}
							else { 
								WarningMessage "Scheduled Disk Fragmentation is not set to Disabled but to $($ScheduledDefragTask.value), Disabling ScheduledDefrag Task, starting..." 
								(invoke-Command -Session $pssessions -ScriptBlock {(Get-ScheduledTask ScheduledDefrag -ErrorAction SilentlyContinue | Disable-ScheduledTask)}) | Out-Null
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
						
					# Remove the PS Session
					if(![string]::IsNullOrEmpty($pssessions.Id)) {
						#Remove the Session from the server
						Get-PSSession -Id $($pssessions.Id) | Remove-PSSession -Confirm:$false -ErrorAction SilentlyContinue
						$pssessions = $null
						InfoMessage "Disconnected from $($WinServer) and remove the PSSession"
					}

					# Remove the CIM session
					if(![string]::IsNullOrEmpty($CIMsession.Id)) {
						#Disconwnect from the server
						Get-CimSession -Id $($CIMsession.Id) | Remove-CimSession -Confirm:$false -ErrorAction SilentlyContinue
						$CIMsession = $null
						InfoMessage "Remove the CimSession"
					}
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
	Finally	{
		# Once all data is collected - output into HTML
		$MessageCurrentObject = "Finished activating`n"

		PrintDelimiterServer

		# Remove the PS session
		if(![string]::IsNullOrEmpty($pssessions.Id)) {
			#Disconwnect from the server
			Get-PSSession -Id $($pssessions.Id) | Remove-PSSession -Confirm:$false -ErrorAction SilentlyContinue
			$pssessions = $null
			InfoMessage "Disconnected from $($WinServer)"
		}

		# Remove the CIM session
		if(![string]::IsNullOrEmpty($CIMsession.Id)) {
			#Disconwnect from the server
			Get-CimSession -Id $($CIMsession.Id) | Remove-CimSession -Confirm:$false -ErrorAction SilentlyContinue
			$CIMsession = $null
			InfoMessage "Remove the CimSession"
		}
	}
}
#endregion

#region Linux Activator
function Linux_Activator {
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
	
	#region Checking_Package
	Function Checking_Package {
		Param(		
		[string]$Pacakge,
		[string]$LinuxOSType
		)

		$bUpdate = $false

		# Checking the PREREQUISITES of the packages that must be installed on the machine
		switch -Wildcard ($LinuxOSType) {
			'rhel*' {
				$command = "sudo rpm -qa | grep $($Pacakge)"
				if($bLocalServer) {
					$rpmCheck = Invoke-Expression $command
				}
				else {
					$rpmCheck = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
				}

				if ($rpmCheck) {
					GoodMessage "package $($Pacakge) Installed, Will try to update to newest version!, The Current version:"
					handle_string_array_messages ($rpmCheck | Out-String).trim() "Data"

					# Found so we Runing update
					$bUpdate = $true
				}
				else {
					$command = "sudo yum -y install $($Pacakge)"
					WarningMessage "package $($Pacakge) not Installed, and will be install, Package installation starting..."
					if($bLocalServer) {
						$rpmInstall = Invoke-Expression $command
					}
					else {
						$rpmInstall = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					GoodMessage "Package installation is completed, Will try to update to newest version!"
					$bUpdate = $true
				}

				if($bUpdate = $true) {
					$command = "sudo yum -y update $($Pacakge)"
					if($bLocalServer) {
						$rpmInstall = Invoke-Expression $command
					}
					else {
						$rpmInstall = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					GoodMessage "Package upading is completed"
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
					GoodMessage "package $($Pacakge) Installed, Will try to update to newest version!, The Current version:"
					handle_string_array_messages ($rpmCheck | Out-String).trim() "Data"

					# Found so we Runing update
					$bUpdate = $true
				}
				else {
					$command = "sudo apt-get -y install $($Pacakge)"
					WarningMessage "package $($Pacakge) not Installed, and will be install, Package installation starting..."
					if($bLocalServer) {
						$rpmInstall = Invoke-Expression $command
					}
					else {
						$rpmInstall = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					GoodMessage "Package installation is completed, Will try to update to newest version!"
					$bUpdate = $true
				}

				if($bUpdate = $true) {
					$command = "sudo apt-get -y --only-upgrade install $($Pacakge)"					
					if($bLocalServer) {
						$rpmInstall = Invoke-Expression $command
					}
					else {
						$rpmInstall = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
					}
					GoodMessage "Package upading is completed"
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

		# Check if it null`
		if($CheckingServiceStatus) {
			$CheckingServiceStatus = $CheckingServiceStatus -join " "
			if(($CheckingServiceStatus -match $ServiceActive) -AND ($CheckingServiceStatus -match $ServiceEnabled)) {
				GoodMessage "$($Service) service is running and enabled..."
			}
			else {
				$command = "sudo systemctl enable $($Service) ; sudo systemctl start $($Service)"
				WarningMessage "Service $($Service) is not running or enabled, current state is - $($CheckingServiceStatus), Enabling and Starting Service starting..."
				if($bLocalServer) {
					$EnablingService = Invoke-Expression $command
				}
				else {
					$EnablingService = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
				}
				InfoMessage "Enabling and Starting Service is completed"
			}
		}
		else {
			BadMessage "$($Service) service not found, Please installed it."
		}
	}
	#endregion

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

	Try 
	{
		# Write the user name to the HTMl
		InfoMessage "Using $($linux_username) login user for Linux Validator"

		PrintDelimiter

		# Write the headline messages into HTML report
		$HeadlineMessage
		$HeadlineMessage = "<div id='Headline'>Running Activator for Linux host(s) `"$($ServerArray)`".</div>"

		# Run over the Server array list
		foreach ($Server in $ServerArray) {
			# Trim the server
			$Server = $Server.trim()
			
			# Init the name of the Linux server 
			$MessageCurrentObject = $Server
			
			if (-not (Test-Connection -ComputerName $Server -Count 2 -Quiet)) {
				WarningMessage "Linux server $($Server) not responding to ping, skipping this server."
			}
			else {
				# Write that ping was sucessfully
				GoodMessage "Pinging - $($Server) was successfully"
				
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
						$command           = "lsb_release -a | grep -E 'Release:|Distributor ID:'"
						$Splinter          = ":"
						
						if($bLocalServer) {
							$Linux_Distro_info = Invoke-Expression $command |  Sort-Object
						}
						else {
							$Linux_Distro_info = (plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command) | Sort-Object
						}						
					}
					else {
						$command  = "cat /etc/os-release | grep -E '\bID=|\bVERSION_ID='"
						$Splinter = "="
						
						if($bLocalServer) {
							$Linux_Distro_info = Invoke-Expression $command |  Sort-Object
						}
						else {
							$Linux_Distro_info = (plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command) |  Sort-Object
						}

						if(-not($Linux_Distro_info)) {
							$bLinuxDistroFound = $false
						}
					}
					
					if($bLinuxDistroFound)	{
						# Get the linux distro and version
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
								elseif($Linux_OS_Version -ge 6)	{
									$linuxtype = "rhel6"
								}
								elseif($Linux_OS_Version -ge 5)	{
									$linuxtype = "rhel5"
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
						WarringMessage "Linux distribution is not found in the Linux OS (cat /etc/os-release | lsb_release -a)"
						WarringMessage "Contact Silk Customer Support if you are using a different version of Oracle Linux, CentOS Linux, Ubuntu, Debian or SUSE Linux"
						Start-Sleep -Seconds 1

						# Ask the customer what is the Linux OS Distro
						Write-host -ForegroundColor Black -BackgroundColor yellow "Please select a Linux distribution"
						Write-host -ForegroundColor Black -BackgroundColor yellow "-----------------------------------------------------"
						write-host -ForegroundColor Black -BackgroundColor White "Option A - RedHat 5.x" 
						write-host -ForegroundColor Black -BackgroundColor White "Option B - RedHat 6.x, CentOS 6.x, Oracle 6.x, Suse 11.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option C - RedHat 7.x, CentOS 7.x, CentOS 8.x, Suse 12.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option D - Debian 6.x, Ubuntu 12.x"
						write-host -ForegroundColor Black -BackgroundColor White "Option E - Debian 7.x, Ubuntu 14.x"

						# Choose the Linux distributions 
						$linuxtitle   = "Please select a Linux distribution"
						$linuxmessage = "Please select from the following options"
						$rhel5		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &A", "Configuring settings according to a RedHat 5 system best practices." 
						$rhel6 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &B", "Configuring settings according to a RedHat 6 system best practices."
						$rhel7 		  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &C", "Configuring settings according to a RedHat 7 system best practices."
						$debian6 	  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &D", "Configuring settings according to a Debian 6 system best practices."
						$debian7 	  = New-Object System.Management.Automation.Host.ChoiceDescription "Option &E", "Configuring settings according to a Debian 7 system best practices."

						$linuxoptions = [System.Management.Automation.Host.ChoiceDescription[]]($rhel5, $rhel6, $rhel7, $debian6, $debian7)
						$linuxresult  = $host.ui.PromptForChoice($linuxtitle, $linuxmessage, $linuxoptions,0) 

						switch ($linuxresult) {
							0 {$linuxtype = "rhel5"}
							1 {$linuxtype = "rhel6"}
							2 {$linuxtype = "rhel7"}
							3 {$linuxtype = "debian6"}
							4 {$linuxtype = "debian7"}
						}
					}
					
					InfoMessage "$MessageCounter - Silk Activator - script will activate according to Linux distribution - $($linuxtype)"
					PrintDelimiter										

					PrintDescription "Category: High Availability related.`nParameter type: Multipath Services and Packages.`nDescription:Installing Multipath packages and services"
					$MPIO_Services = UserSelections "MPIO Packages and Services"

					PrintDescription "Category: High Availability related.`nParameter type: The Multipath configuration settings. `nDescription:Multipathing allows the combination of multiple physical connections between a server and a storage array into one virtual device"
					$Multipath_Conf = UserSelections "Multipath Configuration"

					PrintDescription "Category: High Availability related.`nParameter type: The ioscheduler configuration. `nDescription:I/O schedulers attempt to improve throughput by reordering request access into a linear order based on the logical addresses of the data and trying to group these together"
					$ioscheduler_Conf = UserSelections "ioscheduler Configuration"

					if($systemConnectivitytype -eq "fc") {
						PrintDescription "Category: Performance related.`nParameter type: The HBA settings are global parameters and may impact other attached storage arrays.`nDescription: The HBA settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
						$Linux_Qlogic = UserSelections "Qlogic"
					}
					else {
						PrintDescription "Category: Performance related.`nParameter type: The HBA settings are global parameters and may impact other attached storage arrays.`nDescription: The HBA settings are defined by Silk best practices and are set to work optimally with the Silk Data Platform."
						$Linux_ISCSI = UserSelections "ISCSI" 
					}
					
					# Starting the main section of Applying the best practices
					# =========================================================
					if($MPIO_Services) {
						# Checking the PREREQUISITES of the packages that must be installed on the machine.
						InfoMessage "$MessageCounter - Checking / Enabling / Installing Packages and Services"
						switch -Wildcard ($linuxtype) {
							'rhel*' {
								Checking_Package "device-mapper-multipath" $linuxtype
							}
							'debian*' {
								Checking_Package "multipath-tools" $linuxtype
								Checking_Package "multipath-tools-boot" $linuxtype
							}
						}

						PrintDelimiter

						switch -Wildcard ($linuxtype) {
							'rhel*' {
								Checking_Service "multipathd" $linuxtype
							}
							'debian*' {
								Checking_Service "multipathd" $linuxtype
								Checking_Service "multipath-tools" $linuxtype
							}
						}
					}
					else {
						InfoMessage "$MessageCounter - Skipping Linux MPIO Packages and Services section."
					}

					$MessageCounter++
					PrintDelimiter 

					# MPIO file and parameters
					# ========================
					if($Multipath_Conf) {
						# Get multipath.conf file from server
						InfoMessage "$MessageCounter - Running the Activator for MPIO configuration"
						$multipath_path = "/etc/multipath.conf"
						
						# File Header
						$multipathfile_data = @('# Silk BP Configuration for multipath.conf')
						
						# defaults section
						$multipathfile_data += 'defaults {'
						$multipathfile_data += 'XXXXXXuser_friendly_names   yes'
						$multipathfile_data += 'XXXXXXpolling_interval      1'
						$multipathfile_data += 'XXXXXXfind_multipaths       yes'
						$multipathfile_data += '}'
						$multipathfile_data += ''
						$multipathfile_data += 'blacklist {'

						# blacklist section
						if ($PSPlatform -eq $Platfrom_Windows) {
							$multipathfile_data += 'XXXXXXdevnode ""^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*""'
						}
						else {
							$multipathfile_data += 'XXXXXXdevnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"'
						}
						$multipathfile_data += '}'
						
						# Devices section
						$multipathfile_data += 'devices {'
						$multipathfile_data += 'XXXXXXdevice {'
						if ($PSPlatform -eq $Platfrom_Windows) {
							$multipathfile_data += 'XXXXXXXXXXXXvendor                        ""KMNRIO""'
							$multipathfile_data += 'XXXXXXXXXXXXproduct                       ""K2""'
							$multipathfile_data += 'XXXXXXXXXXXXhardware_handler              ""0""'
						}
						else {
							$multipathfile_data += 'XXXXXXXXXXXXvendor                        "KMNRIO"'
							$multipathfile_data += 'XXXXXXXXXXXXproduct                       "K2"'
							$multipathfile_data += 'XXXXXXXXXXXXhardware_handler              "0"'
							
						}

						switch($linuxtype) {
							"rhel7" {
								if ($PSPlatform -eq $Platfrom_Windows) {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 ""queue-length 0""'
								}
								else {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 "queue-length 0"'
								}
								$multipathfile_data += 'XXXXXXXXXXXXfailback                      immediate'
								$multipathfile_data += 'XXXXXXXXXXXXfast_io_fail_tmo              2'
								$multipathfile_data += 'XXXXXXXXXXXXdev_loss_tmo                  3'
							}
							"rhel6" {
								if ($PSPlatform -eq $Platfrom_Windows) {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 ""queue-length 0""'
									$multipathfile_data += 'XXXXXXXXXXXXgetuid_callout                ""/lib/udev/scsi_id --whitelisted --device=/dev/%n""'
								}
								else {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 "queue-length 0"'
									$multipathfile_data += 'XXXXXXXXXXXXgetuid_callout                "/lib/udev/scsi_id --whitelisted --device=/dev/%n"'
								}
								$multipathfile_data += 'XXXXXXXXXXXXfailback                      15'
								$multipathfile_data += 'XXXXXXXXXXXXfast_io_fail_tmo              5'
								$multipathfile_data += 'XXXXXXXXXXXXdev_loss_tmo                  8'
							}
							"rhel5" {
								if ($PSPlatform -eq $Platfrom_Windows) {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 ""round-robin 0""'
									$multipathfile_data += 'XXXXXXXXXXXXgetuid_callout                ""/sbin/scsi_id -g -u -s /block/%n""'
								}
								else {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 "queue-length 0"'
									$multipathfile_data += 'XXXXXXXXXXXXgetuid_callout                "/sbin/scsi_id -g -u -s /block/%n"'
								}
								$multipathfile_data += 'XXXXXXXXXXXXfailback                      15'
							}
							"debian6" {
								if ($PSPlatform -eq $Platfrom_Windows) {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 ""queue-length 0""'
									$multipathfile_data += 'XXXXXXXXXXXXgetuid_callout                ""/lib/udev/scsi_id --whitelisted --device=/dev/%n""'
								}
								else {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 "queue-length 0"'
									$multipathfile_data += 'XXXXXXXXXXXXgetuid_callout                "/lib/udev/scsi_id --whitelisted --device=/dev/%n"'
								}
								$multipathfile_data += 'XXXXXXXXXXXXfailback                      15'
								$multipathfile_data += 'XXXXXXXXXXXXfast_io_fail_tmo              5'
								$multipathfile_data += 'XXXXXXXXXXXXdev_loss_tmo                  8'
							}
							"debian7" {
								if ($PSPlatform -eq $Platfrom_Windows) {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 ""queue-length 0""'
								}
								else {
									$multipathfile_data += 'XXXXXXXXXXXXpath_selector                 "queue-length 0"'
								}
								$multipathfile_data += 'XXXXXXXXXXXXfailback                      15'
							}
						}
						$multipathfile_data += 'XXXXXXXXXXXXpath_grouping_policy          multibus'
						$multipathfile_data += 'XXXXXXXXXXXXpath_checker                  tur'
						$multipathfile_data += 'XXXXXXXXXXXXno_path_retry                 fail'
						$multipathfile_data += 'XXXXXXXXXXXXrr_weight                     priorities'
						$multipathfile_data += 'XXXXXXXXXXXXrr_min_io                     1'
						$multipathfile_data += 'XXXXXX}'
						$multipathfile_data += '}'
						
						# Fix the TAB by replace XXX with space
						$multipathfile_data = (($multipathfile_data -split "`n") | ForEach-Object {$_.TrimStart()} | ForEach-Object {$_.replace("XXXXXX","         ")}) -join "`n"
						
						# Check if the file existing
						$command = "test -f $($multipath_path) && echo true || echo false"
						if($bLocalServer) {
							$multipathconffileexists = Invoke-Expression $command
						}
						else {
							$multipathconffileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}

						if ($multipathconffileexists -match "true") {
							$command = "cat $($multipath_path)"
							if($bLocalServer) {
								$multipathconf = Invoke-Expression $command
							}
							else {
								$multipathconf = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
							}
							
							# 	Write the Multipath into the HTML file
							InfoMessage "File - $($multipath_path) - Content:"
							handle_string_array_messages ($multipathconf |out-string).Trim() "Data"

							# Backup the orginal one 
							$backup_multipath_file = $multipath_path.Replace(".conf","_backup.conf")
							InfoMessage "Backing up file - $($multipath_path) ,to - $($backup_multipath_file)"
							$command_multipath_backup = "sudo cp $($multipath_path) $($backup_multipath_file)"
							
							if($bLocalServer) {
								Invoke-Expression $command_multipath_backup
							}
							else {
								plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command_multipath_backup
							}
						}
						else {
							BadMessage "multipath.conf file not found on $($multipath_path), we will create it"
						}
												
						$command_multipath_write = "echo '$multipathfile_data' | sudo tee $($multipath_path)"
						InfoMessage "Setting the multipath.conf according to Silk's Best Practices"
						if($bLocalServer) {
							$command_multipath_write_output = Invoke-Expression $command_multipath_write
						}
						else {
							$command_multipath_write_output = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command_multipath_write
						}
						GoodMessage "multipath.conf file was set with Silk's best practices"
						
						# If it was created from windows (Plink remotlly)
						if ($PSPlatform -eq $Platfrom_Windows) {
							$command_multipath_write_dos2unix = "sudo sed -i -e 's/\r//g' $($multipath_path)"
							$command_multipath_write_dos2unix_output = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command_multipath_write_dos2unix
							GoodMessage "multipath.conf file was set as dos2unix, Removed ^M characters"
						}

						# Restart and Enable the multipathd
						switch -Wildcard ($linuxtype) {
							'rhel*' {
								$multipath_command_chkconfig = "sudo chkconfig --level 345 multipathd on"
								$multipath_command_restart   = "sudo systemctl restart multipathd"
								$multipath_command_enable    = "sudo systemctl enable multipathd"
							}
							'debian*' {
								$multipath_command_chkconfig = "sudo chkconfig --level 345 multipath-tools on"
								$multipath_command_restart   = "sudo systemctl restart multipath-tools.service"
								$multipath_command_enable    = "sudo systemctl enable multipath-tools"
							}
						}
						
						if($bLocalServer) {
							Invoke-Expression $multipath_command_chkconfig
							Invoke-Expression $multipath_command_restart
							Invoke-Expression $multipath_command_enable	
						}
						else {							
							plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $multipath_command_chkconfig
							plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $multipath_command_restart
							plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $multipath_command_enable
						}
						GoodMessage "multipathd service restarted and enabled"
					}
					else
					{
						InfoMessage "$MessageCounter - Skipping Linux Multipath Configuration"
					}
					
					$MessageCounter++
					PrintDelimiter
					
					# ioscheduler_Conf file and parameters
					# ====================================
					if ($ioscheduler_Conf)
					{
						#overwrite the files content
						InfoMessage "$MessageCounter - Running the Activator for ioscheduler configuration"	
						
						$udev_Silk_BP_data = @('# Silk BP Configuration for SDP-io.rules')
						if ($PSPlatform -eq $Platfrom_Windows) {
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""20024f400*"",ATTR{queue/scheduler}=""noop""'
							$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-20024f400*"",ATTR{queue/scheduler}=""noop""'
						}
						else {
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="20024f400*",ATTR{queue/scheduler}="noop"'
							$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-20024f400*",ATTR{queue/scheduler}="noop"'
						}
						
						switch -Wildcard ($linuxtype) 
						{
							'rhel*'
							{
								if ($PSPlatform -eq $Platfrom_Windows) {
									$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""20024f400*"",ATTR{queue/max_sectors_kb}=""1024""'
									$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-20024f400*"",ATTR{queue/max_sectors_kb}=""1024""'
								}
								else {
									$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="20024f400*",ATTR{queue/max_sectors_kb}="1024"'
									$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-20024f400*",ATTR{queue/max_sectors_kb}="1024"'
								}
							}
							
							'debian*'
							{
								if ($PSPlatform -eq $Platfrom_Windows) {
									$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{ID_SERIAL}==""20024f400*"",ATTR{queue/max_sectors_kb}=""4096""'
									$udev_Silk_BP_data += 'ACTION==""add|change"", SUBSYSTEM==""block"", ENV{DM_UUID}==""mpath-20024f400*"",ATTR{queue/max_sectors_kb}=""4096""'
								}
								else {
									$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="20024f400*",ATTR{queue/max_sectors_kb}="4096"'
									$udev_Silk_BP_data += 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DM_UUID}=="mpath-20024f400*",ATTR{queue/max_sectors_kb}="4096"'
								}
							}
						}
						
						# Get /usr/lib/udev/rules.d/98-sdp-io.rules file from server
						$udev_Silk_BP_data = $udev_Silk_BP_data | Out-String -Stream
						
						# Get multipath.conf file from server 
						$udev_file_path = "/etc/udev/rules.d/62-io-schedulers.rules"
						
						$command = "test -f $($udev_file_path) && echo true || echo false"
						if($bLocalServer) {
							$ioschedulersfileexists = Invoke-Expression $command
						}
						else{
							$ioschedulersfileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
						}
						
						if($ioschedulersfileexists -match "true") {
							$command = "cat $($udev_file_path)"
							if($bLocalServer) {
								$ioschedulersData = Invoke-Expression $command
							}
							else {
								$ioschedulersData = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command
							}

							# 	Write the 98-sdp-io.rules into the HTML file
							InfoMessage "File - $($udev_file_path) - Content Before Overwrite:"
							handle_string_array_messages ($ioschedulersData |out-string).trim() "Data"

							# Backup the orginal one 
							$backup_udev_file = $udev_file_path.Replace(".rules","_backup.rules")
							InfoMessage "Backing up file - $($udev_file_path) ,to - $($backup_udev_file)"
							$command_udev_backup = "sudo cp $($udev_file_path) $($backup_udev_file)"
							
							if($bLocalServer) {
								$command_udev_backup_output = Invoke-Expression $command_udev_backup
							}
							else {
								$command_udev_backup_output = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command_udev_backup
							}
						}
						else {
							BadMessage "98-sdp-io.rules not found on $($udev_file_path), We will create it"
						}

						# Overwrite the current schedulers values
						$udev_Silk_BP_data = $udev_Silk_BP_data -join "`n"
						$command_fill_udev = "echo '$udev_Silk_BP_data' | sudo tee $($udev_file_path)"
						if($bLocalServer) {
							$ioschedulersfileexists = Invoke-Expression $command_fill_udev
						}
						else {
							$ioschedulersfileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command_fill_udev
						}
						GoodMessage "io-schedulers.rules file was set with Silk's best practices"

						#rewrites the io-schedulers.rules according to Silks BP
						InfoMessage "Reloading the UDEV rules"
						$command_reload_udev = 'sudo udevadm trigger && sudo udevadm settle'
						if($bLocalServer) {
							$ioschedulersfileexists = Invoke-Expression $command_reload_udev
						}
						else {
							$ioschedulersfileexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $command_reload_udev
						}
						GoodMessage "udevadm trigger && udevadm settle commands executed"
					}
					else {
						InfoMessage "$MessageCounter - Skipping Linux ioscheduler Configuration"
					}
					
					$MessageCounter++
					PrintDelimiter
					
					# Network Section
					# ===============
					switch($systemConnectivitytype) {
						"fc" {
							if($linux_username -ne "root") {
								WarningMessage "$MessageCounter - We don't support the qLogic FC validation with user that it not root user (Locally / Remote)"
							}
							else {
								if ($Linux_Qlogic) {									
									#check if qconverge is installed propely and can be exeuted
									InfoMessage "$MessageCounter - Running Activation for FC QLogic configuration"
									$lspcicommand = "lspci | grep -i qlogic | grep -i 'Fibre Channel'"
									if($bLocalServer) {
										$qlogic = Invoke-Expression $lspcicommand
									}
									else{
										$qlogic = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $lspcicommand
									}
									
									if($qlogic) {
										$qlogictest = "test -d /opt/QLogic_Corporation/QConvergeConsoleCLI && echo true || echo false"
										if($bLocalServer) {
											$qaucliexists = Invoke-Expression $qlogictest
										}
										else{
											$qaucliexists = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qlogictest
										}
										
										if (-not($qaucliexists)) {
											BadMessage "Couldn't found qaucli tool for QLogic for setting configuration"
										}
										else {
											$qlogicHBACommand = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -pr fc -g"
											if($bLocalServer) {
												$qlogicHBAData = Invoke-Expression $qlogicHBACommand
											}
											else{
												$qlogicHBAData = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qlogicHBACommand
											}
											$qlogicHBAData = $qlogicHBAData | Select-String "HBA Instance" | select-string "Online"| Select-Object -Property @{ Name = 'Row';  Expression = {$_}}, @{ Name = 'HBA_Instance'; Expression = { $_.ToString().split(" ")[-2].Replace(")","")}}
											
											$HBA_Online_Array = @()
											foreach($qauclioutput_hba_item in $qlogicHBAData)
											{
												$obj = New-Object -TypeName PSObject
												$obj | Add-Member -MemberType NoteProperty -Name Row -Value $qauclioutput_hba_item.Row.ToString().Trim()
												$obj | Add-Member -MemberType NoteProperty -Name HBA_Instance -Value $qauclioutput_hba_item.HBA_Instance
												
												$qaucliHBA    = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -pr fc -c $($qauclioutput_hba_item.HBA_Instance)"
												if($bLocalServer) {
													$qlogic_hba = Invoke-Expression $qaucliHBA
												}
												else {
													$qlogic_hba = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliHBA
												}

												$qlogic_hba = qlogic_hba | Select-String "^Operation Mode|^Interrupt Delay Timer|^Execution Throttle"
												$HBA_Settings_Operation_Mode        = ($HBA_Settings -match "^Operation Mode").line.split(":")[1].trim()
												$HBA_Settings_Interrupt_Delay_Timer = ($HBA_Settings -match "^Interrupt Delay Timer").line.split(":")[1].trim()
												$HBA_Settings_Execution_Throttle    = ($HBA_Settings -match "^Execution Throttle").line.split(":")[1].trim()
												$obj | Add-Member -MemberType NoteProperty -Name Operation_Mode -value $HBA_Settings_Operation_Mode
												$obj | Add-Member -MemberType NoteProperty -Name Interrupt_Delay_Timer -value $HBA_Settings_Interrupt_Delay_Timer
												$obj | Add-Member -MemberType NoteProperty -Name Execution_Throttle -value $HBA_Settings_Execution_Throttle
														
												$HBA_Online_Array += $obj
											}

											# Print to the HTML report all Online reports
											handle_string_array_messages ($HBA_Online_Array | Format-Table * -AutoSize | Out-String).trim() "Data"

											# Show to the customer only HBA that need to be change
											$HBA_Online_Array_Change = $null
											$HBA_Online_Array_Change = $HBA_Online_Array | Where-Object {($_.Operation_Mode -ne "6 - Interrupt when Interrupt Delay Timer expires") -or ($_.Interrupt_Delay_Timer -ne 1) -or ($_.Execution_Throttle -ne 400)} 
																					
											if($HBA_Online_Array_Change) {
												$HBA_Online_Array_Change | Format-Table * -autosize
												$confirmation = Read-Host "Select specified HBA instance number or select all instances (999)"

												if($confirmation -eq 999) {
													InfoMessage "Setting the QLogic parameters according to Silk's best pratices for all avaliable HBA instances"
													foreach ($HBA_Online_Array_Change_item in $HBA_Online_Array_Change) {
														$temp_HBA_Instance = $HBA_Online_Array_Change_item.HBA_Instance
														$qaucliom = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -n $($temp_HBA_Instance) OM 6"
														$qaucliid = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -n $($temp_HBA_Instance) ID 1"
														$qaucliet = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -n $($temp_HBA_Instance) ET 400"
														
														if($bLocalServer) {
															Invoke-Expression $qaucliom
															Invoke-Expression $qaucliid
															Invoke-Expression $qaucliet
														}
														else {
															plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliom
															plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliid
															plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliet
														}
			
														GoodMessage "HBA instance - $($temp_HBA_Instance) - Operation Mode set to Interrupt when Interrupt Delay Timer expires or there is no active I/O"
														GoodMessage "HBA instance - $($temp_HBA_Instance) - Interrupt Delay Timer set to 1"
														GoodMessage "HBA instance - $($temp_HBA_Instance) - Execution Throttle set to 400"
													}
													WarningMessage "Please reboot the server for these changes to take effect!"
												}
												else {
													$qaucliHBA  = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -pr fc -c $($confirmation)"
													if($bLocalServer) {
														$qlogic_hba = Invoke-Expression $qaucliHBA
													}
													else{
														$qlogic_hba = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliHBA
													}
													
													while (($qlogic_hba -eq "Unable to locate the specified HBA!") -or ($qlogic_hba -match "Unrecognized")) {
														WarringMessage "Unable to locate the specified HBA instance!, skipping configuration for QLogic section, try again."
														$confirmation = Read-Host "Select specified HBA instance number"
														$qaucliHBA    = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -pr fc -c $($confirmation)"
														if($bLocalServer) {
															$qlogic_hba = Invoke-Expression $qaucliHBA
														}
														else {
															$qlogic_hba = plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliHBA
														}
													}
		
													InfoMessage "Setting the QLogic parameters according to Silk's best pratices for HBA instance - $confirmation"
													
													$qaucliom = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -n $($confirmation) OM 6"
													$qaucliid = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -n $($confirmation) ID 1"
													$qaucliet = "/opt/QLogic_Corporation/QConvergeConsoleCLI/qaucli -n $($confirmation) ET 400"
													
													if($bLocalServer) {
														Invoke-Expression $qaucliom
														Invoke-Expression $qaucliid
														Invoke-Expression $qaucliet
													}
													else {
														plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliom
														plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliid
														plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $qaucliet
													}
		
													GoodMessage "HBA instance - $($confirmation) - Operation Mode set to Interrupt when Interrupt Delay Timer expires or there is no active I/O"
													GoodMessage "HBA instance - $($confirmation) - Interrupt Delay Timer set to 1"
													GoodMessage "HBA instance - $($confirmation) - Execution Throttle set to 400"
		
													WarningMessage "Please reboot the server for these changes to take effect!"
												}
											}
											else{
												GoodMessage "Skipping Windows Qlogic configuration - All HBA are configured probably as Silk BP"
											}
										}
									}
									else {
										InfoMessage "Skipping FC check since FC HBA is not Qlogic"
									}
								}
								else {
									InfoMessage "$MessageCounter - Skipping Linux FC Qlogic Configuration"
								}
							}
						}
						
						"iscsi" {
							if ($Linux_ISCSI) {
								InfoMessage "$MessageCounter - Running Activation for iSCSI configuration"

								# Install the iSCSI service 
								switch -Wildcard ($linuxtype) {
									'rhel*' {
										Checking_Package "iscsi-initiator-utils" $linuxtype
										$iSCSI_command_chkconfig = "sudo chkconfig --level 345 iscsi on"
										$iSCSI_command_enable    = "sudo systemctl enable iscsi"
										switch ($linuxtype)	{
											"rhel7" {
												$iSCSI_command_start   = "sudo systemctl start iscsid"
											}
											"rhel6" {
												
												$iSCSI_command_start   = "/etc/init.d/iscsi start"
											}
											"rhel5" {
												$iSCSI_command_start   = "/etc/init.d/iscsi start"
											}
										}

										if($bLocalServer) {
											Invoke-Expression $iSCSI_command_chkconfig
											Invoke-Expression $iSCSI_command_start
											Invoke-Expression $iSCSI_command_enable
										}
										else {
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_chkconfig
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_restart
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_enable
										}
									}
									'debian*' {
										Checking_Package "open-iscsi" $linuxtype
										$iSCSI_command_chkconfig = "sudo chkconfig --level 345 open-iscsi on"
										$iSCSI_command_start_iscsid      = "sudo systemctl start iscsid"
										$iSCSI_command_enable_iscsid     = "sudo systemctl enable iscsid"
										$iSCSI_command_start_open_iscsi  = "sudo systemctl start open-iscsi"
										$iSCSI_command_enable_open_iscsi = "sudo systemctl enable open-iscsi"
										$iSCSI_command_restart           = "sudo systemctl resart iscsid open-iscsi"


										if($bLocalServer) {
											Invoke-Expression $iSCSI_command_chkconfig
											Invoke-Expression $iSCSI_command_start_iscsid
											Invoke-Expression $iSCSI_command_enable_iscsid
											Invoke-Expression $iSCSI_command_start_open_iscsi
											Invoke-Expression $iSCSI_command_enable_open_iscsi
											Invoke-Expression $iSCSI_command_restart
										}
										else {
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_chkconfig
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_start_iscsid
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_enable_iscsid
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_start_open_iscsi
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_enable_open_iscsi
											plink -ssh $Server -pw $linux_userpassword -l $linux_username -no-antispoof $iSCSI_command_restart
										}
									}
								}							

								$MessageCounter++
								PrintDelimiter
							}
							else
							{
								InfoMessage "$MessageCounter - Skipping Linux iSCSI setup configuration"
							}
						}
					}
				}
			}

			PrintDelimiter
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
		$MessageCurrentObject = "Finished Activation`n"	

		PrintDelimiterServer
	}
}
#endregion
##################################### End Activator functions ##############################################################

##################################### Main #####################################
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
	Set-Variable -Name systemConnectivitytype -Option AllScope -Scope Script
	Set-Variable -Name SDPBPHTMLBody -Value "" -Option AllScope -Scope Script

	#Global parameter for all Functions for the HTML output file
	$TempOrigColor = $host.ui.RawUI.ForegroundColor
	Set-Variable -Name OrigColor -Value $TempOrigColor -Option AllScope -Scope Script
	
	# clear the console
	clear-host

	# Add the Pre-Checking Header
	$MessageCurrentObject = "Silk Activator pre-Checking"

	# Start time 
	$bDate = Get-date

	# Print the PowerShell versions and edtion
	InfoMessage "Silk Activator for Product - $($ActivatorProduct)"
	InfoMessage "PowerShell Version is - $($PSVersionTable.PSVersion.Major)"
	InfoMessage "PowerShell Edition is - $($PSVersionTable.PSEdition)"

	if (CheckAdminUserCrossPlatform) {
		# Global Variables
		[string]$HostType = ""
		[string]$systemConnectivitytype = ""

		#region Script Choice Selection Host Type
		$optionVMWare  = New-Object System.Management.Automation.Host.ChoiceDescription '&VMWare' , 'Host Type: VMWare'
		$optionLinux   = New-Object System.Management.Automation.Host.ChoiceDescription '&Linux'  , 'Host Type: Linux'
		$optionWindows = New-Object System.Management.Automation.Host.ChoiceDescription '&Windows', 'Host Type: Windows'
		$optionExit    = New-Object System.Management.Automation.Host.ChoiceDescription "&Exit"   , "Exit"

		$optionsContainer = [System.Management.Automation.Host.ChoiceDescription[]]($optionVMWare, $optionLinux, $optionWindows,$optionExit)

		$optiontitle    = 'The Silk Best Practices Activator Script'
		$optionmessage  = 'Choose your Host Type'
		$HostTypeResult = $host.ui.PromptForChoice($optiontitle, $optionmessage, $optionsContainer, 3)
		[boolean]$bExit = $false

		switch ($HostTypeResult) {
			0 { $HostType = "VMware"  }
			1 { $HostType = "Linux"   }
			2 { $HostType = "Windows" }
			3 { 
				Write-Host "Exiting, Good Bye." -ForegroundColor Red
				$HostType = "Exit"
				$bExit = $true
				Start-Sleep -Seconds 2
			}
		}
		InfoMessage "Customer choose operation system type: $($HostType)"
		#endregion

		if (-not($bExit)) {
			#region Script Choice Selection K2 Connectivity (FC / iSCSI)
			$optionfc 	 = New-Object System.Management.Automation.Host.ChoiceDescription '&FC', "Validating settings according to a FC system best practices."
			$optioniscsi = New-Object System.Management.Automation.Host.ChoiceDescription '&ISCSI', "Validating settings according to a iSCSI system best practices."

			$optionsContainer1 = [System.Management.Automation.Host.ChoiceDescription[]]($optionfc, $optioniscsi)

			$optiontitle        = "System connectivity type"
			$optionmessage      = "What type of SAN connectivity your system is?"
			$ConnectivityResult = $host.ui.PromptForChoice($optiontitle, $optionmessage, $optionsContainer1, 0) 

			switch ($ConnectivityResult) {
				0 {$systemConnectivitytype = "FC"}
				1 {$systemConnectivitytype = "ISCSI"}
			}
			InfoMessage "Customer choose Connectivity type: $($systemConnectivitytype)"	
			#endregion

			# Write console empty row
			write-host 

			# Print Delimiter 
			PrintDelimiterServer
			$SDPBPHTMLBody += "<div id='host_space'></div>"

			#checks the input from and Activates accordingly 
			switch($HostType) {
				"VMware"{
					Write-Host -ForegroundColor Yellow "This script gets vCenter and a Cluster name as inputs and validates all ESXi servers according to Silk best practices. `n there is also an option to specify just specific servers with the esxi parameter."
					$vCenter    = read-host "vCenter -Specify the vCenter name to connect to. Can be combined with -ESXHost and/or -Cluster"
					$Cluster    = read-host "Cluster -Specify the ESXi cluster to validate. Requires the -vCenter argument"
					$ESXHost    = read-host "ESXHost -Specify the ESXi host to validate. Can be combined with the -vCenter argument"
					$Credential = $host.ui.PromptForCredential("Silk BP credentials", "Please enter your VMware username and password.", "", "")
					VMware_Activator $vCenter $Cluster $ESXHost $Credential
				}
				
				"Linux" {
					Write-Host -ForegroundColor Yellow "This script gets Linux servers as inputs and validates servers parameters according to Silk best practices."
					[string]$LinuxServerString  = ""
					[string[]]$LinuxServerArray = @()
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

				"Windows" {
					Write-Host -ForegroundColor Yellow "This script gets Windows servers as input and validates servers parameters according to Silk best practices."
					[string]$WindowsServerString  = ""
					[string[]]$WindowsServerArray = @()
					$WindowsServerString = read-host  ("Windows Server -Specify the Server name/s or IP adress/es to connect to (comma as a separation between them),`nPress enter if you want check local server")
					$WindowsServerString = TrimHostNames $WindowsServerString
					$WindowsServerArray  = $WindowsServerString.split(",")
					
					# Check the Windows servers, if it empty run this with local user
					if ([string]::IsNullOrEmpty($WindowsServerarray)) {
						Windows_Activator $WindowsServerarray
					}
					else {
						# Choose user for the validator
						do {
							$WinCredential = Read-Host "Windows Credential - using $(whoami) Login user (Y/N), N = or different user"
						} while (($WinCredential -NotMatch "[yY]") -and ($WinCredential -NotMatch "[nN]"))

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
	[string]$MessageCurrentObject = "Silk Activator Ending"
	GoodMessage "Done, Good Bye!"
	start-sleep -seconds 2
}
#endregion
##################################### End Main #############################################################################