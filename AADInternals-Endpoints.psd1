@{

	# Script module or binary module file associated with this manifest.
	RootModule = 'AADInternals-Endpoints.psm1'

	# Version number of this module.
	ModuleVersion = '0.9.8'

	# Supported PSEditions
	# CompatiblePSEditions = @()

	# ID used to uniquely identify this module
	GUID = '38a316d7-d55d-4611-8218-efa0817d55cf'

	# Author of this module
	Author = 'Dr Nestori Syynimaa'

	# Company or vendor of this module
	CompanyName = 'Gerenios Ltd'

	# Copyright statement for this module
	Copyright = '(c) 2025 Nestori Syynimaa (@DrAzureAD). Distributed under MIT license.'

	# Description of the functionality provided by this module
	Description = 'The AADInternals-Endpoints PowerShell Module contains functionality to modify and extract information from the endpoints (servers, computers, etc.).

DISCLAIMER: Functionality provided through this module are not supported by Microsoft and thus should not be used in a production environment. Use on your own risk! 

'

	# Minimum version of the Windows PowerShell engine required by this module
	# PowerShellVersion = ''

	# Name of the Windows PowerShell host required by this module
	# PowerShellHostName = ''

	# Minimum version of the Windows PowerShell host required by this module
	# PowerShellHostVersion = ''

	# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# DotNetFrameworkVersion = ''

	# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
	# CLRVersion = ''

	# Processor architecture (None, X86, Amd64) required by this module
	# ProcessorArchitecture = ''

	# Modules that must be imported into the global environment prior to importing this module
	# RequiredModules = @()

	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @()

	# Script files (.ps1) that are run in the caller's environment prior to importing this module.
	# ScriptsToProcess = @()

	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @()

	# Format files (.ps1xml) to be loaded when importing this module
	# FormatsToProcess = @()

	# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
	NestedModules = @(
        ".\AADSyncSettings.ps1"
        ".\AccessToken_utils.ps1"
        ".\AD_utils.ps1"
        ".\ADFS.ps1"
        ".\ADFS_utils.ps1"
        ".\ClientTools.ps1"
        ".\CommonUtils.ps1"
        ".\CommonUtils_endpoints.ps1"
        ".\Device.ps1"
        ".\Device_utils.ps1"
        ".\DRS_Utils.ps1"
        ".\FederatedIdentityTools.ps1"
        ".\HybridHealthServices_utils.ps1"
        ".\ProcessTools.ps1"
        ".\ProxySettings.ps1"
        ".\PRT.ps1"
        ".\PRT_Utils.ps1"
        ".\PTA.ps1"
        ".\SQLite.ps1"
        ".\TBRES.ps1"
        ".\Win32Ntv.ps1"
)

	# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
	FunctionsToExport = @(
    # ADFS.ps1
    "Export-ADFSCertificates"
    "Export-ADFSConfiguration"
    "Export-ADFSEncryptionKey"
    "Set-ADFSConfiguration"
    "Get-ADFSPolicyStoreRules"
    "Set-ADFSPolicyStoreRules"

    # ADFS_utils.ps1
    "New-ADFSSelfSignedCertificates"
    "Restore-ADFSAutoRollover"
    "Update-ADFSFederationSettings"
    
    # AccessToken_utils.ps1
    "Export-TeamsTokens"
    "Export-AzureCliTokens"
    "Export-TokenBrokerTokens"

    # AADSyncSettings.ps1
    "Get-SyncCredentials"
    "Update-SyncCredentials"
    "Get-SyncEncryptionKeyInfo"
    "Get-SyncEncryptionKey"

    # PTASpy.ps1
    "Install-PTASpy"
    "Remove-PTASpy"
    "Get-PTASpyLog"

    # ClientTools.ps1
    "Get-OfficeUpdateBranch"
    "Set-OfficeUpdateBranch"

    # PTA.ps1
    "Set-PTACertificate"

    # MSAppProxy.ps1
    "Export-ProxyAgentCertificates"

    # AD_Utils.ps1
    "Get-DPAPIKeys"
    "Get-LSASecrets"
    "Get-LSABackupKeys"
    "Get-UserMasterkeys"
    "Get-LocalUserCredentials"
    "Get-SystemMasterkeys"

    # PRT.ps1
    "Get-UserPRTToken"
    "Get-UserPRTKeysFromCloudAP"
    
    # CommonUtils_endpoints.ps1
    "New-Certificate"
    "Get-AzureWireServierAddress"
    "Invoke-ScriptAs"
    "Remove-Services"

    # DRS_Utils.ps1
    "Get-ADUserNTHash"
    "Get-ADUserThumbnailPhoto"
    "Get-DesktopSSOAccountPassword"

    # HybridHealthServices_utils.ps1
    "Get-HybridHealthServiceAgentInfo"

    # Device.ps1
    "Export-LocalDeviceCertificate"
    "Export-LocalDeviceTransportKey" 
    "Join-LocalDeviceToAzureAD"
    "Get-LocalDeviceJoinInfo"
    "Export-LocalDeviceMDMCertificate"

    # ProxySettings.ps1
    "Set-ProxySettings"
)

	# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
	CmdletsToExport = @()

	# Variables to export from this module
	VariablesToExport = ''

	# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
	AliasesToExport = @()

	# DSC resources to export from this module
	# DscResourcesToExport = @()

	# List of all modules packaged with this module
	# ModuleList = @()

	# List of all files packaged with this module
	# FileList = @()

	# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{

		PSData = @{

			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = @('Office365','Microsoft365','Azure','AAD','Security')

			# A URL to the license for this module.
			LicenseUri = 'https://raw.githubusercontent.com/Gerenios/AADInternals/master/LICENSE.md'

			# A URL to the main website for this project.
			ProjectURI = 'https://aadinternals.com/aadinternals'

			# A URL to an icon representing this module.
			IconUri = 'https://aadinternals.com/images/favicon-endpoints-128.png'

			# ReleaseNotes of this module
			# ReleaseNotes = ''

		} # End of PSData hashtable

	} # End of PrivateData hashtable

	# HelpInfo URI of this module
	HelpInfoURI = 'https://aadinternals.com/aadinternals'

	# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
	DefaultCommandPrefix = 'AADInt'

}

