function Get-SpeculationControlSettings {
    <#
    .SYNOPSIS
    This function queries the speculation control settings for the system.

    .DESCRIPTION
    This function queries the speculation control settings for the system.

    .PARAMETER Quiet
    This parameter suppresses host output that is displayed by default.

    .LINK
        PSModule : https://www.powershellgallery.com/packages/SpeculationControl/1.0.14
    .LINK
        Understand The Output : https://support.microsoft.com/en-us/topic/understanding-get-speculationcontrolsettings-powershell-script-output-fd70a80a-a63f-e539-cda5-5be4c9e67c04
    .LINK

    #>
    [CmdletBinding()]
    param (
        [switch]$Quiet
    )
    Begin {
        #requires -Version 3
    }

    process {
        if ($(try { [bool]([Win32.ntdll] -as [Type]) }catch { $false })) {
            Write-Verbose "Type [Win32.ntdll] already exist, Using it now ..."
            $ntdll = [Win32.ntdll]
        }
        else {
            Write-Verbose "Add-Type [Win32.ntdll] ..."
            $NtQSIDefinition = '[DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);'
            $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru
        }
        [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

        $object = New-Object -TypeName PSObject

        try {
            $cpu = Get-CimInstance Win32_Processor

            if ($cpu -is [array]) {
                $cpu = $cpu[0]
            }

            $PROCESSOR_ARCHITECTURE_ARM64 = 12
            $PROCESSOR_ARCHITECTURE_ARM = 5

            $manufacturer = $cpu.Manufacturer
            $processorArchitecture = $cpu.Architecture

            $isArmCpu = ($processorArchitecture -eq $PROCESSOR_ARCHITECTURE_ARM) -or ($processorArchitecture -eq $PROCESSOR_ARCHITECTURE_ARM64)

            #
            # Query branch target injection information.
            #

            if ($Quiet -ne $true) {

                Write-Host "For more information about the output below, please refer to https://support.microsoft.com/help/4074629" -ForegroundColor Cyan
                Write-Host
                Write-Host "Speculation control settings for CVE-2017-5715 [branch target injection]" -ForegroundColor Cyan

                if ($manufacturer -eq "AuthenticAMD") {
                    Write-Host "AMD CPU detected: mitigations for branch target injection on AMD CPUs have additional registry settings for this mitigation, please refer to FAQ #15 at https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV180002" -ForegroundColor Cyan
                }

                Write-Host
            }

            $btiHardwarePresent = $false
            $btiWindowsSupportPresent = $false
            $btiWindowsSupportEnabled = $false
            $btiDisabledBySystemPolicy = $false
            $btiDisabledByNoHardwareSupport = $false

            $ssbdAvailable = $false
            $ssbdHardwarePresent = $false
            $ssbdSystemWide = $false
            $ssbdRequired = $null

            $mdsHardwareProtected = $null
            $mdsMbClearEnabled = $false
            $mdsMbClearReported = $false

            [System.UInt32]$systemInformationClass = 201
            [System.UInt32]$systemInformationLength = 4

            $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

            if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
                $null # fallthrough
            }
            elseif ($retval -ne 0) {
                throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
            }
            else {
                $tivs = @{
                    scfBpbEnabled                               = 0x01
                    scfBpbDisabledSystemPolicy                  = 0x02
                    scfBpbDisabledNoHardwareSupport             = 0x04
                    scfHwReg1Enumerated                         = 0x08
                    scfHwReg2Enumerated                         = 0x10
                    scfHwMode1Present                           = 0x20
                    scfHwMode2Present                           = 0x40
                    scfSmepPresent                              = 0x80
                    scfSsbdAvailable                            = 0x100
                    scfSsbdSupported                            = 0x200
                    scfSsbdSystemWide                           = 0x400
                    scfSsbdRequired                             = 0x1000
                    scfSpecCtrlRetpolineEnabled                 = 0x4000
                    scfSpecCtrlImportOptimizationEnabled        = 0x8000
                    scfEnhancedIbrs                             = 0x10000
                    scfHvL1tfStatusAvailable                    = 0x20000
                    scfHvL1tfProcessorNotAffected               = 0x40000
                    scfHvL1tfMigitationEnabled                  = 0x80000
                    scfHvL1tfMigitationNotEnabled_Hardware      = 0x100000
                    scfHvL1tfMigitationNotEnabled_LoadOption    = 0x200000
                    scfHvL1tfMigitationNotEnabled_CoreScheduler = 0x400000
                    scfEnhancedIbrsReported                     = 0x800000
                    scfMdsHardwareProtected                     = 0x1000000
                    scfMbClearEnabled                           = 0x2000000
                    scfMbClearReported                          = 0x4000000
                }
                $btivariables = @(); $tivs.Keys | ForEach-Object { $btivariables += [PSCustomObject]@{ Name = $_; Value = [System.UInt32]$tivs["$_"] } }
                [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)
                $btiHardwarePresent = ((($flags -band $tivs['scfHwReg1Enumerated']) -ne 0) -or (($flags -band $tivs['scfHwReg2Enumerated'])))
                $btiWindowsSupportPresent = $true
                $btiWindowsSupportEnabled = (($flags -band $tivs['scfBpbEnabled']) -ne 0)
                $btiRetpolineEnabled = (($flags -band $tivs['scfSpecCtrlRetpolineEnabled']) -ne 0)
                $btiImportOptimizationEnabled = (($flags -band $tivs['scfSpecCtrlImportOptimizationEnabled']) -ne 0)

                $mdsHardwareProtected = (($flags -band $tivs['scfMdsHardwareProtected']) -ne 0)
                $mdsMbClearEnabled = (($flags -band $tivs['scfMbClearEnabled']) -ne 0)
                $mdsMbClearReported = (($flags -band $tivs['scfMbClearReported']) -ne 0)

                if (($manufacturer -eq "AuthenticAMD") -or
                ($isArmCpu -eq $true)) {
                    $mdsHardwareProtected = $true
                }

                if ($btiWindowsSupportEnabled -eq $false) {
                    $btiDisabledBySystemPolicy = (($flags -band $tivs['scfBpbDisabledSystemPolicy']) -ne 0)
                    $btiDisabledByNoHardwareSupport = (($flags -band $tivs['scfBpbDisabledNoHardwareSupport']) -ne 0)
                }

                $ssbdAvailable = (($flags -band $tivs['scfSsbdAvailable']) -ne 0)

                if ($ssbdAvailable -eq $true) {
                    $ssbdHardwarePresent = (($flags -band $tivs['scfSsbdSupported']) -ne 0)
                    $ssbdSystemWide = (($flags -band $tivs['scfSsbdSystemWide']) -ne 0)
                    $ssbdRequired = (($flags -band $tivs['scfSsbdRequired']) -ne 0)
                }

                if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                    $btivariables | ForEach-Object { Write-Verbose "$($_.Name + ' ' * $($([int]$($btivariables | ForEach-Object { $_.Name.length } | Sort-Object -Descending)[0] + 2) - $_.Name.Length) + ': ' + $(($flags -band $tivs[$_.Value]) -ne 0))" -Verbose }
                }
            }

            if ($Quiet -ne $true) {
                Write-Host "Hardware support for branch target injection mitigation is present:"($btiHardwarePresent)
                Write-Host "Windows OS support for branch target injection mitigation is present:"($btiWindowsSupportPresent)
                Write-Host "Windows OS support for branch target injection mitigation is enabled:"($btiWindowsSupportEnabled)

                if ($btiWindowsSupportPresent -eq $true -and $btiWindowsSupportEnabled -eq $false) {
                    Write-Host "Windows OS support for branch target injection mitigation is disabled by system policy:"($btiDisabledBySystemPolicy)
                    Write-Host "Windows OS support for branch target injection mitigation is disabled by absence of hardware support:"($btiDisabledByNoHardwareSupport)
                }
            }

            $object | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $btiHardwarePresent
            $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $btiWindowsSupportPresent
            $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $btiWindowsSupportEnabled
            $object | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $btiDisabledBySystemPolicy
            $object | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $btiDisabledByNoHardwareSupport
            $object | Add-Member -MemberType NoteProperty -Name BTIKernelRetpolineEnabled -Value $btiRetpolineEnabled
            $object | Add-Member -MemberType NoteProperty -Name BTIKernelImportOptimizationEnabled -Value $btiImportOptimizationEnabled

            #
            # Query kernel VA shadow information.
            #

            if ($Quiet -ne $true) {
                Write-Host
                Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
                Write-Host
            }

            $kvaShadowRequired = $true
            $kvaShadowPresent = $false
            $kvaShadowEnabled = $false
            $kvaShadowPcidEnabled = $false

            $l1tfRequired = $true
            $l1tfMitigationPresent = $false
            $l1tfMitigationEnabled = $false
            $l1tfFlushSupported = $false
            $l1tfInvalidPteBit = $null

            [System.UInt32]$systemInformationClass = 196
            [System.UInt32]$systemInformationLength = 4

            $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

            if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
            }
            elseif ($retval -ne 0) {
                throw (("Querying kernel VA shadow information failed with error {0:X8}" -f $retval))
            }
            else {

                [System.UInt32]$kvaShadowEnabledFlag = 0x01
                [System.UInt32]$kvaShadowUserGlobalFlag = 0x02
                [System.UInt32]$kvaShadowPcidFlag = 0x04
                [System.UInt32]$kvaShadowInvpcidFlag = 0x08
                [System.UInt32]$kvaShadowRequiredFlag = 0x10
                [System.UInt32]$kvaShadowRequiredAvailableFlag = 0x20

                [System.UInt32]$l1tfInvalidPteBitMask = 0xfc0
                [System.UInt32]$l1tfInvalidPteBitShift = 6
                [System.UInt32]$l1tfFlushSupportedFlag = 0x1000
                [System.UInt32]$l1tfMitigationPresentFlag = 0x2000

                [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

                $kvaShadowPresent = $true
                $kvaShadowEnabled = (($flags -band $kvaShadowEnabledFlag) -ne 0)
                $kvaShadowPcidEnabled = ((($flags -band $kvaShadowPcidFlag) -ne 0) -and (($flags -band $kvaShadowInvpcidFlag) -ne 0))

                if (($flags -band $kvaShadowRequiredAvailableFlag) -ne 0) {
                    $kvaShadowRequired = (($flags -band $kvaShadowRequiredFlag) -ne 0)
                }
                else {

                    if ($manufacturer -eq "AuthenticAMD") {
                        $kvaShadowRequired = $false
                    }
                    elseif ($manufacturer -eq "GenuineIntel") {
                        $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
                        $result = $regex.Match($cpu.Description)

                        if ($result.Success) {
                            $family = [System.UInt32]$result.Groups[1].Value
                            $model = [System.UInt32]$result.Groups[2].Value
                            Set-Variable -Name stepping -Visibility Public -Value [System.UInt32]$result.Groups[3].Value

                            if ($($family -eq 0x6) -and $(
                                    ($model -eq 0x1c) -or
                                    ($model -eq 0x26) -or
                                    ($model -eq 0x27) -or
                                    ($model -eq 0x36) -or
                                    ($model -eq 0x35)
                                )
                            ) {
                                $kvaShadowRequired = $false
                            }
                        }
                    }
                    else {
                        throw ("Unsupported processor manufacturer: {0}" -f $manufacturer)
                    }
                }

                if ($isArmCpu -eq $true) {
                    $l1tfRequired = $false
                }
                else {
                    $l1tfRequired = $kvaShadowRequired
                }

                $l1tfInvalidPteBit = [math]::Floor(($flags -band $l1tfInvalidPteBitMask) * [math]::Pow(2, - $l1tfInvalidPteBitShift))

                $l1tfMitigationEnabled = (($l1tfInvalidPteBit -ne 0) -and ($kvaShadowEnabled -eq $true))
                $l1tfFlushSupported = (($flags -band $l1tfFlushSupportedFlag) -ne 0)

                if (($flags -band $l1tfMitigationPresentFlag) -or
                ($l1tfMitigationEnabled -eq $true) -or
                ($l1tfFlushSupported -eq $true)) {
                    $l1tfMitigationPresent = $true
                }

                if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                    Write-Verbose "KvaShadowEnabled             : $(($flags -band $kvaShadowEnabledFlag) -ne 0)"
                    Write-Verbose "KvaShadowUserGlobal          : $(($flags -band $kvaShadowUserGlobalFlag) -ne 0)"
                    Write-Verbose "KvaShadowPcid                : $(($flags -band $kvaShadowPcidFlag) -ne 0)"
                    Write-Verbose "KvaShadowInvpcid             : $(($flags -band $kvaShadowInvpcidFlag) -ne 0)"
                    Write-Verbose "KvaShadowRequired            : $kvaShadowRequired"
                    Write-Verbose "KvaShadowRequiredAvailable   : $(($flags -band $kvaShadowRequiredAvailableFlag) -ne 0)"
                    Write-Verbose "L1tfRequired                 : $l1tfRequired"
                    Write-Verbose "L1tfInvalidPteBit            : $l1tfInvalidPteBit"
                    Write-Verbose "L1tfFlushSupported           : $l1tfFlushSupported"
                }
            }

            if ($Quiet -ne $true) {
                Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

                if ($kvaShadowRequired) {

                    Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent
                    Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled

                    if ($kvaShadowEnabled) {
                        Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]"
                    }
                }
            }

            $object | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $kvaShadowRequired
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $kvaShadowPresent
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $kvaShadowEnabled
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $kvaShadowPcidEnabled

            #
            # Speculation Control Settings for CVE-2018-3639 (Speculative Store Bypass)
            #

            if ($Quiet -ne $true) {
                Write-Host
                Write-Host "Speculation control settings for CVE-2018-3639 [speculative store bypass]" -ForegroundColor Cyan
                Write-Host
            }

            if ($Quiet -ne $true) {
                if (($ssbdAvailable -eq $true)) {
                    Write-Host "Hardware is vulnerable to speculative store bypass:"$ssbdRequired
                    if ($ssbdRequired -eq $true) {
                        Write-Host "Hardware support for speculative store bypass disable is present:"$ssbdHardwarePresent
                        Write-Host "Windows OS support for speculative store bypass disable is present:"$ssbdAvailable
                        Write-Host "Windows OS support for speculative store bypass disable is enabled system-wide:"$ssbdSystemWide
                    }
                }
                else {
                    Write-Host "Windows OS support for speculative store bypass disable is present:"$ssbdAvailable
                }
            }

            $object | Add-Member -MemberType NoteProperty -Name SSBDWindowsSupportPresent -Value $ssbdAvailable
            $object | Add-Member -MemberType NoteProperty -Name SSBDHardwareVulnerable -Value $ssbdRequired
            $object | Add-Member -MemberType NoteProperty -Name SSBDHardwarePresent -Value $ssbdHardwarePresent
            $object | Add-Member -MemberType NoteProperty -Name SSBDWindowsSupportEnabledSystemWide -Value $ssbdSystemWide


            #
            # Speculation Control Settings for CVE-2018-3620 (L1 Terminal Fault)
            #

            if ($Quiet -ne $true) {
                Write-Host
                Write-Host "Speculation control settings for CVE-2018-3620 [L1 terminal fault]" -ForegroundColor Cyan
                Write-Host
            }

            if ($Quiet -ne $true) {
                Write-Host "Hardware is vulnerable to L1 terminal fault:"$l1tfRequired

                if ($l1tfRequired -eq $true) {
                    Write-Host "Windows OS support for L1 terminal fault mitigation is present:"$l1tfMitigationPresent
                    Write-Host "Windows OS support for L1 terminal fault mitigation is enabled:"$l1tfMitigationEnabled
                }
            }

            $object | Add-Member -MemberType NoteProperty -Name L1TFHardwareVulnerable -Value $l1tfRequired
            $object | Add-Member -MemberType NoteProperty -Name L1TFWindowsSupportPresent -Value $l1tfMitigationPresent
            $object | Add-Member -MemberType NoteProperty -Name L1TFWindowsSupportEnabled -Value $l1tfMitigationEnabled
            $object | Add-Member -MemberType NoteProperty -Name L1TFInvalidPteBit -Value $l1tfInvalidPteBit
            $object | Add-Member -MemberType NoteProperty -Name L1DFlushSupported -Value $l1tfFlushSupported

            #
            # Speculation control settings for MDS [microarchitectural data sampling]
            #

            if ($Quiet -ne $true) {
                Write-Host
                Write-Host "Speculation control settings for MDS [microarchitectural data sampling]" -ForegroundColor Cyan
                Write-Host
            }

            if ($Quiet -ne $true) {

                Write-Host "Windows OS support for MDS mitigation is present:"$mdsMbClearReported

                if ($mdsMbClearReported -eq $true) {
                    Write-Host "Hardware is vulnerable to MDS:"($mdsHardwareProtected -ne $true)

                    if ($mdsHardwareProtected -eq $false) {
                        Write-Host "Windows OS support for MDS mitigation is enabled:"$mdsMbClearEnabled
                    }
                }
            }

            $object | Add-Member -MemberType NoteProperty -Name MDSWindowsSupportPresent -Value $mdsMbClearReported

            if ($mdsMbClearReported -eq $true) {
                $object | Add-Member -MemberType NoteProperty -Name MDSHardwareVulnerable -Value ($mdsHardwareProtected -ne $true)
                $object | Add-Member -MemberType NoteProperty -Name MDSWindowsSupportEnabled -Value $mdsMbClearEnabled
            }

            #
            # Provide guidance as appropriate.
            #

            $actions = @()

            if ($btiHardwarePresent -eq $false) {
                $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
            }

            if (($btiWindowsSupportPresent -eq $false) -or
            ($kvaShadowPresent -eq $false) -or
            ($ssbdAvailable -eq $false) -or
            ($l1tfMitigationPresent -eq $false) -or
            ($mdsMbClearReported -eq $false)) {
                $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
            }

            if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or
            ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false) -or
            ($l1tfRequired -eq $true -and $l1tfMitigationEnabled -eq $false) -or
            ($mdsMbClearReported -eq $true -and $mdsHardwareProtected -eq $false -and $mdsMbClearEnabled -eq $false)) {
                $guidanceUri = ""
                $guidanceType = ""
                $os = Get-CimInstance Win32_OperatingSystem

                if ($os.ProductType -eq 1) {
                    # Workstation
                    $guidanceUri = "https://support.microsoft.com/help/4073119"
                    $guidanceType = "Client"
                }
                else {
                    # Server/DC
                    $guidanceUri = "https://support.microsoft.com/help/4072698"
                    $guidanceType = "Server"
                }

                $actions += "Follow the guidance for enabling Windows $guidanceType support for speculation control mitigations described in $guidanceUri"
            }

            if ($Quiet -ne $true -and $actions.Length -gt 0) {

                Write-Host
                Write-Host "Suggested actions" -ForegroundColor Cyan
                Write-Host

                foreach ($action in $actions) {
                    Write-Host " *" $action
                }
            }
            return $object
        }
        finally {
            if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
            }

            if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
            }
        }
    }
}
