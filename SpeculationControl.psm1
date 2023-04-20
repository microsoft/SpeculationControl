function Get-SpeculationControlSettings {
  <#

  .SYNOPSIS
  This function queries the speculation control settings for the system.

  .DESCRIPTION
  This function queries the speculation control settings for the system.

  .PARAMETER Quiet
  This parameter suppresses host output that is displayed by default.
  
  #>

  [CmdletBinding()]
  param (
    [switch]$Quiet
  )
  
  process {

    $NtQSIDefinition = @'
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);
'@
    
    $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru

    $SYSTEM_SPECULATION_CONTROL_INFORMATION_LENGTH = 8
    
    [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SYSTEM_SPECULATION_CONTROL_INFORMATION_LENGTH)
    [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

    $object = New-Object -TypeName PSObject

    try {
        if ($PSVersionTable.PSVersion -lt [System.Version]("3.0.0.0")) {
            $cpu = Get-WmiObject Win32_Processor
        }
        else {
            $cpu = Get-CimInstance Win32_Processor
        }

        if ($cpu -is [array]) {
            $cpu = $cpu[0]
        }

        $PROCESSOR_ARCHITECTURE_ARM64 = 12
        $PROCESSOR_ARCHITECTURE_ARM   = 5

        $manufacturer = $cpu.Manufacturer
        $processorArchitecture = $cpu.Architecture

        $isArmCpu = ($processorArchitecture -eq $PROCESSOR_ARCHITECTURE_ARM) -or ($processorArchitecture -eq $PROCESSOR_ARCHITECTURE_ARM64)

        if ($manufacturer -eq "GenuineIntel") {
            $intelFmsRegex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
            $intelFmsRegexResult = $intelFmsRegex.Match($cpu.Description)

            if ($intelFmsRegexResult.Success) {
                $intelCpuFamily = [System.UInt32]$intelFmsRegexResult.Groups[1].Value
                $intelCpuModel = [System.UInt32]$intelFmsRegexResult.Groups[2].Value
                $intelCpuStepping = [System.UInt32]$intelFmsRegexResult.Groups[3].Value
            } else {
                throw ("Unsupported processor: {0}" -f $cpu.Description) 
            }
        }
 
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

        $sbdrSsdpHardwareProtected = $null
        $fbsdpHardwareProtected = $null
        $psdpHardwareProtected = $null
        $fbClearEnabled = $false
        $fbClearReported = $false
    
        [System.UInt32]$systemInformationClass = 201
        [System.UInt32]$systemInformationLength = $SYSTEM_SPECULATION_CONTROL_INFORMATION_LENGTH

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        [System.UInt32]$returnLength = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
            # fallthrough
        }
        elseif ($retval -ne 0) {
            throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$scfBpbEnabled = 0x01
            [System.UInt32]$scfBpbDisabledSystemPolicy = 0x02
            [System.UInt32]$scfBpbDisabledNoHardwareSupport = 0x04
            [System.UInt32]$scfSpecCtrlEnumerated = 0x08
            [System.UInt32]$scfSpecCmdEnumerated = 0x10
            [System.UInt32]$scfIbrsPresent = 0x20
            [System.UInt32]$scfStibpPresent = 0x40
            [System.UInt32]$scfSmepPresent = 0x80
            [System.UInt32]$scfSsbdAvailable = 0x100
            [System.UInt32]$scfSsbdSupported = 0x200
            [System.UInt32]$scfSsbdSystemWide = 0x400
            [System.UInt32]$scfSsbdRequired = 0x1000
            [System.UInt32]$scfSpecCtrlRetpolineEnabled = 0x4000
            [System.UInt32]$scfSpecCtrlImportOptimizationEnabled = 0x8000
            [System.UInt32]$scfEnhancedIbrs = 0x10000
            [System.UInt32]$scfHvL1tfStatusAvailable = 0x20000
            [System.UInt32]$scfHvL1tfProcessorNotAffected = 0x40000
            [System.UInt32]$scfHvL1tfMigitationEnabled = 0x80000
            [System.UInt32]$scfHvL1tfMigitationNotEnabled_Hardware = 0x100000
            [System.UInt32]$scfHvL1tfMigitationNotEnabled_LoadOption = 0x200000
            [System.UInt32]$scfHvL1tfMigitationNotEnabled_CoreScheduler = 0x400000
            [System.UInt32]$scfEnhancedIbrsReported = 0x800000
            [System.UInt32]$scfMdsHardwareProtected = 0x1000000
            [System.UInt32]$scfMbClearEnabled = 0x2000000
            [System.UInt32]$scfMbClearReported = 0x4000000

            [System.UInt32]$scf2SbdrSsdpHardwareProtected = 0x01
            [System.UInt32]$scf2FbsdpHardwareProtected =  0x02
            [System.UInt32]$scf2PsdpHardwareProtected =  0x04
            [System.UInt32]$scf2FbClearEnabled =  0x08
            [System.UInt32]$scf2FbClearReported =  0x10

            [System.UInt32]$scf2RdclHardwareProtectedReported =  0x800
            [System.UInt32]$scf2RdclHardwareProtected =  0x1000

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)
            
            if ($returnLength -gt 4) {
                [System.UInt32]$flags2 = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr, 4)
            }
            else {
                [System.UInt32]$flags2 = 0
            }
            
            $btiHardwarePresent = ((($flags -band $scfSpecCtrlEnumerated) -ne 0) -or (($flags -band $scfSpecCmdEnumerated)))
            $btiWindowsSupportPresent = $true
            $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)
            $btiRetpolineEnabled = (($flags -band $scfSpecCtrlRetpolineEnabled) -ne 0)
            $btiImportOptimizationEnabled = (($flags -band $scfSpecCtrlImportOptimizationEnabled) -ne 0)

            $mdsHardwareProtected = (($flags -band $scfMdsHardwareProtected) -ne 0)
            $mdsMbClearEnabled = (($flags -band $scfMbClearEnabled) -ne 0)
            $mdsMbClearReported = (($flags -band $scfMbClearReported) -ne 0)

            if (($manufacturer -eq "AuthenticAMD") -or
                ($isArmCpu -eq $true)) {
                $mdsHardwareProtected = $true
            }

            if ($btiWindowsSupportEnabled -eq $false) {
                $btiDisabledBySystemPolicy = (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                $btiDisabledByNoHardwareSupport = (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
            }
            
            $ssbdAvailable = (($flags -band $scfSsbdAvailable) -ne 0)

            if ($ssbdAvailable -eq $true) {
                $ssbdHardwarePresent = (($flags -band $scfSsbdSupported) -ne 0)
                $ssbdSystemWide = (($flags -band $scfSsbdSystemWide) -ne 0)
                $ssbdRequired = (($flags -band $scfSsbdRequired) -ne 0)
            }

            $sbdrSsdpHardwareProtected = (($flags2 -band $scf2SbdrSsdpHardwareProtected) -ne 0)
            $fbsdpHardwareProtected = (($flags2 -band $scf2FbsdpHardwareProtected) -ne 0)
            $psdpHardwareProtected = (($flags2 -band $scf2PsdpHardwareProtected) -ne 0)
            $fbClearEnabled = (($flags2 -band $scf2FbClearEnabled) -ne 0)
            $fbClearReported = (($flags2 -band $scf2FbClearReported) -ne 0)

            $rdclHardwareProtectedReported = (($flags2 -band $scf2RdclHardwareProtectedReported) -ne 0)
            $rdclHardwareProtected = (($flags2 -band $scf2RdclHardwareProtected) -ne 0)

            if (($manufacturer -eq "AuthenticAMD") -or
                ($isArmCpu -eq $true)) {
                $sbdrSsdpHardwareProtected = $true
                $fbsdpHardwareProtected = $true
                $psdpHardwareProtected = $true
            }

            $hvL1tfStatusAvailable = (($flags -band $scfHvL1tfStatusAvailable) -ne 0)
            $hvL1tfProcessorNotAffected = (($flags -band $scfHvL1tfProcessorNotAffected) -ne 0)

            if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                Write-Verbose "BpbEnabled                        : $(($flags -band $scfBpbEnabled) -ne 0)"
                Write-Verbose "BpbDisabledSystemPolicy           : $(($flags -band $scfBpbDisabledSystemPolicy) -ne 0)"
                Write-Verbose "BpbDisabledNoHardwareSupport      : $(($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)"
                Write-Verbose "SpecCtrlEnumerated                : $(($flags -band $scfSpecCtrlEnumerated) -ne 0)"
                Write-Verbose "SpecCmdEnumerated                 : $(($flags -band $scfSpecCmdEnumerated) -ne 0)"
                Write-Verbose "IbrsPresent                       : $(($flags -band $scfIbrsPresent) -ne 0)"
                Write-Verbose "StibpPresent                      : $(($flags -band $scfStibpPresent) -ne 0)"
                Write-Verbose "SmepPresent                       : $(($flags -band $scfSmepPresent) -ne 0)"
                Write-Verbose "SsbdAvailable                     : $(($flags -band $scfSsbdAvailable) -ne 0)"
                Write-Verbose "SsbdSupported                     : $(($flags -band $scfSsbdSupported) -ne 0)"
                Write-Verbose "SsbdSystemWide                    : $(($flags -band $scfSsbdSystemWide) -ne 0)"
                Write-Verbose "SsbdRequired                      : $(($flags -band $scfSsbdRequired) -ne 0)"
                Write-Verbose "SpecCtrlRetpolineEnabled          : $(($flags -band $scfSpecCtrlRetpolineEnabled) -ne 0)"
                Write-Verbose "SpecCtrlImportOptimizationEnabled : $(($flags -band $scfSpecCtrlImportOptimizationEnabled) -ne 0)"
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

        $kvaShadowRequired = $true
        $kvaShadowPresent = $false
        $kvaShadowEnabled = $false
        $kvaShadowPcidEnabled = $false

        # CPUs Vulnerable to L1TF (Family, Model, Stepping)

        $l1tfVulnerableCpus = [tuple]::Create(6, 26, 4), [tuple]::Create(6, 26, 5), [tuple]::Create(6, 30, 4), [tuple]::Create(6, 30, 5), 
                                [tuple]::Create(6, 37, 2), [tuple]::Create(6, 37, 5), [tuple]::Create(6, 42, 7), [tuple]::Create(6, 44, 2), 
                                [tuple]::Create(6, 45, 6), [tuple]::Create(6, 45, 7), [tuple]::Create(6, 46, 6), [tuple]::Create(6, 47, 2), 
                                [tuple]::Create(6, 58, 9), [tuple]::Create(6, 60, 3), [tuple]::Create(6, 61, 4), [tuple]::Create(6, 62, 4), 
                                [tuple]::Create(6, 62, 7), [tuple]::Create(6, 63, 2), [tuple]::Create(6, 63, 4), [tuple]::Create(6, 69, 1), 
                                [tuple]::Create(6, 70, 1), [tuple]::Create(6, 78, 3), [tuple]::Create(6, 79, 1), [tuple]::Create(7, 69, 1), 
                                [tuple]::Create(6, 85, 3), [tuple]::Create(6, 85, 4), [tuple]::Create(6, 86, 2), [tuple]::Create(6, 86, 3), 
                                [tuple]::Create(6, 86, 4), [tuple]::Create(6, 86, 5), [tuple]::Create(6, 94, 3), [tuple]::Create(6, 102, 3), 
                                [tuple]::Create(6, 142, 9), [tuple]::Create(6, 142, 10), [tuple]::Create(6, 142, 11), [tuple]::Create(6, 158, 9), 
                                [tuple]::Create(6, 158, 10), [tuple]::Create(6, 158, 11), [tuple]::Create(6, 158, 12)

        
        if ($manufacturer -eq "GenuineIntel") {
            $l1tfRequired = $true

            if (($rdclHardwareProtectedReported-eq $true) -and ($rdclHardwareProtected -eq $true)) {
                $l1tfRequired = $false
            } 
            elseif (($hvL1tfStatusAvailable -eq $true) -and ($hvL1tfProcessorNotAffected -eq $true)) {
                $l1tfRequired = $false
            } 
            else {
                $fmsTuple = [tuple]::Create([int]$intelCpuFamily, [int]$intelCpuModel, [int]$intelCpuStepping)
                
                if ($l1tfVulnerableCpus.Contains($fmsTuple) -eq $false) {
                    $l1tfRequired = $false
                }
            }
        } 
        else {
            $l1tfRequired = $false
        }

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
                    if (($intelCpuFamily -eq 0x6) -and 
                        (($intelCpuModel -eq 0x1c) -or
                         ($intelCpuModel -eq 0x26) -or
                         ($intelCpuModel -eq 0x27) -or
                         ($intelCpuModel -eq 0x36) -or
                         ($intelCpuModel -eq 0x35))) {

                        $kvaShadowRequired = $false
                    }
                }
                else {
                    throw ("Unsupported processor manufacturer: {0}" -f $manufacturer)
                }
            }

            $l1tfInvalidPteBit = [math]::Floor(($flags -band $l1tfInvalidPteBitMask) * [math]::Pow(2,-$l1tfInvalidPteBitShift))

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
            Write-Host
            Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
            Write-Host 

            if ($rdclHardwareProtectedReported) {
                Write-Host "Hardware is vulnerable to rogue data cache load:" ($rdclHardwareProtected -ne $true)

                if ($rdclHardwareProtected -ne $true) {
                    Write-Host "Windows OS support for rogue data cache load mitigation is present:" $kvaShadowPresent
                    Write-Host "Windows OS support for rogue data cache load mitigation is enabled:" $kvaShadowEnabled
                }

                Write-Host
            }

            Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

            if ($kvaShadowRequired) {

                Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent
                Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled

                if ($kvaShadowEnabled) {
                    Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]"
                }
            }
        }

        $object | Add-Member -MemberType NoteProperty -Name RdclHardwareProtectedReported -Value $rdclHardwareProtectedReported
        if ($rdclHardwareProtectedReported) {
            $object | Add-Member -MemberType NoteProperty -Name RdclHardwareProtected -Value $rdclHardwareProtected
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
        $object | Add-Member -MemberType NoteProperty -Name HvL1tfStatusAvailable -Value $hvL1tfStatusAvailable
        $object | Add-Member -MemberType NoteProperty -Name HvL1tfProcessorNotAffected -Value $hvL1tfProcessorNotAffected

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
        # Speculation control settings for SBDR [shared buffers data read]
        #

        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for SBDR [shared buffers data read]" -ForegroundColor Cyan
            Write-Host
            Write-Host "Windows OS support for SBDR mitigation is present:"$fbClearReported

            if ($fbClearReported -eq $true) {
                Write-Host "Hardware is vulnerable to SBDR:"($sbdrSsdpHardwareProtected -ne $true)
                
                if ($sbdrSsdpHardwareProtected -eq $false) {
                    Write-Host "Windows OS support for SBDR mitigation is enabled:"$fbClearEnabled
                }
            }
        }

        #
        # Speculation control settings for FBSDP [fill buffer stale data propagator]
        #

        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for FBSDP [fill buffer stale data propagator]" -ForegroundColor Cyan
            Write-Host
            Write-Host "Windows OS support for FBSDP mitigation is present:"$fbClearReported

            if ($fbClearReported -eq $true) {
                Write-Host "Hardware is vulnerable to FBSDP:"($fbsdpHardwareProtected -ne $true)
                
                if ($fbsdpHardwareProtected -eq $false) {
                    Write-Host "Windows OS support for FBSDP mitigation is enabled:"$fbClearEnabled
                }
            }
        }

        #
        # Speculation control settings for PSDP [primary stale data propagator]
        #

        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for PSDP [primary stale data propagator]" -ForegroundColor Cyan
            Write-Host
            Write-Host "Windows OS support for PSDP mitigation is present:"$fbClearReported

            if ($fbClearReported -eq $true) {
                Write-Host "Hardware is vulnerable to PSDP:"($psdpHardwareProtected -ne $true)
                
                if ($psdpHardwareProtected -eq $false) {
                    Write-Host "Windows OS support for PSDP mitigation is enabled:"$fbClearEnabled
                }
            }
        }

        $object | Add-Member -MemberType NoteProperty -Name FBClearWindowsSupportPresent -Value $fbClearReported
        
        if ($fbClearReported -eq $true) {
            $object | Add-Member -MemberType NoteProperty -Name SBDRSSDPHardwareVulnerable -Value ($sbdrSsdpHardwareProtected -ne $true)
            $object | Add-Member -MemberType NoteProperty -Name FBSDPHardwareVulnerable -Value ($fbsdpHardwareProtected -ne $true)
            $object | Add-Member -MemberType NoteProperty -Name PSDPHardwareVulnerable -Value ($psdpHardwareProtected -ne $true)
            $object | Add-Member -MemberType NoteProperty -Name FBClearWindowsSupportEnabled -Value $fbClearEnabled
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
            ($mdsMbClearReported -eq $false) -or
            ($fbClearReported -eq $false) -or
            ($rdclHardwareProtectedReported -eq $false)) {
            $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
        }

        if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or 
            ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false) -or
            ($l1tfRequired -eq $true -and $l1tfMitigationEnabled -eq $false) -or
            ($mdsMbClearReported -eq $true -and $mdsHardwareProtected -eq $false -and $mdsMbClearEnabled -eq $false) -or 
            ($fbClearReported -eq $true -and $sbdrSsdpHardwareProtected -eq $false -and $fbClearEnabled -eq $false) -or
            ($fbClearReported -eq $true -and $fbsdpHardwareProtected -eq $false -and $fbClearEnabled -eq $false) -or
            ($fbClearReported -eq $true -and $psdpHardwareProtected -eq $false -and $fbClearEnabled -eq $false)) {
            $guidanceUri = ""
            $guidanceType = ""

            if ($PSVersionTable.PSVersion -lt [System.Version]("3.0.0.0")) {
                $os = Get-WmiObject Win32_OperatingSystem
            }
            else {
                $os = Get-CimInstance Win32_OperatingSystem
            }

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
    finally
    {
        if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
        }
 
        if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
        }
    }    
  }
}

# SIG # Begin signature block
# MIInlwYJKoZIhvcNAQcCoIIniDCCJ4QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALTbSatsqigojy
# i3tNQfQx/jeKXYrXZOp/aQ6y7B2sRaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXcwghlzAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID3oe6VcCM82rRVVJjjDSErV
# Es3ICUNWHJ+HoD55u7MVMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAelUvXZwrLAxPmFX7O0uxRuMnhqmWl0ksgyqU55tKt32XGOpernoce
# +9BrWbjlRPlWsoZLxFfI4OdiTXJxCJ/JJjyt1nHz5Zzrd7fTFNzLYNvysaVRWB/u
# aNeCmpkRZU9JmdsuHZ204o+IMYyydxLTxZiDxbnhPx5AlBdbevtbmPtTIJjiMw03
# IT+W6cG49gkLfdm6rdsTT8Y7+33bUB0pkDht2wEANp33DuzMUFqdUQL+OvVg71Br
# NuqfezCfeHqIl9SXv1T+16r6SBPnfdA9gAVzKyBLy/fPGUWuR5AoXQnuK9HlSsHI
# o3/EHnCqlQiBfTNaQ8oPvqoQzptvuMaPoYIW/zCCFvsGCisGAQQBgjcDAwExghbr
# MIIW5wYJKoZIhvcNAQcCoIIW2DCCFtQCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBZhWBwf3WQIVA10Zap74q2TcdwVNcys/XT0VkuPkPV2AgZkN+jD
# FsMYEzIwMjMwNDEzMTk1NTEwLjAxNlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
# RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVjCCBwwwggT0oAMCAQICEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTM3WhcNMjQwMjAyMTkwMTM3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC5y51+KE+DJFbCeci4kKpzdMK0WTRc6KYVwqNT1tLp
# YWeDaX4WsiJ3SY9nspazoTCPbVf5mQaQzrH6jMeWY22cdJDjymMgV2UpciiHt9Kj
# jUDifS1AiXCGzy4hgihynvbHAMEcpJnEZoRr/TvTuLI7D5pdlc1xPGA2JEQBJv22
# GUtkzvmZ8kiAFW9SZ0tlz5c5RjDP/y6XsgTO080fhyfwKfS0mEgV+nad62vwZg2i
# LIirG54bv6xK3bFeXv+KBzlwc9mdaF+X09oHj5K62sDzMCHNUdOePhF9/EDhHeTg
# FFs90ajBB85/3ll5jEtMd/lrAHSepnE5j7K4ZaF/qGnlEZGi5z1t5Vm/3wzV6thr
# nlLVqFmAYNAnJxW0TLzZGWYp9Nhja42aU8ta2cPuwOWlWSFhAYq5Nae7BAqr1lNI
# T7RXZwfwlpYFglAwi5ZYzze8s+jchP9L/mNPahk5L2ewmDDALBFS1i3C2rz88m2+
# 3VXpWgbhZ3b8wCJ+AQk6QcXsBE+oj1e/bz6uKolnmaMsbPzh0/avKh7SXFhLPc9P
# kSsqhLT7Mmlg0BzFu/ZReJOTdaP+Zne26XPrPhedKXmDLQ8t6v4RWPPgb3oZxmAr
# Z30b65jKUdbAGd4i/1gVCPrIx1b/iwSmQRuumIk16ZzFQKYGKlntJzfmu/i62Qnj
# 9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFLVcL0mButLAsNOIklPiIrs1S+T1MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAMPWclLIQ8OpKCd+QWJ8hu14lvs2RkJtGPnIEaJPV/19Ma9RvkJbuTd5Kne7
# FSqib0tbKRw19Br9h/DSWJsSKb1hGNQ1wvjaggWq2n/uuX2CDrWiIHw8H7q8sSaN
# eRjFRRHxaMooLlDl3H3oHbV9pJyjYw6a+NjEZRHsCf7jnb2VA88upsQpGNw1Bv6n
# 6aRAfZd4xuyHkRAKRO5gCKYVOCe6LZk8UsS4GnEErnPYecqd4dQn2LilwpZ0KoXU
# A5U3yBcgfRHQV+UxwKDlNby/3RXDH+Y/doTYiB7W4Twz1g0Gfnvvo/GYDXpn5zaz
# 6Fgj72wlmGFEDxpJhpyuUvPtpT/no68RhERFBm224AWStX4z8n60J4Y2/QZ3vlji
# Uosynn/TGg6+I8F0HasPkL9T4Hyq3VsGpAtVnXAdHLT/oeEnFs6LYiAYlo4JgsZf
# bPPRUBPqZnYFNasmZwrpIO/utfumyAL4J/W3RHVpYKQIcm2li7IqN/tSh1FrN685
# /pXTVeSsBEcqsjttCgcUv6y6faWIkIGM3nWYNagSBQIS/AHeX5EVgAvRoiKxzlxN
# oZf9PwX6IBvP6PYYZW6bzmARBL24vNJ52hg/IRfFNuXB7AZ0DGohloqjNEGjDj06
# cv7kKCihUx/dlKqnFzZALQTTeXpz+8KGRjKoxersvB3g+ceqMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs0wggI2AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA384TULvGNTQKUgNdAGK5wBjuy7Kg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOfiZzYwIhgPMjAyMzA0MTMxOTM0MTRaGA8yMDIzMDQxNDE5MzQxNFow
# djA8BgorBgEEAYRZCgQBMS4wLDAKAgUA5+JnNgIBADAJAgEAAgEMAgH/MAcCAQAC
# AhHPMAoCBQDn47i2AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKg
# CjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEArN3UxTu3
# 9Sb0EZNz6ktWir+YKOHQ2DFil1J1fUVVvmhLe7yKsCbSmX/MVsm97oNITPlnl0Ei
# fPBnaQU+8NithFkma2t7bb2qBRuxy5YRG23qps6f4xRghmtwkrPBfWN/Z/5Lcnsa
# z3xSMsxCEvculNwC8O5bG5/+q8c52/OA6OcxggQNMIIECQIBATCBkzB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcj5sO5n7eprRgABAAAByDANBglg
# hkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqG
# SIb3DQEJBDEiBCAFt1TEQyQH8NbF46A45am9B1/jh8n6HKrcirwZhLfjcTCB+gYL
# KoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGIAmM/NP22jL8cOo3Kkry9BVuE3bwNP
# Z8R37D4bhANmMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAHI+bDuZ+3qa0YAAQAAAcgwIgQgZq7rQs8Ij+vivaJhmw9/GKz87ccLgFRp
# xSA64/YqWxcwDQYJKoZIhvcNAQELBQAEggIAoTG0EiQj0npQJtH8oUGxhheR9ScB
# IceFqtvBazS+GYqTaHungyZUxXTdxJv9Sn9Va2PlcAbbbH9lqvHTcacjJVImejeZ
# bDQQ0yK1rVy9ZBkOzq/PJNcnGkzPNQ5OJGCZJADzEfZEszbjJly+ugO8rtqWonHB
# +KI1Krp2hhXjENJvw1Yuxln7cCskCANm9ctsnRM40QLilPuRsv4ZlO7S8IHG/9Lw
# mMt8AKXLR5sPWNJIHQnhYr2XXqo1cHK9RWCKjobNV+nbKqnocdCLx6IP5IMl6oNh
# znQeJh6DmrIvJawk7Lljyl/SvQmmstScHDdUNXoolmmliWAskP5zEsBoZZWbzEyY
# hOIVhGoTwH4VBMh27+lKleoG4r5prus+8fIkC9FbgizEt4lVLD7zxBbiDqTEGTGi
# srTiX2x9OSViR+DMi99bHKzxK9d+CdpXo7tLvNwmpzk1ktRm6SRQBwhhGUVYYAMP
# 8wOqEJpLbBs46Q5stVa/97MxFifzeAkmQTvf/wv8loyjiXbp6lltKpXzl8RuQL5S
# OtSQJoP3buBcVz0am+s2IyTfWr9BSj4f5flK/a4gvffMU3hu+Tt/9y4lt2KkwbG2
# rvIubQsNcW9O68vyR2L+lS35rEqh8lWeGvfWvyqQPCPpeoAEK5zr7VG0/tL3tsR3
# ZMOMJZ8BOeufuBw=
# SIG # End signature block
