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
            [System.UInt32]$scf2BhbEnabled = 0x20
            [System.UInt32]$scf2BhbDisabledSystemPolicy = 0x40
            [System.UInt32]$scf2BhbDisabledNoHardwareSupport = 0x80
            [System.UInt32]$scf2BranchConfusionStatus =  0x300
            [System.UInt32]$scf2BranchConfusionReported = 0x400
            [System.UInt32]$scf2RdclHardwareProtectedReported =  0x800
            [System.UInt32]$scf2RdclHardwareProtected =  0x1000
            [System.UInt32]$scf2GdsReported = 0x2000
            [System.UInt32]$scf2GdsStatus = 0x1C000
            [System.UInt32]$scf2SrsoReported = 0x20000
            [System.UInt32]$scf2SrsoStatus = 0xC0000
            [System.UInt32]$scf2DivideByZeroReported = 0x100000
            [System.UInt32]$scf2DivideByZeroStatus = 0x200000
            [System.UInt32]$scf2RfdsReported = 0x400000
            [System.UInt32]$scf2RfdsStatus = 0x1800000

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
                Write-Verbose "EnhancedIbrs                      : $(($flags -band $scfEnhancedIbrs) -ne 0)"
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
        # Speculation control settings for BHB CVE-2022-0001, CVE-2022-0002
        #

        $bhbEnabled = ($flags2 -band $scf2BhbEnabled) -ne 0
        $bhbDisabledSystemPolicy = ($flags2 -band $scf2BhbDisabledSystemPolicy) -ne 0
        $bhbDisabledNoHardwareSupport = ($flags2 -band $scf2BhbDisabledNoHardwareSupport) -ne 0
                        
        $object | Add-Member -MemberType NoteProperty -Name BhbEnabled -Value $bhbEnabled
        $object | Add-Member -MemberType NoteProperty -Name BhbDisabledSystemPolicy -Value $bhbDisabledSystemPolicy
        $object | Add-Member -MemberType NoteProperty -Name BhbDisabledNoHardwareSupport -Value $bhbDisabledNoHardwareSupport
        
        #
        # Speculation control settings for BranchConfusion/Retbleed CVE-2022-23825
        #

        $branchConfusionReported = ($flags2 -band $scf2BranchConfusionReported) -ne 0

        $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_UNSUPPORTED = 0x0
        $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_DISABLED = 0x1
        $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_HARDWARE_IMMUNE = 0x2
        $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATED = 0x3
        
        if ($manufacturer -eq "AuthenticAMD") {
            $branchConfusionStatus = (($flags2 -band $scf2BranchConfusionStatus) -shr 8)
        }
        elseif ($manufacturer -eq "GenuineIntel") {
            if ($btiHardwarePresent -eq $false) {
                $branchConfusionStatus = $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_HARDWARE_IMMUNE
            }
            elseif ($btiWindowsSupportEnabled -eq $true) {
                $branchConfusionStatus = $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATED
            }
            else {
                $branchConfusionStatus = $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_DISABLED
            }
        }
                        
        $branchConfusionStatusString = switch ($branchConfusionStatus) {
            $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_UNSUPPORTED { "SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_UNSUPPORTED" }
            $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_DISABLED { "SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATION_DISABLED" }
            $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_HARDWARE_IMMUNE { "SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_HARDWARE_IMMUNE" }
            $SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATED { "SYSTEM_SPECULATION_CONTROL_BRANCH_CONFUSION_MITIGATED" }
            default { 'UNKNOWN_VALUE' }
        }

        $object | Add-Member -MemberType NoteProperty -Name BranchConfusionReported -Value $branchConfusionReported
        
        if ($branchConfusionReported -eq $true) {
            $object | Add-Member -MemberType NoteProperty -Name BranchConfusionStatus -Value $branchConfusionStatusString
        }

        #
        # Speculation control settings for GDS (Gather Data Sample) CVE-2022-40982
        #

        $gdsReported = ($flags2 -band $scf2GdsReported) -ne 0

        $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATION_UNSUPPORTED = 0x0
        $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATION_DISABLED = 0x1
        $SYSTEM_SPECULATION_CONTROL_GDS_HARDWARE_IMMUNE = 0x2
        $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATED = 0x3
        $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATED_AND_LOCKED = 0x4

        $gdsStatus = (($flags2 -band $scf2GdsStatus) -shr 14)

        $gdsStatusString = switch ($gdsStatus) {
            $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATION_UNSUPPORTED { "SYSTEM_SPECULATION_CONTROL_GDS_MITIGATION_UNSUPPORTED" }
            $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATION_DISABLED { "SYSTEM_SPECULATION_CONTROL_GDS_MITIGATION_DISABLED" }
            $SYSTEM_SPECULATION_CONTROL_GDS_HARDWARE_IMMUNE { "SYSTEM_SPECULATION_CONTROL_GDS_HARDWARE_IMMUNE" }
            $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATED { "SYSTEM_SPECULATION_CONTROL_GDS_MITIGATED" }
            $SYSTEM_SPECULATION_CONTROL_GDS_MITIGATED_AND_LOCKED { "SYSTEM_SPECULATION_CONTROL_GDS_MITIGATED_AND_LOCKED" }
            default { 'UNKNOWN_VALUE' }
        }

        $object | Add-Member -MemberType NoteProperty -Name GdsReported -Value $gdsReported

        if ($gdsReported -eq $true) {
            $object | Add-Member -MemberType NoteProperty -Name GdsStatus -Value $gdsStatusString
        }

        #
        # Speculation control settings for SRSO (Speculative Return Stack Overflow) CVE-2023-20569 
        #

        $srsoReported = ($flags2 -band $scf2SrsoReported) -ne 0

        $SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATION_UNSUPPORTED = 0x0
        $SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATION_DISABLED = 0x1
        $SYSTEM_SPECULATION_CONTROL_SRSO_HARDWARE_IMMUNE = 0x2
        $SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATED = 0x3

        $srsoStatus = (($flags2 -band $scf2SrsoStatus) -shr 18)

        $srsoStatusString = switch ($srsoStatus) {
            $SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATION_UNSUPPORTED { "SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATION_UNSUPPORTED" }
            $SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATION_DISABLED { "SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATION_DISABLED" }
            $SYSTEM_SPECULATION_CONTROL_SRSO_HARDWARE_IMMUNE { "SYSTEM_SPECULATION_CONTROL_SRSO_HARDWARE_IMMUNE" }
            $SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATED { "SYSTEM_SPECULATION_CONTROL_SRSO_MITIGATED" }
            default { 'UNKNOWN_VALUE' }
        }

        $object | Add-Member -MemberType NoteProperty -Name SrsoReported -Value $srsoReported
        
        if ($srsoReported -eq $true) {
            $object | Add-Member -MemberType NoteProperty -Name SrsoStatus -Value $srsoStatusString
        }

        #
        # Speculation control settings for DivideByZero CVE-2023-20588
        #

        $divideByZeroReported = ($flags2 -band $scf2DivideByZeroReported) -ne 0

        $SYSTEM_SPECULATION_CONTROL_DIVIDE_BY_ZERO_HARDWARE_IMMUNE = 0x0
        $SYSTEM_SPECULATION_CONTROL_DIVIDE_BY_ZERO_MITIGATED = 0x1

        $divideByZeroStatus = (($flags2 -band $scf2DivideByZeroStatus) -shr 21)

        $divideByZeroStatusString = switch ($divideByZeroStatus) {
            $SYSTEM_SPECULATION_CONTROL_DIVIDE_BY_ZERO_HARDWARE_IMMUNE { "SYSTEM_SPECULATION_CONTROL_DIVIDE_BY_ZERO_HARDWARE_IMMUNE" }
            $SYSTEM_SPECULATION_CONTROL_DIVIDE_BY_ZERO_MITIGATED { "SYSTEM_SPECULATION_CONTROL_DIVIDE_BY_ZERO_MITIGATED" }
            default { 'UNKNOWN_VALUE' }
        }

        $object | Add-Member -MemberType NoteProperty -Name DivideByZeroReported -Value $divideByZeroReported

        if ($divideByZeroReported -eq $true) {
            $object | Add-Member -MemberType NoteProperty -Name DivideByZeroStatus -Value $divideByZeroStatusString
        }

        #
        # Speculation control settings for RFDS (Register File Data Sampling) CVE-2023-28746
        #
        
        $rfdsReported = ($flags2 -band $scf2RfdsReported) -ne 0

        $SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATION_UNSUPPORTED = 0x0
        $SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATION_DISABLED = 0x1
        $SYSTEM_SPECULATION_CONTROL_RFDS_HARDWARE_IMMUNE = 0x2
        $SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATED = 0x3

        $rfdsStatus = (($flags2 -band $scf2RfdsStatus) -shr 23)

        $rfdsStatusString = switch ($rfdsStatus) {
            $SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATION_UNSUPPORTED { "SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATION_UNSUPPORTED" }
            $SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATION_DISABLED { "SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATION_DISABLED" }
            $SYSTEM_SPECULATION_CONTROL_RFDS_HARDWARE_IMMUNE { "SYSTEM_SPECULATION_CONTROL_RFDS_HARDWARE_IMMUNE" }
            $SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATED { "SYSTEM_SPECULATION_CONTROL_RFDS_MITIGATED" }
            default { 'UNKNOWN_VALUE' }
        }

        $object | Add-Member -MemberType NoteProperty -Name RfdsReported -Value $rfdsReported

        if ($rfdsReported -eq $true) {
            $object | Add-Member -MemberType NoteProperty -Name RfdsStatus -Value $rfdsStatusString
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
# MIIoRQYJKoZIhvcNAQcCoIIoNjCCKDICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAz7kViO9B+ucN1
# qp3U+hRMd//fXksmJOpYyVzT2L3bcaCCDXYwggX0MIID3KADAgECAhMzAAAEBGx0
# Bv9XKydyAAAAAAQEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwOTEyMjAxMTE0WhcNMjUwOTExMjAxMTE0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC0KDfaY50MDqsEGdlIzDHBd6CqIMRQWW9Af1LHDDTuFjfDsvna0nEuDSYJmNyz
# NB10jpbg0lhvkT1AzfX2TLITSXwS8D+mBzGCWMM/wTpciWBV/pbjSazbzoKvRrNo
# DV/u9omOM2Eawyo5JJJdNkM2d8qzkQ0bRuRd4HarmGunSouyb9NY7egWN5E5lUc3
# a2AROzAdHdYpObpCOdeAY2P5XqtJkk79aROpzw16wCjdSn8qMzCBzR7rvH2WVkvF
# HLIxZQET1yhPb6lRmpgBQNnzidHV2Ocxjc8wNiIDzgbDkmlx54QPfw7RwQi8p1fy
# 4byhBrTjv568x8NGv3gwb0RbAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU8huhNbETDU+ZWllL4DNMPCijEU4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMjkyMzAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjmD9IpQVvfB1QehvpC
# Ge7QeTQkKQ7j3bmDMjwSqFL4ri6ae9IFTdpywn5smmtSIyKYDn3/nHtaEn0X1NBj
# L5oP0BjAy1sqxD+uy35B+V8wv5GrxhMDJP8l2QjLtH/UglSTIhLqyt8bUAqVfyfp
# h4COMRvwwjTvChtCnUXXACuCXYHWalOoc0OU2oGN+mPJIJJxaNQc1sjBsMbGIWv3
# cmgSHkCEmrMv7yaidpePt6V+yPMik+eXw3IfZ5eNOiNgL1rZzgSJfTnvUqiaEQ0X
# dG1HbkDv9fv6CTq6m4Ty3IzLiwGSXYxRIXTxT4TYs5VxHy2uFjFXWVSL0J2ARTYL
# E4Oyl1wXDF1PX4bxg1yDMfKPHcE1Ijic5lx1KdK1SkaEJdto4hd++05J9Bf9TAmi
# u6EK6C9Oe5vRadroJCK26uCUI4zIjL/qG7mswW+qT0CW0gnR9JHkXCWNbo8ccMk1
# sJatmRoSAifbgzaYbUz8+lv+IXy5GFuAmLnNbGjacB3IMGpa+lbFgih57/fIhamq
# 5VhxgaEmn/UjWyr+cPiAFWuTVIpfsOjbEAww75wURNM1Imp9NJKye1O24EspEHmb
# DmqCUcq7NqkOKIG4PVm3hDDED/WQpzJDkvu4FrIbvyTGVU01vKsg4UfcdiZ0fQ+/
# V0hf8yrtq9CkB8iIuk5bBxuPMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGiUwghohAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAQEbHQG/1crJ3IAAAAABAQwDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFedOK/T86ntnGx1uPS2lfhK
# vaf2+GhemwS689p/43rxMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAKH71AQR/whcsRQg9juEmbjmpkhIgblWBaM1fwn0PvN/3AhqEaHZIQ
# TfIVrrRLHRUnsUwqWwglb0akWyjIayMoa1VfxgQo+o4KtsWzfde84EeaafoowGCX
# g3UHiQx69BjTkN9IuqIOW4V8PfyuGe56J540GkDBWG9m63FXF1N/u94VMldZvVtJ
# lur72vE/JupFSfGLBCdEhp/U6jJA5HR/wwPx4YODqFWghVpszQ546Iq2VNrkgcvQ
# l31WUG4kV3sX+XcWlXwtkxM1imv7Qvs3054UrCkt6b2wC7veZdS5ggTEtp6N5m/W
# p/GuOYG3zBLzozmRsKllnvrLElIxxVIQoYIXrTCCF6kGCisGAQQBgjcDAwExgheZ
# MIIXlQYJKoZIhvcNAQcCoIIXhjCCF4ICAQMxDzANBglghkgBZQMEAgEFADCCAVoG
# CyqGSIb3DQEJEAEEoIIBSQSCAUUwggFBAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBbGYd4IZ6mPO29nWl7VI9oRGlaxngfcj7QQBWKs1UNsAgZoLdTB
# gYsYEzIwMjUwNTI5MTgwNjA1Ljc0M1owBIACAfSggdmkgdYwgdMxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1Mg
# RVNOOjMyMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIR+zCCBygwggUQoAMCAQICEzMAAAH4o6EmDAxASP4AAQAAAfgw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjQwNzI1MTgzMTA4WhcNMjUxMDIyMTgzMTA4WjCB0zELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQg
# T3BlcmF0aW9ucyBMaW1pdGVkMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzIx
# QS0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDFHbeldicPYG44N15e
# zYK79PmQoj5sDDxxu03nQKb8UCuNfIvhFOox7qVpD8Kp4xPGByS9mvUmtbQyLgXX
# mvH9W94aEoGahvjkOY5xXnHLHuH1OTn00CXk80wBYoAhZ/bvRJYABbFBulUiGE9Y
# KdVXei1W9qERp3ykyahJetPlns2TVGcHvQDZur0eTzAh4Le8G7ERfYTxfnQiAAez
# JpH2ugWrcSvNQQeVLxidKrfe6Lm4FysU5wU4Jkgu5UVVOASpKtfhSJfR62qLuNS0
# rKmAh+VplxXlwjlcj94LFjzAM2YGmuFgw2VjF2ZD1otENxMpa111amcm3KXl7eAe
# 5iiPzG4NDRdk3LsRJHAkgrTf6tNmp9pjIzhdIrWzRpr6Y7r2+j82YnhH9/X4q5wE
# 8njJR1uolYzfEy8HAtjJy+KAj9YriSA+iDRQE1zNpDANVelxT5Mxw69Y/wcFaZYl
# AiZNkicAWK9epRoFujfAB881uxCm800a7/XamDQXw78J1F+A8d86EhZDQPwAsJj4
# uyLBvNx6NutWXg31+fbA6DawNrxF82gPrXgjSkWPL+WrU2wGj1XgZkGKTNftmNYJ
# GB3UUIFcal+kOKQeNDTlg6QBqR1YNPZsZJpRkkZVi16kik9MCzWB3+9SiBx2IvnW
# juyG4ciUHpBJSJDbhdiFFttAIQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFL3OxnPP
# ntCVPmeu3+iK0u/U5Du2MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1Gely
# MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNy
# bDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBh+TwbPOkR
# WcaXvLqhejK0JvjYfHpM4DT52RoEjfp+0MT20u5tRr/ExscHmtw2JGEUdn3dF590
# +lzj4UXQMCXmU/zEoA77b3dFY8oMU4UjGC1ljTy3wP1xJCmAZTPLDeURNl5s0sQD
# XsD8JOkDYX26HyPzgrKB4RuP5uJ1YOIR9rKgfYDn/nLAknEi4vMVUdpy9bFIIqgX
# 2GVKtlIbl9dZLedqZ/i23r3RRPoAbJYsVZ7z3lygU/Gb+bRQgyOOn1VEUfudvc2D
# ZDiA9L0TllMxnqcCWZSJwOPQ1cCzbBC5CudidtEAn8NBbfmoujsNrD0Cwi2qMWFs
# xwbryANziPvgvYph7/aCgEcvDNKflQN+1LUdkjRlGyqY0cjRNm+9RZf1qObpJ8sF
# MS2hOjqAs5fRQP/2uuEaN2SILDhLBTmiwKWCqCI0wrmd2TaDEWUNccLIunmoHoGg
# +lzzZGE7TILOg/2C/vO/YShwBYSyoTn7Raa7m5quZ+9zOIt9TVJjbjQ5lbyV3ixL
# x+fJuf+MMyYUCFrNXXMfRARFYSx8tKnCQ5doiZY0UnmWZyd/VVObpyZ9qxJxi0SW
# mOpn0aigKaTVcUCk5E+z887jchwWY9HBqC3TSJBLD6sF4gfTQpCr4UlP/rZIHvSD
# 2D9HxNLqTpv/C3ZRaGqtb5DyXDpfOB7H9jCCB3EwggVZoAMCAQICEzMAAAAVxedr
# ngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4
# MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qls
# TnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLA
# EBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrE
# qv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyF
# Vk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1o
# O5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg
# 3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2
# TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07B
# MzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJ
# NmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6
# r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+
# auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3
# FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl
# 0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUH
# AgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0
# b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMA
# dQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
# gBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRf
# MjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL
# /Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu
# 6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5t
# ggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfg
# QJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8s
# CXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCr
# dTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZ
# c9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2
# tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8C
# wYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9
# JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDB
# cQZqELQdVTNYs6FwZvKhggNWMIICPgIBATCCAQGhgdmkgdYwgdMxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1Mg
# RVNOOjMyMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQC2RC395tZJDkOcb5opHM8QsIUT0aCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# CwUAAgUA6+LegjAiGA8yMDI1MDUyOTEzMjQxOFoYDzIwMjUwNTMwMTMyNDE4WjB0
# MDoGCisGAQQBhFkKBAExLDAqMAoCBQDr4t6CAgEAMAcCAQACAh1VMAcCAQACAhK6
# MAoCBQDr5DACAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAB4QD395Tp8L
# U4jmG3/PgYcMv3XJDCRkA+3rC8d06KnKdt2iMgNpBNtr/f0VcXtVX4ag0M4wd9Xv
# yfH4eC4N7+2oXeTAnRr8Ov83jc2m+TNRY0R67kZ8/UwlFSHNiGrk1HmZUuoxjMHU
# Zr93JuIkSWTIzBp6Hoyg2vT/KxDbim42S9NhDrCfSfHVIeiE+cs9CUIfaKv8XFef
# ysxKtOrt44/ERKlsCWVbJNmoiH+zfvcldXaW7E+IJ0fv3asuB98pK2KwCgoU+r1N
# deZiaM8vERlqPKhX1/RiLpnH32ev/CJop+DX78t2Ohr91/IMMjI8KsMl7bpUFtqX
# y2BDsXa8GaQxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAfijoSYMDEBI/gABAAAB+DANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCiP2+AtRb4
# RJskrWeSsiH4S1/5F+a9OqWBGe+izA0nFjCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIO/MM/JfDVSQBQVi3xtHhR2Mz3RC/nGdVqIoPcjRnPdaMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAH4o6EmDAxASP4AAQAA
# AfgwIgQg9Ulx3XJ+/zTkzVg4eJYmOqXR/Fe/GoaoK0JPzSQA0UIwDQYJKoZIhvcN
# AQELBQAEggIAOyPQAUFOYjiAeleynRbsG5NwPFPjTdqnWKcOgws1bgKZvyJPwsaD
# h3axIBoCEKgce9mjUxnTuneVJtTTZRnfZSTQ151QxnrwzErKQKF6Xo34Kx1GORDy
# tLTBIrUAIs0vIefrcr7dx8sXZEIwgtX/fSSc1KFXCdxbXbI/Na7umjVIaCwPyHaD
# ncDKht8LxUcN+IuhS08XPiUHBeIePAtsKghjH5ZvMZ28bLlKGGyqgGoqApiSF8r+
# nc9lkI0ltVHGuUVALwGYmkcmQReb/jF6enqDTxQPtpb0nmM6054bpnMbWZ+bBEmQ
# ffVaJWJp6UnoqWt0kug9PRCYeOTGaFTlqaot8JGLldb+XImlwx7sSSCQIiFp1fEh
# 5VUydVf2YPMZr/Sl0lmNoPYjcue3VW+2QhvacFbKOljyfBUCcT7g20gnp6r1Fi36
# Y7LJTy4nhzXXXcOH837fE3tFJIBI6VXwRiMg/CaNXuyHfmb4Q6S7+tNr2rhlT67U
# H5qCV27kUN9buVX9M8NR4FMwPbVpvf8kD+//Etj6exE5l4yIi741VMwu8Tu2Zzhj
# UxUGkf08dAbmZOwjxtjB3+SbNwFAzX5e+9+Ar9gRaZjjN77xcMLH6++xhhvJrAO5
# w17JTsgA17hIW6eOMzjeeAIae1Cgg5pXGvWZNbt0SSRURTK++uHp0MM=
# SIG # End signature block
