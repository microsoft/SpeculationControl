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


    [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
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

        $manufacturer = $cpu.Manufacturer
 
        #
        # Query branch target injection information.
        #

        if ($Quiet -ne $true) {

            Write-Host "For more information about the output below, please refer to https://support.microsoft.com/en-in/help/4074629" -ForegroundColor Cyan
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
    
        [System.UInt32]$systemInformationClass = 201
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

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
            [System.UInt32]$scfHwReg1Enumerated = 0x08
            [System.UInt32]$scfHwReg2Enumerated = 0x10
            [System.UInt32]$scfHwMode1Present = 0x20
            [System.UInt32]$scfHwMode2Present = 0x40
            [System.UInt32]$scfSmepPresent = 0x80
            [System.UInt32]$scfSsbdAvailable = 0x100
            [System.UInt32]$scfSsbdSupported = 0x200
            [System.UInt32]$scfSsbdSystemWide = 0x400
            [System.UInt32]$scfSsbdRequired = 0x1000

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $btiHardwarePresent = ((($flags -band $scfHwReg1Enumerated) -ne 0) -or (($flags -band $scfHwReg2Enumerated)))
            $btiWindowsSupportPresent = $true
            $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)

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

            if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                Write-Verbose "BpbEnabled                   : $(($flags -band $scfBpbEnabled) -ne 0)"
                Write-Verbose "BpbDisabledSystemPolicy      : $(($flags -band $scfBpbDisabledSystemPolicy) -ne 0)"
                Write-Verbose "BpbDisabledNoHardwareSupport : $(($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)"
                Write-Verbose "HwReg1Enumerated             : $(($flags -band $scfHwReg1Enumerated) -ne 0)"
                Write-Verbose "HwReg2Enumerated             : $(($flags -band $scfHwReg2Enumerated) -ne 0)"
                Write-Verbose "HwMode1Present               : $(($flags -band $scfHwMode1Present) -ne 0)"
                Write-Verbose "HwMode2Present               : $(($flags -band $scfHwMode2Present) -ne 0)"
                Write-Verbose "SmepPresent                  : $(($flags -band $scfSmepPresent) -ne 0)"
                Write-Verbose "SsbdAvailable                : $(($flags -band $scfSsbdAvailable) -ne 0)"
                Write-Verbose "SsbdSupported                : $(($flags -band $scfSsbdSupported) -ne 0)"
                Write-Verbose "SsbdSystemWide               : $(($flags -band $scfSsbdSystemWide) -ne 0)"
                Write-Verbose "SsbdRequired                 : $(($flags -band $scfSsbdRequired) -ne 0)"
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
                        $stepping = [System.UInt32]$result.Groups[3].Value
                
                        if (($family -eq 0x6) -and 
                            (($model -eq 0x1c) -or
                             ($model -eq 0x26) -or
                             ($model -eq 0x27) -or
                             ($model -eq 0x36) -or
                             ($model -eq 0x35))) {

                            $kvaShadowRequired = $false
                        }
                    }
                }
                else {
                    throw ("Unsupported processor manufacturer: {0}" -f $manufacturer)
                }
            }

            $l1tfRequired = $kvaShadowRequired

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
        # Provide guidance as appropriate.
        #

        $actions = @()
        
        if ($btiHardwarePresent -eq $false) {
            $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
        }

        if (($btiWindowsSupportPresent -eq $false) -or 
            ($kvaShadowPresent -eq $false) -or
            ($ssbdAvailable -eq $false) -or
            ($l1tfMitigationPresent -eq $false)) {
            $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
        }

        if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or 
            ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false) -or
            ($l1tfRequired -eq $true -and $l1tfMitigationEnabled -eq $false)) {
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
# MIIdoAYJKoZIhvcNAQcCoIIdkTCCHY0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3qK/cqj1j/00k2QWrSdZW9MW
# apqgghhuMIIE3jCCA8agAwIBAgITMwAAAOtpqsw+KZ8tOQAAAAAA6zANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTgwODIzMjAxOTMw
# WhcNMTkxMTIzMjAxOTMwWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJp
# Y28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkI4RUMtMzBBNC03MTQ0MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAtUgVMTCRT4OJO0Mpuwvx+XO5QmP3h0rKAKfeLGh8
# EaWmLrpncRID7XmyosZLraSDHoz/hauMvlnCJFE+iMTvTDkSiioNZcAKBK7JDIq0
# vPzA559v2UunwBHaU+NueS6nYTBx54n6I4QpiE8/wr3dMz4e10eBAXd8h4OZ4ZK/
# YmJfSxJUGMSn70yzmSuKhQ7tIqUmmUSIt2Z3vu/zRhbKi8Aind4+ASRFpYMuE+1h
# D4jIpwJ1CUjZZhI0UsDRa7mz6CO2RwCUXPRjgXXvTfrv2zv+F8jDbTfEXs8RZPLw
# 3eIFo06gqUfYhp1Ufw+/7Oesc5rM4OkRY1TG2jD/ne5PqQIDAQABo4IBCTCCAQUw
# HQYDVR0OBBYEFAW30KaPfAOZ1HwiXZI8utZ3J6amMB8GA1UdIwQYMBaAFCM0+NlS
# RnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly9jcmwubWlj
# cm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY3Jvc29mdFRpbWVTdGFtcFBD
# QS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzAChjxodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcnQw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQEFBQADggEBAHvg1mBCSvjq
# wnWpRZF0s84/duMABrGAur2JSbcCMVeY1Gz9xftubwtIkxaUSqtyUkGOJVdgwlUM
# ZAT4/up2bRT896uVKcEHNweSFLqPxfeJFgsUzQ+z9ftH4S9+IX+V7o0HB4VoB92Q
# 9Qdd56HqRJFaLzbsppXJpSXbbdtrBjjfohYSrkzlcedWQ6sANjswlYbZ4cWxGDEB
# 3ad8YTzLnPZtcwY4R4n49UOnUavG/NB0tJRUbMOO4fyUAMBr4R20tYudgvoXRK8B
# VVEfYP6mQa1QG6Mh3oluJb3jJ7pYpDfMMRXh3S9Y6pofu67todxbL7afn1Vi11d6
# /bjN6QMHSnYwggX/MIID56ADAgECAhMzAAABA14lHJkfox64AAAAAAEDMA0GCSqG
# SIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# KDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwHhcNMTgw
# NzEyMjAwODQ4WhcNMTkwNzI2MjAwODQ4WjB0MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24w
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRlHY25oarNv5p+UZ8i4hQ
# y5Bwf7BVqSQdfjnnBZ8PrHuXss5zCvvUmyRcFrU53Rt+M2wR/Dsm85iqXVNrqsPs
# E7jS789Xf8xly69NLjKxVitONAeJ/mkhvT5E+94SnYW/fHaGfXKxdpth5opkTEbO
# ttU6jHeTd2chnLZaBl5HhvU80QnKDT3NsumhUHjRhIjiATwi/K+WCMxdmcDt66Va
# mJL1yEBOanOv3uN0etNfRpe84mcod5mswQ4xFo8ADwH+S15UD8rEZT8K46NG2/Ys
# AzoZvmgFFpzmfzS/p4eNZTkmyWPU78XdvSX+/Sj0NIZ5rCrVXzCRO+QUauuxygQj
# AgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEEAYI3TAgBBggrBgEFBQcDAzAd
# BgNVHQ4EFgQUR77Ay+GmP/1l1jjyA123r3f3QP8wUAYDVR0RBEkwR6RFMEMxKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMRYwFAYDVQQF
# Ew0yMzAwMTIrNDM3OTY1MB8GA1UdIwQYMBaAFEhuZOVQBdOCqhc3NyK1bajKdQKV
# MFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0wNy0wOC5jcmwwYQYIKwYBBQUH
# AQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0wNy0wOC5jcnQwDAYDVR0T
# AQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAn/XJUw0/DSbsokTYDdGfY5YGSz8e
# XMUzo6TDbK8fwAG662XsnjMQD6esW9S9kGEX5zHnwya0rPUn00iThoj+EjWRZCLR
# ay07qCwVlCnSN5bmNf8MzsgGFhaeJLHiOfluDnjYDBu2KWAndjQkm925l3XLATut
# ghIWIoCJFYS7mFAgsBcmhkmvzn1FFUM0ls+BXBgs1JPyZ6vic8g9o838Mh5gHOmw
# GzD7LLsHLpaEk0UoVFzNlv2g24HYtjDKQ7HzSMCyRhxdXnYqWJ/U7vL0+khMtWGL
# sIxB6aq4nZD0/2pCD7k+6Q7slPyNgLt44yOneFuybR/5WcF9ttE5yXnggxxgCto9
# sNHtNr9FB+kbNm7lPTsFA6fUpyUSj+Z2oxOzRVpDMYLa2ISuubAfdfX2HX1RETcn
# 6LU1hHH3V6qu+olxyZjSnlpkdr6Mw30VapHxFPTy2TUxuNty+rR1yIibar+YRcdm
# stf/zpKQdeTr5obSyBvbJ8BblW9Jb1hdaSreU0v46Mp79mwV+QMZDxGFqk+av6pX
# 3WDG9XEg9FGomsrp0es0Rz11+iLsVT9qGTlrEOlaP470I3gwsvKmOMs1jaqYWSRA
# uDpnpAdfoP7YO0kT+wzh7Qttg1DO8H8+4NkI6IwhSkHC3uuOW+4Dwx1ubuZUNWZn
# cnwa6lL2IsRyP64wggYHMIID76ADAgECAgphFmg0AAAAAAAcMA0GCSqGSIb3DQEB
# BQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJk/IsZAEZFgltaWNy
# b3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
# cml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMxMzAzMDlaMHcxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ+h
# bLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn0UytdDAgEesH1VSVFUmUG0KS
# rphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0Zxws/HvniB3q506jocEjU8qN
# +kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4nrIZPVVIM5AMs+2qQkDBuh/NZ
# MJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YRJylmqJfk0waBSqL5hKcRRxQJ
# gp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54QTF3zJvfO4OToWECtR0Nsfz3
# m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsGA1UdDwQEAwIBhjAQBgkrBgEE
# AYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJgQFYnl+UlE/wq4QpTlVnkpKFj
# pGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jv
# c29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL21pY3Jvc29mdHJvb3Rj
# ZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYBBQUHMAKGOGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9zb2Z0Um9vdENlcnQuY3J0MBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBBQUAA4ICAQAQl4rDXANENt3p
# tK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1iuFcCy04gE1CZ3XpA4le7r1ia
# HOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+rkuTnjWrVgMHmlPIGL4UD6ZEq
# JCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGctxVEO6mJcPxaYiyA/4gcaMvnM
# MUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/FNSteo7/rvH0LQnvUU3Ih7jDK
# u3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbonXCUbKw5TNT2eb+qGHpiKe+i
# myk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0NbhOxXEjEiZ2CzxSjHFaRkMU
# vLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPpK+m79EjMLNTYMoBMJipIJF9a
# 6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2JoXZhtG6hE6a/qkfwEm/9ijJs
# sv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0eFQF1EEuUKyUsKV4q7OglnUa
# 2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng9wFlb4kLfchpyOZu6qeXzjEp
# /w7FW1zYTRuh2Povnj8uVRZryROj/TCCB3owggVioAMCAQICCmEOkNIAAAAAAAMw
# DQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
# cml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoXDTI2MDcwODIxMDkwOVowfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKvw+nIQHC6t2G6qghBNNLrytlghn0IbKmvpWlCquAY4GgRJun/D
# DB7dN2vGEtgL8DjCmQawyDnVARQxQtOJDXlkh36UYCRsr55JnOloXtLfm1OyCizD
# r9mpK656Ca/XllnKYBoF6WZ26DJSJhIv56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW
# 9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01W
# KKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y
# 07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yU
# h7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLE
# tVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhE
# fEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L
# 50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo8e1twyiPLI9AN0/B4YVEicQJTMXU
# pUMvdJX3bvh4IFgsE11glZo+TzOE2rCIF96eTvSWsLxGoGyY0uDWiIwLAgMBAAGj
# ggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3
# IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUci06AjGQQ7kUBU7h6qfHMdEj
# iTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNybDBe
# BggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNydDCB
# nwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBA
# BggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBwAG8AbABpAGMAeQBfAHMAdABh
# AHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPY
# dGcimwuWEeFjkplCln3SeQyQwWVfLiw++MNy0W2D/r4/6ArKO79HqaPzadtjvyI1
# pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJ
# RD14eiPzE32mkHSDjfTLJgJGKsKKELukqQUMm+1o+mgulaAqPyprWEljHwlpblqY
# luSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMOr5kol5hNDj0L8giJ1h/DMhji8MUt
# zluetEk5CsYKwsatruWy2dsViFFFWDgycScaf7H0J/jeLDogaZiyWYlobm+nt3TD
# QAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWnduVAKmWjw11SYobDHWM2l4bf2vP4
# 8hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1HxS+YWG18NzGGwS+30HHDiju3mUv
# 7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnFsZulP0V3HjXG0qKin3p6IvpIlR+r
# +0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9azI2h15q/6/IvrC4DqaTuv/DDtBEyO
# 3991bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/+6jMpF3BoYibV3FWTkhFwELJm3Zb
# CoBIa/15n8G9bW1qyVJzEw16UM0xggScMIIEmAIBATCBlTB+MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29k
# ZSBTaWduaW5nIFBDQSAyMDExAhMzAAABA14lHJkfox64AAAAAAEDMAkGBSsOAwIa
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKlUP4ueahtTJYKi/3JTAoG+
# 1qhOMFAGCisGAQQBgjcCAQwxQjBAoBaAFABQAG8AdwBlAHIAUwBoAGUAbABsoSaA
# JGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Qb3dlclNoZWxsIDANBgkqhkiG9w0B
# AQEFAASCAQDQ6sGXvhz5BEByBP5kvba2DiDnHTCl0tSrRMViryNgpSFIRG8/alRH
# YLKFKgqIpIJ+FEFsPHn+sONrbAfOjCJvNh9CloQWbwLDfWa8klVjjwBQ73aSyCtO
# nlo416719XiOGWQFjQ6CFTK+oDMDol/M7UPFdtK8NLTFMoW/IIgfq1dZzF80tRFe
# zBUbCTSWf2cTQDXmesGkFgo/FFSSzXDbRFWnh1hC+Sa7MH9miFoqLpjMlvIVigsg
# ziWnROsEjtbybralrLgD3mOJu0f0E0SunM/EhFiRfgw8ChBvmYcHBACWpC7k9vSf
# uxiUpWIXrnxwZCj1i1FOY6VPmB3EmW1ioYICKDCCAiQGCSqGSIb3DQEJBjGCAhUw
# ggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# ITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAOtpqsw+KZ8t
# OQAAAAAA6zAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTgwOTA1MTcxNDA5WjAjBgkqhkiG9w0BCQQxFgQUXH+Z
# fBrfo3EdLIlE64T1YVgn7v8wDQYJKoZIhvcNAQEFBQAEggEAnDSPZJIHRmR8l5Fs
# WQJo/xKDmhPsp5xzD9JqwSkc/So2inqoRJMPRJ5EX+ADgubZBK77uvekM1A/WCEi
# kqyM/+BneMyYkDIbuupXcxYaeC/6Mq5BOCDAfeDQjAWVat2yCICA6l//uUg/+FSO
# Q9pwObjG5Uf1/LoupJNsAVXPX8GwJRsZlCRLL06b9ynBki3bSZEij4D0bQAzl4Ld
# X60s5Pq417cOG0SuKVW3W/u1REdHSq609i2Tt5eOcntGi3gycjvi3hRxgCWlNsbl
# Eeci6KkUsyhaSRVvVRBMK2CL6S8w4lZg/gNMOezHnQUQ60aFbA+Iv9Vq0mPSkGkp
# gICjug==
# SIG # End signature block
