# Overview

SpeculationControl is a PowerShell script that summarizes the state of configurable Windows mitigations for various [speculative execution side channel vulnerabilities](https://blogs.technet.microsoft.com/srd/2018/03/15/mitigating-speculative-execution-side-channel-hardware-vulnerabilities/), such as CVE-2017-5715 (Spectre variant 2) and CVE-2017-5754 (Meltdown).

For an explanation on how to interpret the output of this tool, please see [Understanding Get-SpeculationControlSettings PowerShell script output](https://support.microsoft.com/en-us/help/4074629/understanding-the-output-of-get-speculationcontrolsettings-powershell).

# Usage

The released version of this script is maintained through the [SpeculationControl](https://www.powershellgallery.com/packages/SpeculationControl) module on PowerShell Gallery.

To install the released version via PowerShell Gallery:

```
PS C:\> Install-Module -Name SpeculationControl
```

To query the state of configurable mitigations:

```
PS> # Save the current execution policy so it can be reset
PS> $SaveExecutionPolicy = Get-ExecutionPolicy
PS> Set-ExecutionPolicy RemoteSigned -Scope Currentuser
PS> Import-Module SpeculationControl
PS> Get-SpeculationControlSettings
PS> # Reset the execution policy to the original state
PS> Set-ExecutionPolicy $SaveExecutionPolicy -Scope Currentuser
```

The following provides an example usage and output for this tool.

```
PS C:\> Import-Module SpeculationControl
PS C:\> Get-SpeculationControlSettings
For more information about the output below, please refer to https://support.microsoft.com/en-in/help/4074629

Speculation control settings for CVE-2017-5715 [branch target injection]

Hardware support for branch target injection mitigation is present: True
Windows OS support for branch target injection mitigation is present: True
Windows OS support for branch target injection mitigation is enabled: True

Speculation control settings for CVE-2017-5754 [rogue data cache load]

Hardware requires kernel VA shadowing: True
Windows OS support for kernel VA shadow is present: True
Windows OS support for kernel VA shadow is enabled: True
Windows OS support for PCID performance optimization is enabled: True [not required for security]

Speculation control settings for CVE-2018-3639 [speculative store bypass]

Hardware is vulnerable to speculative store bypass: True
Hardware support for speculative store bypass disable is present: False
Windows OS support for speculative store bypass disable is present: True
Windows OS support for speculative store bypass disable is enabled system-wide: False

Speculation control settings for CVE-2018-3620 [L1 terminal fault]

Hardware is vulnerable to L1 terminal fault: True
Windows OS support for L1 terminal fault mitigation is present: True
Windows OS support for L1 terminal fault mitigation is enabled: True

Speculation control settings for MDS [microarchitectural data sampling]

Windows OS support for MDS mitigation is present: True
Hardware is vulnerable to MDS: True
Windows OS support for MDS mitigation is enabled: True

BTIHardwarePresent                  : True
BTIWindowsSupportPresent            : True
BTIWindowsSupportEnabled            : True
BTIDisabledBySystemPolicy           : False
BTIDisabledByNoHardwareSupport      : False
BTIKernelRetpolineEnabled           : True
BTIKernelImportOptimizationEnabled  : True
KVAShadowRequired                   : True
KVAShadowWindowsSupportPresent      : True
KVAShadowWindowsSupportEnabled      : True
KVAShadowPcidEnabled                : True
SSBDWindowsSupportPresent           : True
SSBDHardwareVulnerable              : True
SSBDHardwarePresent                 : False
SSBDWindowsSupportEnabledSystemWide : False
L1TFHardwareVulnerable              : True
L1TFWindowsSupportPresent           : True
L1TFWindowsSupportEnabled           : True
L1TFInvalidPteBit                   : 45
L1DFlushSupported                   : False
MDSWindowsSupportPresent            : True
MDSHardwareVulnerable               : True
MDSWindowsSupportEnabled            : True
```

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
