<!---
#######################################
## Python Libs
##
## Format: markdown (md)
## Latest versions should be placed as first
##
## Notation: 00.01.02
##      - 00: stable released version
##      - 01: new features
##      - 02: bug fixes and small changes
##
## Updating schema (mandatory):
##      <empty_line>
##      <version> (dd/mm/rrrr)
##      ----------------------
##      * <item>
##      * <item>
##      <empty_line>
##
## Useful tutorial: https://en.support.wordpress.com/markdown-quick-reference/
##
#######################################
-->

0.3.0 (23.08.2019)
---------------------
    - Added WinRMManager class for managing WinRM connections (using pywinrm library)
    - couple minor changes in arm_driver
    - added list_containers method in StorageAccount class for Azure SDK

0.2.0 (08.07.2019)
---------------------
    - Added endpoint for healthcheck to ecd_driver and change timeout in ecd_oper for check_status
    - Added possibility to create and remove Storage Account in StorageAccount class

0.1.0 (22.05.2019)
---------------------
    - refactored getting latest package version in setup.py
    - refactored CHANGELOG.md to the new format

0.0.2 (27.03.2019)
---------------------
    - Added Azure public IP and Network Interface operations
         - create_pip(): public IP creation
         - get_pip(): get public IP data
         - delete_pip(): delete given public IP
         - list_network_interfaces(): List all Network Interfaces in given Azure resource group name
         - get_network_interface(): get information about given Network Interface
         - update_network_interface_pip(): Update public IP configuration part of network interface
    - Removed temporary comments

0.0.1 (25.02.2019)
---------------------
    - Added first version of python-libs with following lib categories:
        - azure_cloud (Azure Cloud provider libraries)
        - exceptions (handlers)
        - network (network-related libraries, e.g. SSH connections manager)
        - misc (various libraries not fitting into any category: YAML, string generator, colored print, etc.)
    - Supported Python version: 3.5.6

0.0.0 (25.02.2019)
---------------------
    - Initialised repository, added requirements.txt and setup.py
