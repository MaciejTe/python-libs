"""
This file contains Azure Resource Manager driver class.
"""
import logging
import os
from time import sleep
from urllib.parse import urlparse

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import DeploymentMode
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.locks.management_lock_client import ManagementLockClient
from azure.mgmt.network.models import (
    NetworkSecurityGroup,
    SecurityRule,
    PublicIPAddress,
    NetworkInterface,
)
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservices.models import (
    Vault,
    Sku,
    SkuName,
    VaultProperties,
    VaultExtendedInfoResource,
)
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.mgmt.recoveryservicesbackup.models import OperationStatusValues
from azure.mgmt.compute import ComputeManagementClient
from msrest.exceptions import AuthenticationError
from msrestazure.azure_exceptions import CloudError


LOGGER = logging.getLogger(__name__)

from python_libs.azure_cloud.azure_creds_manager import AzureCredentialsManager
from python_libs.misc.colored_print import ColoredPrint


class ARMDriver:
    """
    Initialize the Azure Resource Manager driver class with path to
    YAML Azure credentials file.
    """

    def __init__(self, creds_path=None, use_envs=False):
        """
        Create AzureCredentialsManager object which passes Azure credentials
        to ResourceManagementClient, ComputeManagementClient and
        NetworkManagementClient and enables driver to perform various
        operations in Azure.

        Args:
            creds_path (str): path to YAML credentials file
            use_envs (bool): boolean flag telling if environment variables
                             should be used to authenticate to Azure
        """
        self.colored_print = ColoredPrint()
        if creds_path is None and use_envs is False:
            err_msg = (
                "You need to specify if you want to use authentication "
                "data from configuration file or from environment variables!"
            )
            self.colored_print(err_msg, level="error")
            raise Exception(err_msg)
        if use_envs:
            self.tenant = os.environ["ARM_TENANT_ID"]
            self.secret = os.environ["ARM_CLIENT_SECRET"]
            self.client_id = os.environ["ARM_CLIENT_ID"]
            self.subscription_id = os.environ["ARM_SUBSCRIPTION_ID"]
        else:
            self.creds_manager = AzureCredentialsManager(creds_path)
            self.tenant = self.creds_manager.credentials["ARM_TENANT_ID"]
            self.secret = self.creds_manager.credentials["ARM_CLIENT_SECRET"]
            self.client_id = self.creds_manager.credentials["ARM_CLIENT_ID"]
            self.subscription_id = self.creds_manager.credentials["ARM_SUBSCRIPTION_ID"]

        try:
            self.credentials = ServicePrincipalCredentials(
                client_id=self.client_id, secret=self.secret, tenant=self.tenant
            )

            self.client = ResourceManagementClient(
                self.credentials, self.subscription_id
            )
            self.compute_client = ComputeManagementClient(
                self.credentials, self.subscription_id
            )
            self.network_client = NetworkManagementClient(
                self.credentials, self.subscription_id
            )
            self.lock_client = ManagementLockClient(
                self.credentials, self.subscription_id
            )
            self.recovery_client = RecoveryServicesClient(
                self.credentials, self.subscription_id
            )
            self.backup_client = RecoveryServicesBackupClient(
                self.credentials, self.subscription_id
            )

        except AuthenticationError as auth_err:
            err_msg = "Invalid / expired Azure credentials! \n" "Details: {}".format(
                auth_err.inner_exception
            )
            self.colored_print(err_msg, level="error")
            raise

    def get_resource_groups(self, filter_type="none", value=""):
        """
        Get resource group list narrowed down by selected filter.

        Args:
            filter_type (str): filter type for listing Azure resource groups
                - 'none' - no filter, all RGs are listed
                - 'name' - filter RGs by name
            value (str): filter value

        Returns:
            rg_list (list): List with resource groups objects

        Raises:
            Exception: when non-existent filter type is given
        """
        filters = ["none", "name"]
        if filter_type not in filters:
            raise Exception("Improper filter selected!")
        found_rg_list = list()
        rg_list = self.client.resource_groups.list()
        for resource_group in rg_list:
            if filter_type == "none":
                found_rg_list.append(resource_group)
            elif filter_type == "name":
                try:
                    if value in resource_group.name:
                        found_rg_list.append(resource_group)
                except TypeError:
                    continue
        return found_rg_list

    def deploy(
        self,
        template_json=None,
        rg_name=None,
        location=None,
        template_params=dict,
        deployment_name="automation_test",
    ):
        """
        Deploy custom template to Azure.

        Args:
            template_json (dict): ARM template JSON
            rg_name (str): Resource group name
            location (str): Resource group location
            template_params (dict): Template additional parameters
            deployment_name (str): Deployment name
        """
        try:
            self.client.resource_groups.create_or_update(
                rg_name, {"location": location}
            )

            parameters = {
                "Arm_Client_Id": self.client_id,
                "Arm_Client_Secret": self.secret,
            }
            parameters.update(template_params)

            parameters = {k: {"value": v} for k, v in parameters.items()}

            deployment_properties = {
                "mode": DeploymentMode.incremental,
                "template": template_json,
                "parameters": parameters,
            }

            deployment_async_operation = self.client.deployments.create_or_update(
                rg_name, deployment_name, deployment_properties
            )
            deployment_async_operation.wait()
        except CloudError as cloud_err:
            self.colored_print(
                "ARM driver failed to properly deploy resource group "
                "{rg} due to Cloud error: {err}".format(
                    rg=rg_name, err=cloud_err.message
                ),
                level="error",
            )
            self.colored_print(str(cloud_err.response.json()), level="error")
            raise

    def delete(self, rg_name=None, force=True):
        """
        Delete given resource group

        Args:
            rg_name (str): resource group name
            force (bool): force resource group removal, even if Service
                          Recovery Vaults with backups are present
        """
        try:
            if force:
                vault_info_data = dict()
                if self.has_rg_recovery_vault(rg_name):
                    response = self.get_recovery_vault_info(rg_name)
                    for vault in response["value"]:
                        backup_list = self.get_rg_backups(rg_name, vault["name"])
                        vault_info_data[vault["name"]] = backup_list

                for vault_name, backup_data in vault_info_data.items():
                    for backup in backup_data:
                        self.delete_backup(
                            rg_name,
                            vault_name,
                            backup.properties.container_name,
                            backup.name,
                        )
                    self.delete_recovery_vault(rg_name, vault_name)
            self.client.resource_groups.delete(rg_name)
        except CloudError as cloud_err:
            err_msg = "Failed to delete given resource group! \n" "Details: {}".format(
                cloud_err.message
            )
            self.colored_print(err_msg, level="error")
            self.colored_print(str(cloud_err.inner_exception.__dict__), level="error")
            raise Exception(err_msg)

    def get_resource_group_info(self, rg_name=None):
        """
        Get information about given resource group

        Args:
            rg_name (str): resource group name

        Returns:
            rg_info_dict (dict): dictionary containing resource group
                                 information
        """
        rg_info_dict = dict()
        for group in self.client.resource_groups.list():
            if group.name == rg_name:
                rg_info_dict = {
                    "name": group.name,
                    "id": group.id,
                    "location": group.location,
                    "tags": group.tags,
                    "managed_by": group.managed_by,
                    "provisioning_state": group.properties.provisioning_state,
                }
                break
        return rg_info_dict

    def get_rg_resources_types(self, rg_name=None):
        """
        Get list of resources residing in resource group

        Args:
            rg_name (str): resource group name

        Returns:
            resources_list (list): list of resources inside resource group
        """
        resources_list = [
            resource.type
            for resource in self.client.resources.list_by_resource_group(rg_name)
        ]
        return resources_list

    def get_rg_resources_objects(self, rg_name=None):
        """
        Get list of resources residing in resource group

        Args:
            rg_name (str): resource group name

        Returns:
            resources_list (list): list of resources inside resource group
        """
        resources_list = [
            resource
            for resource in self.client.resources.list_by_resource_group(rg_name)
        ]
        return resources_list

    def get_rg_resource_info(self, rg_name=None, resource="vm"):
        """
        Get given resource group's resource data

        Args:
            rg_name (str): resource group to be searched through
            resource (str): resource type
            TODO: for now 'vm', 'disk' and 'all' resources are supported

        Returns:
            resource_info_list (list): list with all encountered resources
                                       of given type
        """
        resource_info_list = list()
        resources_dict = {
            "vm": "Microsoft.Compute/virtualMachines",
            "disk": "Microsoft.Compute/disks",
            "lb": "Microsoft.Network/loadBalancers",
            "sa": "Microsoft.Storage/storageAccounts",
            "nsg": "Microsoft.Network/networkSecurityGroups",
            "all": "Microsoft",
        }
        if resource in resources_dict.keys():
            resources_list = self.client.resources.list_by_resource_group(rg_name)
            try:
                for rg_resource in resources_list:
                    if resource == "all":
                        if resources_dict["all"] in rg_resource.type:
                            resource_info_list.append(rg_resource.__dict__)
                    else:
                        if resources_dict[resource] == rg_resource.type:
                            resource_info_list.append(rg_resource.__dict__)
            except CloudError as cloud_err:
                self.colored_print(cloud_err.message, level="error")
                raise
        return resource_info_list

    def get_vm_objects(self, rg_name):
        """
        Get names list of virtual machines objects residing inside given
        resource group

        Args:
            rg_name (str): resource group

        Returns:
            (list): list of found VMs
        """
        vm_info_list = self.get_vm_names(rg_name=rg_name)
        vm_obj_list = list()
        for vm_name in vm_info_list:
            vm_obj_list.append(
                self.compute_client.virtual_machines.get(
                    rg_name, vm_name, expand="instanceView"
                )
            )
        return vm_obj_list

    def get_vm_statuses(self, rg_name):
        """
        Get Virtual Machines statuses in given resource group.

        Args:
            rg_name (str): Azure resource group name

        Returns:
            vm_statuses_list (dict): dictionary containing pair
                                     VM name: VM status
        """
        vm_obj_list = self.get_vm_objects(rg_name)
        vm_statuses = {
            vm_obj.name: vm_obj.instance_view.statuses[1].display_status
            for vm_obj in vm_obj_list
        }
        return vm_statuses

    def get_vm_names(self, rg_name=None):
        """
        Get names list of virtual machines names residing inside given
        resource group

        Args:
            rg_name (str): resource group

        Returns:
            (list): list of found VMs
        """
        vm_info_list = self.get_rg_resource_info(rg_name=rg_name, resource="vm")
        return [vm["name"] for vm in vm_info_list]

    def get_vm_hardware_profile(self, vm_name):
        """
        Get Virtual Machine's hardware profile.

        Args:
            vm_name: Virtual Machine name

        Returns:
            instance.hardware_profile (HardwareProfile): Azure management
            compute class
        """
        instance_list = self.compute_client.virtual_machines.list_all()
        hardware_profile = None
        for instance in instance_list:
            if vm_name == instance.name:
                hardware_profile = instance.hardware_profile
                break
        return hardware_profile

    def get_vm_public_ip(self, vm_name=None):
        """
        Get public IP address of given VM.

        Args:
            vm_name (str): virtual machine name

        Returns:
            (str): VM public ip if found, otherwise None
        """
        instance_list = self.compute_client.virtual_machines.list_all()
        public_ip = None
        for instance in instance_list:
            if vm_name == instance.name:
                ni_reference = instance.network_profile.network_interfaces[0]
                ni_reference = ni_reference.id.split("/")
                ni_group = ni_reference[4]
                ni_name = ni_reference[8]

                net_interface = self.network_client.network_interfaces.get(
                    ni_group, ni_name
                )
                try:
                    ip_reference = net_interface.ip_configurations[0].public_ip_address
                    ip_reference = ip_reference.id.split("/")
                except AttributeError:
                    return None
                ip_group = ip_reference[4]
                ip_name = ip_reference[8]

                public_ip = self.network_client.public_ip_addresses.get(
                    ip_group, ip_name
                )
                public_ip = public_ip.ip_address
                break
        return public_ip

    def vm_restart(self, rg_name=None, vm_name=None):
        """
        Restart Virtual Machine.

        Args:
            rg_name (str): Azure resource group name
            vm_name (str): Virtual machine name

        Returns:
            restart_status (bool): True if VM was restarted successfully
        """
        restart_status = False
        try:
            vm_restart = self.compute_client.virtual_machines.restart(rg_name, vm_name)
            vm_restart.wait()
            restart_status = True
        except CloudError as cloud_err:
            self.colored_print(cloud_err.message, level="error")
        return restart_status

    def vm_stop(self, rg_name=None, vm_name=None):
        """
        Stop Virtual Machine.

        Args:
            rg_name (str): Azure resource group name
            vm_name (str): Virtual machine name

        Returns:
            power_off_status (bool): True if VM was stopped successfully
        """
        power_off_status = False
        try:
            vm_stop = self.compute_client.virtual_machines.power_off(rg_name, vm_name)
            vm_stop.wait()
            power_off_status = True
        except CloudError as cloud_err:
            self.colored_print(cloud_err.message, level="error")
        return power_off_status

    def vm_start(self, rg_name=None, vm_name=None):
        """
        Start Virtual Machine.

        Args:
            rg_name (str): Azure resource group name
            vm_name (str): Virtual machine name

        Returns:
            start_status (bool): True if VM was started successfully
        """
        start_status = False
        try:
            vm_start = self.compute_client.virtual_machines.start(rg_name, vm_name)
            vm_start.wait()
            start_status = True
        except CloudError as cloud_err:
            self.colored_print(cloud_err.message, level="error")
        return start_status

    def get_rg_load_balancers(self, rg_name, lb_name=None):
        """
        Get list of exisiting load balancers in specified Azure resource group.

        Args:
            rg_name (str): resource group name
            lb_name (str): load balancer name

        Returns:
            lb_list (list): list of load balancers in resource group
        """
        lb_list = self.get_rg_resource_info(rg_name=rg_name, resource="lb")
        if lb_name is not None:
            # list comprehension returning list of filtered load balancers
            lb_list = [lb for lb in lb_list if lb_name in lb["name"]]
        return lb_list

    def get_rg_public_ip(self, rg_name):
        """
        Get resource group's public IP.

        Returns:
            public_ip (str): resource group public IP
        """
        try:
            rg_ip_info_obj = self.network_client.public_ip_addresses.get(rg_name, "")
        except CloudError as cloud_err:
            err_msg = "Cannot obtain resource group public IP! " "Error: {}".format(
                cloud_err.__repr__()
            )
            LOGGER.error(err_msg)
            raise
        properties_list = rg_ip_info_obj.additional_properties["value"]
        if len(properties_list) > 1:
            err_msg = (
                "Most probably number of load balancers is greater "
                "than 1 and script needs to be updated. "
                "Contact maciej.tomczuk@avid.com for support"
            )
            self.colored_print(err_msg, level="error")
        return properties_list[0]["properties"]["ipAddress"]

    def get_load_balancer_nat_rules(self, rg_name, lb_name=None):
        """
        Print to console inbound NAT rules parameters: name and frontend port.

        Args:
            rg_name (str): resource group name
            lb_name (str): load balancer name
        """
        if lb_name is None:
            self.colored_print("You need to specify load balancer name!", level="error")
        load_balancers = self.network_client.load_balancers
        lb_obj = load_balancers.get(rg_name, lb_name)

        for index, rule in enumerate(lb_obj.inbound_nat_rules):
            self.colored_print(
                "INBOUND RULE_{}: rule_name: {}, "
                "frontend_port: {}".format(index, rule.name, rule.frontend_port)
            )

    def save_lb_ip_to_file(self, rg_name, lb_ip_path, env_name="ECD_VM_IP"):
        """
        Save Load balancer public IP address to report/ecd_vm_ip file.

        Additional actions:
            * Prints load balancer public IP (ECD_VM_IP) value to jenkins console.
            * Saves load balancer public IP (ECD_VM_IP) value to Jenkins Linux
              environment variable.
            * Prints out load balancer's incoming NAT rules names and frontend port.

        Args:
            rg_name (str): resource group name to be searched through
            lb_ip_path (str): path to file which will contain load balancer IP
            env_name (str): Linux environment variable name
        """
        load_balancers_list = self.get_rg_load_balancers(rg_name)
        if len(load_balancers_list) > 1:
            err_msg = (
                "There are two or more load balancers! Unable to save VM IP - "
                "Contact maciej.tomczuk@avid.com to update script."
            )
            self.colored_print(err_msg, level="error")
            raise Exception(err_msg)
        self.get_load_balancer_nat_rules(
            rg_name, lb_name=load_balancers_list[0]["name"]
        )
        rg_ip = self.get_rg_public_ip(rg_name)
        if rg_ip is not None:
            os.environ[env_name] = rg_ip
            self.colored_print(
                "*** ECD VM IP: {ip} " "***".format(ip=os.environ[env_name]),
                level="pass",
            )
            with open(lb_ip_path, "w+") as file:
                file.write(rg_ip)
        else:
            err_msg = "Given VM has no public IP assigned!"
            self.colored_print(err_msg, level="warning")

    def add_nsg_rule(
        self,
        rg_name=None,
        location=None,
        nsg_name=None,
        protocol="Tcp",
        direction="Inbound",
        access="Allow",
        description="Test automation rule",
        source_port_range="*",
        destination_port_range=None,
        priority=700,
        name="test_automation",
        source_address_prefix="*",
        destination_address_prefix="*",
    ):
        """ Add new rule to Azure Network Security Group.

        Args:
            rg_name (str): Azure resource group name
            location (str): Azure resource group location
            nsg_name (str): Azure NSG name
            protocol (str): protocol for rule (Tcp, Udp)
            direction (str): web traffic direction (Inbound, Outbound)
            access (str): access policy for rule (Allow, Deny)
            description (str): rule description
            source_port_range (str): source port range for rule
            destination_port_range (str): destination port range for rule
            priority (int): rule priority
            name (str): rule name
            source_address_prefix (str): source address prefix
            destination_address_prefix (str): destination address prefix
        """
        parameters = NetworkSecurityGroup()
        parameters.location = location
        try:
            parameters.security_rules = self.get_nsg(rg_name, nsg_name).security_rules
        except CloudError:
            parameters.security_rules = []
        parameters.security_rules.append(
            SecurityRule(
                protocol=protocol,
                direction=direction,
                access=access,
                description=description,
                source_port_range=source_port_range,
                destination_port_range=destination_port_range,
                priority=priority,
                name=name,
                source_address_prefix=source_address_prefix,
                destination_address_prefix=destination_address_prefix,
            )
        )
        try:
            poller_obj = self.network_client.network_security_groups.create_or_update(
                rg_name, nsg_name, parameters
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.__repr__(), level="error")
            raise
        poller_obj.wait()

    def delete_nsg_rule(self, rg_name=None, nsg_name=None, rule_name=None):
        """ Delete Network Security Group rule.

        Args:
            rg_name (str): Azure resource group name
            nsg_name (str): Azure Network Security Group name
            rule_name (str): security rule name
        """
        try:
            poller_obj = self.network_client.security_rules.delete(
                rg_name, nsg_name, rule_name
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.__repr__(), level="error")
            raise
        poller_obj.wait()

    def get_nsg_rules_data(self, rg_name, nsg_name, rule_name=""):
        """
        Get Network Security Group rule data. Returns all NSG rules if rule
        name is not provided.

        Args:
            rg_name (str): Azure resource group name
            nsg_name (str): Azure Network Security Group name
            rule_name (str): security rule name

        Returns:
            nsg_rule_data (SecurityRule): SecurityRule object from Azure SDK
        """
        try:
            nsg_rule_data = self.network_client.security_rules.get(
                rg_name, nsg_name, rule_name
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.__repr__(), level="error")
            raise
        return nsg_rule_data

    def get_nsg(self, rg_name, nsg_name):
        """ Get NSG object.

        Args:
            rg_name (str): Azure resource group name
            nsg_name (str): Azure Network Security Group name

        Returns:
            nsg (NetworkSecurityGroup): NetworkSecurityGroup object
        """
        return self.network_client.network_security_groups.get(rg_name, nsg_name)

    def get_rg_lock_info(self, rg_name):
        """ Get Azure JSON response with given resource group lock data.
        Args:
            rg_name (str): Azure resource group name

        Returns:
            response_json (dict): JSON with resource group lock data
        """
        lock_object = self.lock_client.management_locks.list_at_resource_group_level(
            rg_name, filter=None, custom_headers=None, raw=False
        )
        response_json = lock_object._get_next().json()
        return response_json

    def is_rg_locked(self, rg_name):
        """ Tell if given resource group is locked.

        Args:
            rg_name (str): Azure resource group name

        Returns:
            locked (bool): is resource locked
        """
        lock_response = self.get_rg_lock_info(rg_name)
        locked = False
        if len(lock_response["value"]) > 0:
            locked = True
        return locked

    def get_recovery_vault_info(self, rg_name):
        """ Get Azure JSON response with given resource group recovery lock data.

        Args:
            rg_name (str): Azure resource group name

        Returns:
            response_json (dict): recovery service vault information
        """
        vault_object = self.recovery_client.vaults.list_by_resource_group(rg_name)
        response_json = vault_object._get_next().json()
        return response_json

    def has_rg_recovery_vault(self, rg_name):
        """ Tell if given resource group has recovery vault.

        Args:
            rg_name (str): Azure resource group name

        Returns:
            has_vault (bool): boolean telling if resource group has recovery vault
        """
        vault_response = self.get_recovery_vault_info(rg_name)
        has_vault = False
        if len(vault_response["value"]) > 0:
            has_vault = True
        return has_vault

    def delete_recovery_vault(self, rg_name, vault_name):
        """ Delete Azure recovery service vault.

        Args:
            rg_name (str): Azure resource group name
            vault_name (str): Recovery Service Vault name
        """
        self.recovery_client.vaults.delete(rg_name, vault_name)

    def get_rg_backups(self, rg_name, vault_name):
        """ Get all protected items (backups) from Recovery Service Vault.

        Args:
            rg_name (str): Azure resource group name
            vault_name (str): Recovery Service Vault name

        Returns:
            backup_list (list): list of Azure backup objects
        """
        return self.backup_client.backup_protected_items.list(vault_name, rg_name)

    def _get_operation_status(self, raw_response, get_operation_status_func):
        """ Get Azure operation status data.

        Args:
            raw_response (dict): raw Azure HTTP response object
            get_operation_status_func (object): function for getting operation
                                                status

        Returns:
            operation_response.properties (object): response properties object
        """
        operation_id_path = urlparse(
            raw_response.response.headers["Azure-AsyncOperation"]
        ).path
        operation_id = operation_id_path.rsplit("/")[-1]
        operation_response = get_operation_status_func(operation_id)

        while operation_response.status == OperationStatusValues.in_progress.value:
            sleep(5)
            operation_response = get_operation_status_func(operation_id)

        operation_response = get_operation_status_func(operation_id)
        assert OperationStatusValues.succeeded.value == operation_response.status

        return operation_response.properties

    def delete_backup(
        self, rg_name, vault_name, container_name, backup_name, fabric_name="Azure"
    ):
        """ Delete backup from Recovery Service vault.

        Args:
            rg_name (str): Azure resource group name
            vault_name (str): Recovery Services vault name
            container_name (str): Recovery Service vault container name
            backup_name (str): vault backup name to be removed
            fabric_name (str): Azure fabric name

        Returns:
            job_response.job_id (str): job ID
        """
        container_name = "iaasvmcontainer;{}".format(container_name)
        response = self.backup_client.protected_items.delete(
            vault_name, rg_name, fabric_name, container_name, backup_name, raw=True
        )

        job_response = self._get_operation_status(
            response,
            lambda operation_id: self.backup_client.backup_operation_statuses.get(
                vault_name, rg_name, operation_id
            ),
        )
        return job_response.job_id

    def create_vault(self, rg_name, vault_name, location):
        """ Create Recovery Services vault.

        Args:
            rg_name (str): Azure resource group name
            vault_name (str): Recovery Services vault name
            location (str): vault's location
        """
        params_sku = Sku(name=SkuName.standard)
        params_create = Vault(
            location=location, sku=params_sku, properties=VaultProperties()
        )
        self.recovery_client.vaults.create_or_update(rg_name, vault_name, params_create)

    def create_pip(self, rg_name, location, pip_name, allocation_method="Dynamic"):
        """ Create public IP in given resource group.

        Args:
            rg_name (str): Azure resource group name
            location (str): Azure public IP location
                            (needs to be the same as resource group location)
            pip_name (str): public IP name
            allocation_method (str): IP allocation metod (Dynamic, Static)
        """
        params = PublicIPAddress(
            location=location, public_ip_allocation_method=allocation_method
        )
        try:
            poller_obj = self.network_client.public_ip_addresses.create_or_update(
                rg_name, pip_name, params
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.__repr__(), level="error")
            raise
        poller_obj.wait()

    def get_pip(self, rg_name, pip_name):
        """ Get public IP data.

        Args:
            rg_name (str): Azure resource group name
            pip_name (str): public IP name

        Returns:
            pip_data (PublicIP): public IP Azure object
        """
        return self.network_client.public_ip_addresses.get(rg_name, pip_name)

    def delete_pip(self, rg_name, pip_name):
        """ Delete existing public IP address.

        Args:
            rg_name (str): Azure resource group name
            pip_name (str): public IP address name
        """
        try:
            poller_obj = self.network_client.public_ip_addresses.delete(
                rg_name, pip_name
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.__repr__(), level="error")
            raise
        poller_obj.wait()

    def list_network_interfaces(self, rg_name):
        """ List all Network Interfaces in given Azure resource group name.

        Args:
            rg_name (str): Azure resource group name

        Returns:
            nic_list (list): List of NICs
        """
        return self.network_client.network_interfaces.list(rg_name)

    def get_network_interface(self, rg_name, interface_name):
        """ Get network interface information.

        Args:
            rg_name (str): Azure resource group name
            interface_name (str): Network Interface name

        Returns:
            network_interface (NetworkInterface): Network Interface object
        """
        return self.network_client.network_interfaces.get(rg_name, interface_name)

    def update_network_interface_pip(self, rg_name, interface_name, pip_data):
        """ Update public IP configuration part of network interface (assign, unassign).

        Args:
            rg_name (str): Azure resource group name
            interface_name (str): Network Interface name
            pip_data (PublicIP): public IP data object
        """
        ni_data = self.get_network_interface(rg_name, interface_name)
        ni_data.ip_configurations[0].public_ip_address = pip_data
        try:
            poller_obj = self.network_client.network_interfaces.create_or_update(
                rg_name, interface_name, ni_data
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.__repr__(), level="error")
            raise
        poller_obj.wait()
