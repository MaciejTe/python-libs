"""
This file contains common Azure Storage Account operations class.
"""
import logging
import os
from datetime import datetime, timedelta

from azure.cosmosdb.table.tableservice import TableService
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters, Sku, SkuName, Kind
from azure.storage.blob import (
    BlockBlobService,
    ContainerPermissions,
    BlobPermissions,
    PublicAccess,
)
from azure.storage.file import FileService
from msrestazure.azure_exceptions import CloudError

from python_libs.azure_cloud import azure_creds_manager
from python_libs.misc.colored_print import ColoredPrint

LOGGER = logging.getLogger(__name__)


class StorageAccount:
    """
    This class is responsible for common operations on Azure Storage Accounts.
    """

    def __init__(self, creds_path=None, sa_name=None, sa_group=None, use_envs=True):
        """
        Create storage_client and blob_srv objects needed for Storage Account
        operations.

        Args:
            creds_path (str): YAML file with Azure credentials
            sa_name (str): Azure Storage Account name; given only when SA exists
            sa_group (str): Azure Storage Account resource group; given only when SA exists
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
            self.creds_manager = azure_creds_manager.AzureCredentialsManager(
                config_path=creds_path
            )
            self.tenant = self.creds_manager.credentials["ARM_TENANT_ID"]
            self.secret = self.creds_manager.credentials["ARM_CLIENT_SECRET"]
            self.client_id = self.creds_manager.credentials["ARM_CLIENT_ID"]
            self.subscription_id = self.creds_manager.credentials["ARM_SUBSCRIPTION_ID"]

        self.credentials = ServicePrincipalCredentials(
            client_id=self.client_id, secret=self.secret, tenant=self.tenant
        )
        self.storage_client = StorageManagementClient(
            self.credentials, self.subscription_id
        )
        self.storage_acc_name = sa_name
        self.storage_acc_group = sa_group

        self._storage_acc_key_1 = None
        self._storage_acc_key_2 = None
        self._blob_srv = None
        self._file_srv = None
        self._table_service = None
        self._changed_properties = {
            "storage_acc_key_1": False,
            "storage_acc_key_2": False,
            "storage_acc_name": False,
        }

    @property
    def storage_acc_key_1(self):
        condition = (
            self._storage_acc_key_1 is None
            or self._changed_properties["storage_acc_key_1"]
        ) and self.storage_acc_name is not None
        if condition:
            sa_keys = self.get_storage_account_keys(
                group_name=self.storage_acc_group,
                storage_acc_name=self.storage_acc_name,
            )
            self._storage_acc_key_1 = sa_keys["key1"]
            self._changed_properties["storage_acc_key_1"] = False
        return self._storage_acc_key_1

    @property
    def storage_acc_key_2(self):
        condition = (
            self._storage_acc_key_2 is None
            or self._changed_properties["storage_acc_key_2"]
        ) and self.storage_acc_name is not None
        if condition:
            sa_keys = self.get_storage_account_keys(
                group_name=self.storage_acc_group,
                storage_acc_name=self.storage_acc_name,
            )
            self._storage_acc_key_2 = sa_keys["key2"]
            self._changed_properties["storage_acc_key_2"] = False
        return self._storage_acc_key_2

    @property
    def blob_srv(self):
        condition = (
            self._blob_srv is None or self.storage_acc_name is not None
        ) or self._changed_properties["storage_acc_name"]
        if condition:
            self._blob_srv = BlockBlobService(
                account_name=self.storage_acc_name, account_key=self.storage_acc_key_1
            )
            self._changed_properties["storage_acc_name"] = False
        return self._blob_srv

    @property
    def file_srv(self):
        if (
            self._file_srv is None or self.storage_acc_name is not None
        ) or self._changed_properties["storage_acc_name"]:
            self._file_srv = FileService(
                account_name=self.storage_acc_name, account_key=self.storage_acc_key_1
            )
            self._changed_properties["storage_acc_name"] = False
        return self._file_srv

    @property
    def table_service(self):
        if (
            self._table_service is None or self.storage_acc_name is not None
        ) or self._changed_properties["storage_acc_name"]:
            self._table_service = TableService(
                account_name=self.storage_acc_name, account_key=self.storage_acc_key_1
            )
            self._changed_properties["storage_acc_name"] = False
        return self._table_service

    def get_storage_accounts(self):
        """
        Get storage accounts objects list.

        Returns:
            list of Azure StorageAccount objects
        """
        return self.storage_client.storage_accounts.list()

    def get_storage_account_properties(self):
        """ Get Storage Account properties.

        Returns:
            properties (object): Storage Account class object
        """
        return self.storage_client.storage_accounts.get_properties(
            self.storage_acc_group, self.storage_acc_name
        )

    def get_storage_account_keys(self, group_name=None, storage_acc_name=None):
        """
        Obtain dictionary with given Azure Storage Account keys.

        Args:
            group_name (str): Storage Account resource group name
            storage_acc_name (str): Storage Account name

        Returns:
            storage_keys (dict): Azure Storage account keys dict
        """
        try:
            storage_keys = self.storage_client.storage_accounts.list_keys(
                group_name, storage_acc_name
            )
        except CloudError as cloud_err:
            self.colored_print(cloud_err.message, level="error")
            raise
        storage_keys = {v.key_name: v.value for v in storage_keys.keys}
        return storage_keys

    def download_blob(
        self, container="public", blob_name=None, path=None, use_sas_token=False
    ):
        """
        Download blob to given path.

        Args:
            container (str): Azure container name
            blob_name (str): block blob name
            path (str): where blob will be saved
            use_sas_token (bool): generate SAS token for downloading a blob
        """
        generator = self.blob_srv.list_blobs(container)
        for blob in generator.items:
            if blob.name == blob_name:
                full_path_to_file = os.path.join(path, blob.name)
                if use_sas_token:
                    sas_token = self._generate_blob_sas_token(
                        container=container, blob_name=blob.name
                    )
                    blob_service = BlockBlobService(
                        account_name=self.storage_acc_name,
                        account_key=self.storage_acc_key_1,
                        sas_token=sas_token,
                    )
                    blob_service.get_blob_to_path(
                        container, blob.name, full_path_to_file
                    )

                else:
                    self.blob_srv.get_blob_to_path(
                        container, blob.name, full_path_to_file
                    )

    def get_blobs(self, container=None):
        """
        Get all existing blobs in the container.

        Args:
            container (str): container name

        Returns:
            blobs (list): list of blob objects
        """
        generator = self.blob_srv.list_blobs(container)
        blobs = [blob for blob in generator]
        return blobs

    def _generate_container_sas_token(self, container=None, timeout=1):
        """
        Generate shared access signature (SAS) for blob container.

        Args:
            container (str): blob container name
            timeout (int): SAS timeout (in hours)

        Returns:
            sas_url (str): SAS URL used for accessing files in blob container
        """
        sas_url = self.blob_srv.generate_container_shared_access_signature(
            container,
            ContainerPermissions.WRITE,
            datetime.utcnow() + timedelta(hours=timeout),
        )
        return sas_url

    def _generate_blob_sas_token(self, container=None, blob_name=None, timeout=1):
        """
        Generate SAS token for given blob file.

        Returns:
            token (str): SAS token needed to download Blob file
        """
        token = self.blob_srv.generate_blob_shared_access_signature(
            container,
            blob_name,
            BlobPermissions.WRITE,
            datetime.utcnow() + timedelta(hours=timeout),
        )
        return token

    def create_container(self, container=None):
        """
        Create container inside Azure Storage Account.

        Args:
            container (str): container name
        """
        try:
            self.blob_srv.create_container(container_name=container)
            self.blob_srv.set_container_acl(
                container, public_access=PublicAccess.Container
            )
        except Exception as docker_err:
            self.colored_print("STORAGE ACCOUNT CONTAINER NOT CREATED!", level="error")
            self.colored_print("DETAILS: {}".format(docker_err), level="error")
            raise

    def delete_container(self, container=None):
        """
        Delete given Azure Storage Account container.

        Args:
            container (str): container name
        """
        if self.blob_srv.exists(container):
            self.colored_print(
                "Deleting Storage Account container " "{}...".format(container)
            )
            status = self.blob_srv.delete_container(container)
            if status:
                self.colored_print(
                    "Deleting Storage Account container " "{}... DONE".format(container)
                )
        else:
            msg = (
                "{} Storage Account container not deleted! Reason: "
                "not found!".format(container)
            )
            self.colored_print(msg, level="error")

    def list_containers(self):
        """ List Storage Account containers.

        Returns:
            container_list(list): list of storage resources
        """
        return list(self.blob_srv.list_containers())

    def list_file_shares(self):
        """
        Lists Azure Storage Account file share objects.

        Returns:
            file_share_list (list): list of file share objects
        """
        file_share_list = list()
        generator = self.file_srv.list_shares()
        for file_or_dir in generator:
            file_share_list.append(file_or_dir)
        return file_share_list

    def list_file_share_internals(self, file_share):
        """
        Lists files and folders inside Azure Storage Account file share.

        Args:
            file_share (str): file share name

        Returns:
            files_list (list): list of files names located in file share
        """
        files_list = list()
        generator = self.file_srv.list_directories_and_files(file_share)
        for file_or_dir in generator:
            files_list.append(file_or_dir.name)
        return files_list

    def get_storage_table_data(self, table_name, data_filter=None):
        """
        Get Azure Storage Account table data.

        Args:
            table_name (str): Azure SA table name
            data_filter (str): filter for table

        Returns:
            table_data (list): list of dictionaries with table data
        """
        table_data_gen = self.table_service.query_entities(
            table_name, filter=data_filter
        )
        return [data_row for data_row in table_data_gen]

    def update_storage_table(self, table_name, task):
        """
        Update existent Azure Storage Account table with new values.

        Args:
            table_name (str): Azure SA table name
            task (dict): new data inserted into SA table

        Returns:
            timestamp (str): timestamp of successful update operation
        """
        try:
            return self.table_service.update_entity(table_name, task)
        except Exception as err:
            self.colored_print(err.__repr__(), level="error")
            LOGGER.error(err.__repr__())
            raise

    def create_storage_account(
        self,
        sa_name,
        sa_group,
        location,
        kind="storage_v2",
        sku_name="standard_lrs",
        timeout=120,
    ):
        """
        Create Storage Account with given parameters.

        Args:
            sa_name (str): Azure Storage Account name
            sa_group (str): Azure Storage Account resource group
            location (str): Azure location
            kind (str): Storage Account kind; available kinds:
                * Storage,
                * StorageV2,
                * BlobStorage
            sku_name (str): Sku name for SA. Available options:
                * standard_lrs
                * standard_grs
                * standard_ragrs
                * standard_zrs
                * premium_lrs
            timeout (int): operation timeout (in seconds)
        """
        self.storage_acc_name = sa_name
        self.storage_acc_group = sa_group
        storage_async_operation = self.storage_client.storage_accounts.create(
            self.storage_acc_group,
            self.storage_acc_name,
            StorageAccountCreateParameters(
                sku=Sku(name=SkuName[sku_name]), kind=Kind[kind], location=location
            ),
        )
        self._changed_properties["storage_acc_key_1"] = True
        self._changed_properties["storage_acc_key_2"] = True
        self._changed_properties["storage_acc_name"] = True
        return storage_async_operation.result(timeout=timeout)

    def remove_storage_account(self):
        """
        Delete given Storage Account.
        """
        self.storage_client.storage_accounts.delete(
            self.storage_acc_group, self.storage_acc_name
        )
