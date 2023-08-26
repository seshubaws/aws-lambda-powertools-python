import base64
from typing import Any, Dict, List, Optional, Union

import botocore
from aws_encryption_sdk import (
    CachingCryptoMaterialsManager,
    EncryptionSDKClient,
    LocalCryptoMaterialsCache,
    StrictAwsKmsMasterKeyProvider,
)

from aws_lambda_powertools.shared.user_agent import register_feature_to_botocore_session
from aws_lambda_powertools.utilities.data_masking.provider import BaseProvider


class SingletonMeta(type):
    """Metaclass to cache class instances to optimize encryption"""

    _instances: Dict["AwsEncryptionSdkProvider", Any] = {}

    def __call__(cls, *args, **provider_options):
        if cls not in cls._instances:
            instance = super().__call__(*args, **provider_options)
            cls._instances[cls] = instance
        return cls._instances[cls]


CACHE_CAPACITY: int = 100
MAX_ENTRY_AGE_SECONDS: float = 300.0
MAX_MESSAGES_ENCRYPTED: int = 200  # default for sdk is 2 ** 32
# NOTE: You can also set max messages/bytes per data key


class AwsEncryptionSdkProvider(BaseProvider):
    """
    The Aws AwsEncryptionSdkProvider to be used in Datamasking class.

    Example:
        >>> data_masker = DataMasking(provider=AwsEncryptionSdkProvider(keys="secret-key"))
        >>> encrypted_data = data_masker.encrypt([1, 2, "string", 4])
        "encrptedBase64String"
        >>> decrypted_data = data_masker.decrypt(encrypted_data)
        [1, 2, "string", 4]
    """

    session = botocore.session.Session()
    register_feature_to_botocore_session(session, "data-masking")

    def __init__(
        self,
        keys: List[str],
        client: Optional[EncryptionSDKClient] = None,
        local_cache_capacity: Optional[int] = CACHE_CAPACITY,
        max_cache_age_seconds: Optional[int] = MAX_ENTRY_AGE_SECONDS,
        max_messages_encrypted: Optional[int] = MAX_MESSAGES_ENCRYPTED,
    ):
        """
        Establish CachingCryptoMaterialsManager from aws_encryption_sdk with KMS keys,
        EncryptionSDKClient(optional), cache settings(optional)

        Parameters:
            - `keys` (List[str]):
                A list of AWS KMS key IDs.
            - `client` (Optional[EncryptionSDKClient]):
                An optional EncryptionSDKClient object. If not provided, a new client will be created.
            - `local_cache_capacity` (Optional[int]):
                The maximum number of entries to store in the local cache.
            - `max_cache_age_seconds` (Optional[int]):
                The maximum age of an entry in the local cache, in seconds.
            - `max_message_per_key` (Optional[int]):
                Maximum number of messages that may be encrypted under a cache entry
        """

        self.cache = LocalCryptoMaterialsCache(local_cache_capacity)
        self.client = client or EncryptionSDKClient()
        self.keys = keys
        self.key_provider = StrictAwsKmsMasterKeyProvider(key_ids=self.keys, botocore_session=self.session)
        self.cache_cmm = CachingCryptoMaterialsManager(
            master_key_provider=self.key_provider,
            cache=self.cache,
            max_age=max_cache_age_seconds,
            max_messages_encrypted=max_messages_encrypted,
        )

    def encrypt(self, data: Union[bytes, str], **provider_options) -> str:
        """
        Encrypt data using the AwsEncryptionSdkProvider.

        Parameters:
            - `data` (Union[bytes, str]):
                The data to be encrypted.
            - `provider_options` (**kwargs):
                Additional options for the aws_encryption_sdk.EncryptionSDKClient.

        Returns:
            - `ciphertext` (str):
                The encrypted data, as a base64-encoded string.

        """
        ciphertext, _ = self.client.encrypt(source=data, materials_manager=self.cache_cmm, **provider_options)
        ciphertext = base64.b64encode(ciphertext).decode()
        return ciphertext

    def decrypt(self, data: str, **provider_options) -> bytes:
        """
        Decrypt data using AwsEncryptionSdkProvider.

        Parameters:
            - `data` (Union[bytes, str]):
                The encrypted data, as a base64-encoded string.
            - `provider_options` (**kwargs):
                Additional options for the aws_encryption_sdk.EncryptionSDKClient.

        Returns:
            - `ciphertext` (bytes):
                The decrypted data, as a bytes object.

        """
        ciphertext_decoded = base64.b64decode(data)

        expected_context = provider_options.pop("encryption_context", {})

        ciphertext, decryptor_header = self.client.decrypt(
            source=ciphertext_decoded,
            key_provider=self.key_provider,
            **provider_options,
        )

        for key, value in expected_context.items():
            if decryptor_header.encryption_context.get(key) != value:
                raise ValueError(f"Encryption Context does not match expected value for key: {key}")

        return ciphertext
