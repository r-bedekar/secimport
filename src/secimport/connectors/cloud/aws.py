"""
AWS Connector -- resource inventory via boto3.

API Docs: https://boto3.amazonaws.com/v1/documentation/api/latest/index.html

Status: STUB -- Community contribution welcome!
"""

import logging
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedAsset, ParsedOwnerMapping
from ..base import AuthConfig, ConnectionConfig, ConnectorStatus
from .base import BaseCloudConnector

logger = logging.getLogger("secimport.connectors.cloud.aws")


class AWSConnector(BaseCloudConnector):
    """
    AWS resource inventory connector using boto3.

    Authenticates with IAM access-key credentials passed via
    ``AuthConfig(auth_type="token", credentials={...})``.

    Usage::

        from secimport.connectors.cloud import AWSConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://ec2.amazonaws.com")
        auth = AuthConfig(
            auth_type="token",
            credentials={
                "access_key_id": "AKIA...",
                "secret_access_key": "wJalr...",
                "region": "us-east-1",
            },
        )

        with AWSConnector(config, auth) as aws:
            for asset in aws.get_resources(resource_type="ec2"):
                print(asset.hostname, asset.ip_address)
    """

    name: ClassVar[str] = "aws"
    vendor: ClassVar[str] = "Amazon Web Services"
    description: ClassVar[str] = "AWS resource inventory via boto3"
    auth_types: ClassVar[Tuple[str, ...]] = ("token",)

    DEFAULT_OWNER_TAG_KEYS: ClassVar[List[str]] = [
        "Owner",
        "Team",
        "Department",
        "CostCenter",
        "BusinessUnit",
    ]

    # -- init ------------------------------------------------------------------

    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ) -> None:
        """Initialise the AWS connector.

        Args:
            connection: Connection configuration (``base_url`` is unused by boto3).
            auth: Auth config with ``credentials`` containing
                ``access_key_id``, ``secret_access_key``, and optionally
                ``session_token`` and ``region``.
        """
        super().__init__(connection, auth)
        self._session: Any = None
        self._ec2_client: Any = None
        self._tagging_client: Any = None

    # -- connect / disconnect / test -------------------------------------------

    def connect(self) -> bool:
        """
        Create a boto3 session and service clients.

        Returns:
            ``True`` on success; raises ``ConnectionError`` on failure.
        """
        import boto3  # type: ignore[import-untyped]

        creds = self.auth.credentials
        region = creds.get("region", "us-east-1")

        session_kwargs: Dict[str, str] = {
            "aws_access_key_id": creds["access_key_id"],
            "aws_secret_access_key": creds["secret_access_key"],
            "region_name": region,
        }
        if "session_token" in creds:
            session_kwargs["aws_session_token"] = creds["session_token"]

        try:
            self._session = boto3.Session(**session_kwargs)
            self._ec2_client = self._session.client("ec2")
            self._tagging_client = self._session.client(
                "resourcegroupstaggingapi"
            )

            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                logger.info(
                    "%s: connected to AWS region %s", self.name, region
                )
                return True

            self.disconnect()
            return False
        except Exception as exc:
            self.status = ConnectorStatus.ERROR
            self.disconnect()
            raise ConnectionError(
                f"Failed to connect to {self.name}: {exc}"
            ) from exc

    def disconnect(self) -> None:
        """Release boto3 clients and session."""
        self._ec2_client = None
        self._tagging_client = None
        self._session = None
        self.status = ConnectorStatus.DISCONNECTED

    def test_connection(self) -> bool:
        """Validate credentials via ``sts.get_caller_identity()``."""
        try:
            sts = self._session.client("sts")  # type: ignore[union-attr]
            sts.get_caller_identity()
            return True
        except Exception:
            return False

    # -- data methods (stubs) --------------------------------------------------

    def get_resources(
        self,
        resource_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Fetch AWS resources as normalised assets.

        Args:
            resource_type: AWS resource type filter (e.g. ``"ec2"``).
            limit: Maximum number of resources to return.

        Yields:
            ``ParsedAsset`` objects.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_tags(self, resource_id: str) -> Dict[str, str]:
        """
        Retrieve tags for an AWS resource.

        Args:
            resource_id: AWS resource ARN.

        Returns:
            Dict mapping tag key to tag value.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_from_tags(
        self,
        resource_id: str,
        owner_tag_keys: Optional[List[str]] = None,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Derive owner information from AWS resource tags.

        Args:
            resource_id: AWS resource ARN.
            owner_tag_keys: Ordered list of tag keys to check.
                Defaults to ``DEFAULT_OWNER_TAG_KEYS``.

        Returns:
            ``ParsedOwnerMapping`` if an owner tag is found, ``None`` otherwise.
        """
        raise NotImplementedError("Community contribution welcome!")

    # -- parse helper ----------------------------------------------------------

    def _parse_resource(self, raw: Dict[str, Any]) -> ParsedAsset:
        """
        Map a raw EC2 instance dict (+ tags) to ``ParsedAsset``.

        Args:
            raw: Boto3 ``describe_instances`` response element.

        Returns:
            Normalised ``ParsedAsset``.
        """
        tags: Dict[str, str] = {
            t["Key"]: t["Value"] for t in raw.get("Tags", [])
        }
        return ParsedAsset(
            hostname=tags.get("Name"),
            ip_address=raw.get("PrivateIpAddress"),
            asset_type="Virtual Machine",
            environment=tags.get("Environment"),
            criticality=tags.get("Criticality"),
            owner_email=tags.get("Owner"),
            department=tags.get("Department"),
            business_unit=tags.get("BusinessUnit"),
            cost_center=tags.get("CostCenter"),
            operating_system=raw.get("Platform", "linux"),
            location=raw.get("Placement", {}).get("AvailabilityZone"),
            extra={
                "instance_id": raw.get("InstanceId"),
                "instance_type": raw.get("InstanceType"),
                "state": raw.get("State", {}).get("Name"),
                "vpc_id": raw.get("VpcId"),
                "subnet_id": raw.get("SubnetId"),
                "public_ip": raw.get("PublicIpAddress"),
                "launch_time": str(raw.get("LaunchTime", "")),
                "tags": tags,
            },
        )
