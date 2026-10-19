"""Version-pinned private S3 byte adapter. Not asset authorization or release proof."""
from dataclasses import dataclass,field
import base64
import hashlib
import re
import time

from botocore.exceptions import BotoCoreError,ClientError

from proofpack.evidence.repository import StoreConflict,StoreUnavailable
from proofpack.runtime.control import sha,uuid


@dataclass(frozen=True)
class ObjectConfig:
    deployment: str
    bucket: str
    account_id: str
    region: str
    kms_key_arn: str

    def __post_init__(self):
        if (not isinstance(self.deployment,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}',self.deployment)
                or not isinstance(self.bucket,str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',self.bucket)
                or '..' in self.bucket or re.fullmatch(r'\d+\.\d+\.\d+\.\d+',self.bucket)
                or not isinstance(self.account_id,str) or not re.fullmatch(r'\d{12}',self.account_id)
                or not isinstance(self.region,str) or not re.fullmatch(r'[a-z]{2}-[a-z]+-\d',self.region)
                or not isinstance(self.kms_key_arn,str)
                or not re.fullmatch(r'arn:aws:kms:'+re.escape(self.region)+':'+self.account_id+r':key/[a-f0-9-]{36}',self.kms_key_arn)):
            raise ValueError('explicit private S3/account/region/KMS configuration required')
        uuid(self.kms_key_arn.rsplit('/',1)[1])


@dataclass(frozen=True)
class ObjectReceipt:
    asset_id: str
    key: str = field(repr=False)
    version_id: str = field(repr=False)
    source_sha256: str
    context_sha256: str
    byte_length: int
    content_type: str


class EvidenceObjects:
    def __init__(self,client,config:ObjectConfig):
        settings=client.meta.config
        retries=settings.retries or {}
        endpoint=client.meta.endpoint_url
        allowed={'https://s3.'+config.region+'.amazonaws.com'}
        if config.region=='us-east-1':allowed.add('https://s3.amazonaws.com')
        if (client.meta.region_name!=config.region or endpoint not in allowed
                or not 0<settings.connect_timeout<=2 or not 0<settings.read_timeout<=3
                or retries.get('total_max_attempts',retries.get('max_attempts',100)+1)!=1):
            raise ValueError('regional HTTPS S3 client with bounded timeouts and no automatic retries required')
        self.client=client;self.config=config

    def key(self,asset_id):return 'deployments/'+self.config.deployment+'/frames/'+uuid(asset_id)

    def _params(self,asset_id,version_id=None):
        result={'Bucket':self.config.bucket,'Key':self.key(asset_id),'ExpectedBucketOwner':self.config.account_id}
        if version_id is not None:
            if (not isinstance(version_id,str) or not 1<=len(version_id)<=1024 or version_id=='null'
                    or not version_id.isascii() or any(ord(c)<33 for c in version_id)):
                raise StoreUnavailable('versioned evidence object required')
            result['VersionId']=version_id
        return result

    @staticmethod
    def _checksum(digest):return base64.b64encode(bytes.fromhex(sha(digest))).decode()

    def _metadata(self,response,receipt):
        if (response.get('VersionId')!=receipt.version_id or response.get('ContentLength')!=receipt.byte_length
                or response.get('ContentType')!=receipt.content_type or response.get('ServerSideEncryption')!='aws:kms'
                or response.get('SSEKMSKeyId')!=self.config.kms_key_arn
                or response.get('ChecksumSHA256')!=self._checksum(receipt.source_sha256)
                or response.get('Metadata',{}).get('source-sha256')!=receipt.source_sha256
                or response.get('Metadata',{}).get('context-sha256')!=receipt.context_sha256):
            raise StoreUnavailable('evidence object verification failed')

    def put(self,*,asset_id,payload,content_type,context_sha256):
        if not isinstance(payload,bytes) or not 0<len(payload)<=2097152 or content_type not in {'image/jpeg','image/png'}:
            raise ValueError('bounded verified JPEG/PNG bytes required')
        sha(context_sha256);source=hashlib.sha256(payload).hexdigest();params=self._params(asset_id)
        try:
            response=self.client.put_object(**params,Body=payload,ContentLength=len(payload),ContentType=content_type,
                IfNoneMatch='*',ChecksumSHA256=self._checksum(source),ServerSideEncryption='aws:kms',
                SSEKMSKeyId=self.config.kms_key_arn,Metadata={'source-sha256':source,'context-sha256':context_sha256})
            version=response.get('VersionId');self._params(asset_id,version if version is not None else 'null')
            if (response.get('ChecksumSHA256')!=self._checksum(source) or response.get('ServerSideEncryption')!='aws:kms'
                    or response.get('SSEKMSKeyId')!=self.config.kms_key_arn):
                raise StoreUnavailable('evidence write acknowledgement unavailable')
            receipt=ObjectReceipt(asset_id,self.key(asset_id),version,source,context_sha256,len(payload),content_type)
            head=self.client.head_object(**self._params(asset_id,version),ChecksumMode='ENABLED')
            self._metadata(head,receipt)
            return receipt
        except ClientError as exc:
            if exc.response.get('ResponseMetadata',{}).get('HTTPStatusCode') in {409,412}:
                raise StoreConflict('evidence key already exists; reconcile before retry') from exc
            raise StoreUnavailable('evidence object write unavailable; reconcile uncertain output') from exc
        except BotoCoreError as exc:raise StoreUnavailable('evidence transport unavailable; reconcile uncertain output') from exc

    def get(self,receipt:ObjectReceipt):
        if (not isinstance(receipt,ObjectReceipt) or receipt.key!=self.key(receipt.asset_id)
                or type(receipt.byte_length) is not int or not 0<receipt.byte_length<=2097152
                or receipt.content_type not in {'image/jpeg','image/png'}):raise ValueError('bounded owned evidence receipt required')
        sha(receipt.source_sha256);sha(receipt.context_sha256)
        body=None
        try:
            response=self.client.get_object(**self._params(receipt.asset_id,receipt.version_id),ChecksumMode='ENABLED')
            body=response.get('Body')
            self._metadata(response,receipt)
            if body is None:raise StoreUnavailable('evidence bytes unavailable')
            deadline=time.monotonic()+5;payload=bytearray()
            while True:
                chunk=body.read(min(65536,receipt.byte_length+1-len(payload)))
                if time.monotonic()>=deadline:raise StoreUnavailable('evidence read deadline exceeded')
                if not chunk:break
                payload.extend(chunk)
                if len(payload)>receipt.byte_length:raise StoreUnavailable('evidence bytes exceed receipt')
            if len(payload)!=receipt.byte_length or hashlib.sha256(payload).hexdigest()!=receipt.source_sha256:
                raise StoreUnavailable('evidence byte integrity failed')
            return bytes(payload)
        except (ClientError,BotoCoreError,OSError,ValueError) as exc:raise StoreUnavailable('evidence object read unavailable') from exc
        finally:
            if body is not None:body.close()

    def validate(self,receipt:ObjectReceipt):
        if (not isinstance(receipt,ObjectReceipt) or receipt.key!=self.key(receipt.asset_id)
                or type(receipt.byte_length) is not int or not 0<receipt.byte_length<=2097152
                or receipt.content_type not in {'image/jpeg','image/png'}):
            raise ValueError('owned bounded evidence receipt required')
        sha(receipt.source_sha256);sha(receipt.context_sha256)
        try:
            head=self.client.head_object(**self._params(receipt.asset_id,receipt.version_id),ChecksumMode='ENABLED')
            self._metadata(head,receipt)
        except (ClientError,BotoCoreError) as exc:raise StoreUnavailable('evidence object unavailable') from exc


class ReferenceObjects(EvidenceObjects):
    """Distinct owned namespace so reference retention does not inherit frame rules."""
    def key(self,asset_id):return 'deployments/'+self.config.deployment+'/references/'+uuid(asset_id)
