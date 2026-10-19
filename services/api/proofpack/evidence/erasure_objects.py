"""Exact owned-key/version operations; no unversioned delete or retention bypass."""
from dataclasses import dataclass
from botocore.exceptions import BotoCoreError,ClientError
from proofpack.evidence.objects import EvidenceObjects,ReferenceObjects
from proofpack.evidence.repository import StoreUnavailable


@dataclass(frozen=True)
class VersionPage:
    versions:tuple[str,...]
    truncated:bool


class ErasureObjects:
    def __init__(self,frames,references,*,page_size):
        if (not isinstance(frames,EvidenceObjects) or isinstance(frames,ReferenceObjects) or not isinstance(references,ReferenceObjects)
                or frames.config!=references.config or type(page_size) is not int or not 1<=page_size<=1000):
            raise ValueError('shared owned stores and bounded version page required')
        self.frames=frames;self.references=references;self.config=frames.config;self.page_size=page_size

    def store(self,kind):
        if kind not in {'frame','reference'}:raise ValueError('supported owned asset kind required')
        return self.references if kind=='reference' else self.frames

    @staticmethod
    def _version(value):
        if not isinstance(value,str) or not 1<=len(value)<=1024 or not value.isascii() or any(ord(c)<33 for c in value):
            raise StoreUnavailable('explicit listed version identity required')
        return value

    def list(self,kind,ident):
        store=self.store(kind);key=store.key(ident)
        try:
            response=store.client.list_object_versions(Bucket=self.config.bucket,ExpectedBucketOwner=self.config.account_id,Prefix=key,MaxKeys=self.page_size)
            objects=response.get('Versions',[]);markers=response.get('DeleteMarkers',[]);truncated=response.get('IsTruncated')
            if not isinstance(objects,list) or not isinstance(markers,list) or type(truncated) is not bool or len(objects)+len(markers)>self.page_size:
                raise ValueError('bounded complete version page required')
            versions=[]
            for item in [*objects,*markers]:
                if not isinstance(item,dict) or item.get('Key')!=key:raise ValueError('foreign version key rejected')
                versions.append(self._version(item.get('VersionId')))
            if len(set(versions))!=len(versions) or (truncated and not versions):raise ValueError('unambiguous version page required')
            return VersionPage(tuple(versions),truncated)
        except (ClientError,BotoCoreError,KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('owned version listing unavailable') from exc

    def delete(self,kind,ident,versions):
        if not isinstance(versions,tuple) or not 1<=len(versions)<=self.page_size or len(set(versions))!=len(versions):raise ValueError('exact bounded version batch required')
        requested={self._version(v) for v in versions};store=self.store(kind);key=store.key(ident)
        try:
            response=store.client.delete_objects(Bucket=self.config.bucket,ExpectedBucketOwner=self.config.account_id,
                Delete={'Objects':[{'Key':key,'VersionId':v} for v in versions],'Quiet':False})
            deleted=response.get('Deleted',[]);errors=response.get('Errors',[])
            if not isinstance(deleted,list) or not isinstance(errors,list):raise ValueError('explicit per-version outcomes required')
            seen=set();count=0
            for successful,items in ((True,deleted),(False,errors)):
                for item in items:
                    if not isinstance(item,dict) or item.get('Key')!=key:raise ValueError('foreign deletion result rejected')
                    version=self._version(item.get('VersionId'))
                    if version not in requested or version in seen:raise ValueError('unexpected deletion result rejected')
                    seen.add(version);count+=int(successful)
            if seen!=requested:raise ValueError('complete deletion result required')
            return count,bool(errors)
        except (ClientError,BotoCoreError,KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('version removal outcome unconfirmed; relist before retry') from exc
