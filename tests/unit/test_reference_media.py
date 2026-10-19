"""Reference parser/provenance bounds and actual Windows child normalization."""
import hashlib
from io import BytesIO
import json
from uuid import uuid4

from PIL import Image,PngImagePlugin
import pytest
from starlette.exceptions import HTTPException

from proofpack.evidence.http import ReferenceMultipart
from proofpack.vision.reference import ReferenceMetadata
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker import WorkerUnavailable,VisionWorker
from proofpack.vision.worker_limits import WorkerLimits


def limits():return WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0)


def wire(*,metadata=None,extra=b'',image=b'\x89PNG\r\n\x1a\nfixture-prefix'):
    value=metadata if metadata is not None else json.dumps({'purpose_id':str(uuid4()),'source_permission_reference':'owned-1','data_origin':'synthetic','expires_at_ms':100000})
    return (b'--ref-boundary\r\nContent-Disposition: form-data; name="metadata"\r\n\r\n'+value.encode()+b'\r\n'
        +b'--ref-boundary\r\nContent-Disposition: form-data; name="image"; filename="ignored.png"\r\nContent-Type: image/png\r\n\r\n'+image+b'\r\n'
        +extra+b'--ref-boundary--\r\n')


def parse(body):
    parser=ReferenceMultipart('multipart/form-data; boundary=ref-boundary')
    for offset in range(0,len(body),17):parser.write(body[offset:offset+17])
    return parser.finish()


def test_reference_parser_has_exact_fields_and_preserves_only_bounded_input():
    metadata,mime,payload=parse(wire())
    assert metadata.data_origin.value=='synthetic' and mime=='image/png' and payload.startswith(b'\x89PNG')
    assert metadata.model_dump().keys()=={'purpose_id','source_permission_reference','data_origin','expires_at_ms'}


@pytest.mark.parametrize('change',[lambda value:value[:-8],lambda value:value.replace(b'name="metadata"',b'name="passed"'),
    lambda value:value.replace(b'name="metadata"',b'name="permit_id"'),lambda value:b'preamble'+value,
    lambda value:value.replace(b'Content-Type: image/png',b'Content-Type: image/png\r\nContent-Type: image/png'),
    lambda value:value.replace(b'name="image"; filename="ignored.png"',b'name="image"')])
def test_reference_parser_rejects_unknown_or_malformed_parts(change):
    with pytest.raises((HTTPException,ValueError)):parse(change(wire()))


@pytest.mark.parametrize('metadata',['{}','x'*4097,json.dumps({'purpose_id':'f1000000-0000-4000-8000-000000000001','source_permission_reference':'owned-1',
    'data_origin':'synthetic','expires_at_ms':True}),json.dumps({'purpose_id':'f1000000-0000-4000-8000-000000000002','source_permission_reference':'owned-1',
    'data_origin':'synthetic','expires_at_ms':100000,'passed':True})],ids=['missing-required','oversized','strict-expiry-type','forged-pass'])
def test_reference_metadata_is_bounded_strict_and_cannot_assert_pass(metadata):
    with pytest.raises((HTTPException,ValueError)):parse(wire(metadata=metadata))


@pytest.mark.parametrize('changes',[{'width':2001},{'width':2000,'height':2000},{'height':15},{'byte_length':2097153},
    {'byte_length':0},{'stored_sha256':'bad'},{'source_sha256':'bad'},{'content_type':'image/png'}])
def test_reference_reply_cannot_exceed_limits_or_change_type(changes):
    values={'width':64,'height':64,'byte_length':500,'source_sha256':'a'*64,'stored_sha256':'b'*64,'content_type':'image/jpeg',**changes}
    with pytest.raises(ValueError):ReferenceMetadata.model_validate(values)


def test_actual_child_strips_source_metadata_and_returns_distinct_verified_canonical_hash():
    image=Image.new('RGB',(64,48),(15,75,45));info=PngImagePlugin.PngInfo();info.add_text('PrivateLocation','synthetic-not-for-storage')
    source=BytesIO();image.save(source,format='PNG',pnginfo=info);payload=source.getvalue()
    with VisionWorker(limits()) as worker:
        metadata,canonical=worker.reference(payload,content_type='image/png')
        assert metadata.width==64 and metadata.height==48 and metadata.source_sha256==hashlib.sha256(payload).hexdigest()
        assert metadata.stored_sha256==hashlib.sha256(canonical).hexdigest() and metadata.stored_sha256!=metadata.source_sha256
        assert b'PrivateLocation' not in canonical and b'synthetic-not-for-storage' not in canonical
        with Image.open(BytesIO(canonical)) as normalized:assert normalized.format=='JPEG' and not normalized.getexif()
        assert worker.available


def test_actual_child_rejects_unsupported_orientation_and_permanently_closes():
    image=Image.new('RGB',(64,48));exif=Image.Exif();exif[274]=6;source=BytesIO();image.save(source,format='JPEG',exif=exif)
    with VisionWorker(limits()) as worker:
        with pytest.raises(WorkerUnavailable):worker.reference(source.getvalue(),content_type='image/jpeg')
        assert worker.available is False


def test_registry_shutdown_interrupts_owned_diagnostic_and_releases_its_lease_once():
    registry=WorkerRegistry(limits(),max_processes=1)
    with registry.diagnostic(runtime_id=str(uuid4())) as worker:
        assert worker.available;registry.close();assert not worker.available
    assert registry._diagnostics=={}
    registry.close()
