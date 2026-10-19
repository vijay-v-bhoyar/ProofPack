"""Reference media normalization inside the bounded child, never pass authority."""
import hashlib

import cv2
from pydantic import Field,model_validator

from proofpack.recipes.models import Contract
from proofpack.vision.pipeline import InvalidImage,decode_image


class ReferenceMetadata(Contract):
    width:int=Field(ge=16,le=2000)
    height:int=Field(ge=16,le=2000)
    byte_length:int=Field(gt=0,le=2097152)
    source_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    stored_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    content_type:str=Field(pattern=r'^image/jpeg$')

    @model_validator(mode='after')
    def pixels(self):
        if self.width*self.height>2000000:raise ValueError('reference pixel limit')
        return self


def normalize_reference(payload,content_type,*,max_bytes):
    if (content_type not in {'image/jpeg','image/png'} or not isinstance(payload,bytes)
            or not (payload.startswith(b'\xff\xd8\xff') if content_type=='image/jpeg' else payload.startswith(b'\x89PNG\r\n\x1a\n'))):
        raise InvalidImage('reference format mismatch')
    frame=decode_image(payload,max_bytes=max_bytes)
    height,width=frame.shape[:2]
    if max(height,width)>2000:raise InvalidImage('reference dimensions outside bounds')
    ok,encoded=cv2.imencode('.jpg',frame,[cv2.IMWRITE_JPEG_QUALITY,85])
    canonical=encoded.tobytes() if ok else b''
    metadata=ReferenceMetadata(width=width,height=height,byte_length=len(canonical),
        source_sha256=hashlib.sha256(payload).hexdigest(),stored_sha256=hashlib.sha256(canonical).hexdigest(),content_type='image/jpeg')
    return metadata,canonical
