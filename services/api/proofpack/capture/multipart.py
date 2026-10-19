"""Bounded in-memory streaming multipart parsing; never decodes or spools images."""
from dataclasses import dataclass,field
import asyncio
import re
from uuid import UUID

from python_multipart import MultipartParser
from python_multipart.exceptions import FormParserError
from starlette.exceptions import HTTPException
from starlette.requests import ClientDisconnect

MAX_IMAGE=2097152
MAX_BODY=MAX_IMAGE+8192
BOUNDARY=r"[A-Za-z0-9'()+_,./:=?\-]{1,70}"


@dataclass(frozen=True)
class Upload:
    permit_id:str
    nonce:str=field(repr=False)
    sequence:int
    content_type:str
    payload:bytes=field(repr=False)


class ImageMultipart:
    def __init__(self,content_type,*,fields=('permit_id','nonce','sequence'),field_limit=64):
        if (not isinstance(fields,tuple) or not fields or len(fields)>3 or len(set(fields))!=len(fields)
                or any(not isinstance(name,str) or not re.fullmatch(r'[a-z_]{1,32}',name) or name=='image' for name in fields)
                or type(field_limit) is not int or not 1<=field_limit<=4096):raise ValueError('bounded server multipart fields required')
        self.fields=fields;self.field_limit=field_limit
        if not isinstance(content_type,str) or len(content_type)>256:raise HTTPException(415)
        match=re.fullmatch(r'multipart/form-data\s*;\s*boundary=(?:"('+BOUNDARY+r')"|('+BOUNDARY+r'))\s*',content_type,re.I)
        if match is None:raise HTTPException(415)
        boundary=(match[1] or match[2]).encode('ascii')
        self.prefix=b'--'+boundary+b'\r\n';self.start=bytearray();self.total=0
        self.parts={};self.image=bytearray();self.mime=None;self.name=None;self.count=0;self.ended=False
        self.headers={};self.header_name=bytearray();self.header_value=bytearray();self.data=bytearray()
        self.parser=MultipartParser(boundary,{name:getattr(self,name) for name in
            ('on_part_begin','on_header_field','on_header_value','on_header_end','on_headers_finished',
             'on_part_data','on_part_end','on_end')},max_size=MAX_BODY,max_header_count=2,max_header_size=512)

    def on_part_begin(self):
        self.count+=1
        if self.count>len(self.fields)+1:raise HTTPException(400)
        self.headers={};self.header_name=bytearray();self.header_value=bytearray();self.data=bytearray();self.name=None

    def on_header_field(self,data,start,end):self.header_name.extend(data[start:end])
    def on_header_value(self,data,start,end):self.header_value.extend(data[start:end])
    def on_header_end(self):
        name=bytes(self.header_name).lower();value=bytes(self.header_value)
        if name not in {b'content-disposition',b'content-type'} or name in self.headers:raise HTTPException(400)
        self.headers[name]=value;self.header_name.clear();self.header_value.clear()

    def on_headers_finished(self):
        value=self.headers.get(b'content-disposition',b'')
        names='|'.join(('image',*self.fields)).encode('ascii')
        match=re.fullmatch(rb'form-data;\s*name="('+names+rb')"(?:;\s*filename="[^"\r\n]{0,256}")?',value)
        if match is None:raise HTTPException(400)
        self.name=match[1].decode('ascii')
        if self.name in self.parts:raise HTTPException(400)
        file_part=b';' in value and b'filename=' in value
        if (self.name=='image')!=file_part:raise HTTPException(400)
        mime=self.headers.get(b'content-type')
        if self.name=='image':
            if mime not in {b'image/jpeg',b'image/png'}:raise HTTPException(415)
            self.mime=mime.decode('ascii')
        elif mime not in {None,b'text/plain'}:raise HTTPException(415)

    def on_part_data(self,data,start,end):
        limit=MAX_IMAGE if self.name=='image' else self.field_limit
        if len(self.data)+end-start>limit:raise HTTPException(413)
        self.data.extend(data[start:end])

    def on_part_end(self):
        if self.name is None or self.name in self.parts:raise HTTPException(400)
        if self.name=='image':self.image=self.data;self.parts[self.name]=None
        else:
            try:self.parts[self.name]=self.data.decode('ascii')
            except UnicodeDecodeError as exc:raise HTTPException(400) from exc

    def on_end(self):self.ended=True

    def write(self,chunk):
        self.total+=len(chunk)
        if self.total>MAX_BODY:raise HTTPException(413)
        if len(self.start)<len(self.prefix):
            self.start.extend(chunk[:len(self.prefix)-len(self.start)])
            if not self.prefix.startswith(self.start):raise HTTPException(400)
        try:self.parser.write(chunk)
        except FormParserError as exc:raise HTTPException(400) from exc

    def finish_parts(self):
        if not self.ended or set(self.parts)!={'image',*self.fields}:raise HTTPException(400)
        payload=bytes(self.image)
        if not payload or not (payload.startswith(b'\x89PNG\r\n\x1a\n') if self.mime=='image/png' else payload.startswith(b'\xff\xd8\xff')):
            raise HTTPException(415)
        return self.parts,self.mime,payload

    def finish(self):
        parts,mime,payload=self.finish_parts()
        try:
            permit=str(UUID(self.parts['permit_id']))
            if permit!=self.parts['permit_id']:raise ValueError('canonical UUID required')
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}',self.parts['nonce']):raise ValueError('bounded nonce required')
            if not re.fullmatch(r'[1-9][0-9]{0,11}',self.parts['sequence']):raise ValueError('bounded sequence required')
        except (ValueError,TypeError,AttributeError) as exc:raise HTTPException(400) from exc
        return Upload(permit,parts['nonce'],int(parts['sequence']),mime,payload)


async def receive_upload(request,*,parser_factory=ImageMultipart):
    if len(request.headers.getlist('content-type'))!=1:raise HTTPException(415)
    if len(request.headers.getlist('content-encoding'))>1:raise HTTPException(415)
    if request.headers.get('content-encoding','identity').lower()!='identity':raise HTTPException(415)
    transfers=request.headers.getlist('transfer-encoding')
    if len(transfers)>1 or (transfers and transfers[0].lower()!='chunked'):raise HTTPException(400)
    lengths=request.headers.getlist('content-length')
    if len(lengths)>1:raise HTTPException(400)
    if lengths and transfers:raise HTTPException(400)
    if lengths:
        if not re.fullmatch(r'[0-9]{1,12}',lengths[0]):raise HTTPException(400)
        if int(lengths[0])>MAX_BODY:raise HTTPException(413)
    parser=parser_factory(request.headers['content-type'])
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():parser.write(chunk)
    except TimeoutError as exc:raise HTTPException(408) from exc
    except ClientDisconnect as exc:raise HTTPException(400) from exc
    if lengths and int(lengths[0])!=parser.total:raise HTTPException(400)
    return parser.finish()
