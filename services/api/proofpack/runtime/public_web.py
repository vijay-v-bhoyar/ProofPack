"""Capture a bounded immutable public boot package; no mutable-path response delivery."""
from dataclasses import dataclass,field
from html.parser import HTMLParser
from pathlib import Path
import hashlib
import re

MAX_ASSETS=8
MAX_INDEX_BYTES=32768
MAX_PACKAGE_BYTES=4194304
NAME=re.compile(r'[A-Za-z0-9_-]{1,100}\.(js|css)')


@dataclass(frozen=True)
class PublicAsset:
    path:str
    media_type:str
    content:bytes=field(repr=False)

    @property
    def sha256(self):return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class FrozenWeb:
    assets:tuple[PublicAsset,...]

    def __post_init__(self):
        if (type(self.assets) is not tuple or not 2<=len(self.assets)<=MAX_ASSETS+1
                or any(type(a) is not PublicAsset or type(a.path) is not str or type(a.content) is not bytes or not a.content
                    or a.media_type not in {'text/html','text/javascript','text/css'} for a in self.assets)
                or len({a.path for a in self.assets})!=len(self.assets)
                or sum(len(a.content) for a in self.assets)>MAX_PACKAGE_BYTES
                or any((a.media_type!='text/html' or len(a.content)>MAX_INDEX_BYTES) if a.path=='/' else
                    (not a.path.startswith('/assets/') or NAME.fullmatch(a.path.removeprefix('/assets/')) is None
                     or a.media_type!=('text/javascript' if a.path.endswith('.js') else 'text/css')) for a in self.assets)
                or sum(a.path=='/' for a in self.assets)!=1):
            raise ValueError('bounded immutable public web package required')

    @property
    def paths(self):return frozenset(a.path for a in self.assets)

    def get(self,path):return next((a for a in self.assets if a.path==path),None)


class References(HTMLParser):
    def __init__(self):super().__init__(convert_charrefs=True);self.paths=set();self.scripts=0;self.in_script=False
    def handle_starttag(self,tag,attrs):
        values=dict(attrs)
        if tag=='script':
            if values.get('type')!='module' or re.fullmatch(r'/assets/[A-Za-z0-9_-]{1,100}\.js',values.get('src','')) is None:raise ValueError('external bounded module reference required')
            self.paths.add(values['src']);self.scripts+=1;self.in_script=True
        if tag=='link':
            if values.get('rel')!='stylesheet' or re.fullmatch(r'/assets/[A-Za-z0-9_-]{1,100}\.css',values.get('href','')) is None:raise ValueError('bounded stylesheet reference required')
            self.paths.add(values['href'])
    def handle_endtag(self,tag):
        if tag=='script':self.in_script=False
    def handle_data(self,value):
        if self.in_script and value.strip():raise ValueError('inline boot code unavailable')


def _read(path,limit):
    if (path.is_symlink() or getattr(path,'is_junction',lambda:False)() or not path.is_file()):
        raise ValueError('ordinary built public file required')
    with path.open('rb') as file:content=file.read(limit+1)
    if not content or len(content)>limit:raise ValueError('bounded complete public file required')
    return content


def freeze_web(directory):
    root=Path(directory)
    if root.is_symlink() or getattr(root,'is_junction',lambda:False)():raise ValueError('ordinary web package directory required')
    folder=root/'assets'
    if folder.is_symlink() or getattr(folder,'is_junction',lambda:False)() or not folder.is_dir():
        raise ValueError('complete flat built assets required')
    index=_read(root/'index.html',MAX_INDEX_BYTES);items=[PublicAsset('/','text/html',index)]
    for path in folder.iterdir():
        if len(items)>MAX_ASSETS or NAME.fullmatch(path.name) is None:raise ValueError('bounded supported built assets required')
        content=_read(path,MAX_PACKAGE_BYTES-sum(len(a.content) for a in items))
        items.append(PublicAsset('/assets/'+path.name,'text/javascript' if path.suffix=='.js' else 'text/css',content))
    frozen=FrozenWeb(tuple(items));references=References();references.feed(index.decode('utf-8'));references.close()
    if references.scripts<1 or not references.paths<=frozen.paths:raise ValueError('complete local boot references required')
    return frozen
