"""Bundle a prebuilt frontend; never install Node packages or contact a registry."""
from pathlib import Path
from html.parser import HTMLParser
import re
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py


class References(HTMLParser):
    def __init__(self):super().__init__();self.references=[];self.invalid=False;self.scripts=0
    def handle_starttag(self,tag,attributes):
        if tag not in {'script','link'}:return
        name='src' if tag=='script' else 'href';values=[value for key,value in attributes if key==name]
        if len(values)!=1 or values[0] is None or not re.fullmatch(r'/assets/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',values[0]):
            self.invalid=True;return
        parts=values[0].lstrip('/').split('/')
        if any(part in {'.','..'} for part in parts):self.invalid=True;return
        self.references.append(Path(*parts))
        if tag=='script':self.scripts+=1


class BuildPy(build_py):
    def run(self):
        source=Path(__file__).resolve().parent/'apps/web/dist'
        paths=sorted(source.rglob('*')) if source.is_dir() else []
        files=[path for path in paths if path.is_file()]
        if (not (source/'index.html').is_file() or not (source/'assets').is_dir()
                or not any(path.parent==source/'assets' and path.suffix=='.js' for path in files)
                or not 2<=len(files)<=32 or sum(path.stat().st_size for path in files)>10485760
                or any(path.is_symlink() for path in paths) or source.is_symlink()
                or any(path.relative_to(source).parts[0]!='assets' and path.relative_to(source).as_posix()!='index.html' for path in files)):
            raise RuntimeError('Build the complete bounded frontend with npm run build before building the Python package.')
        references=References()
        references.feed((source/'index.html').read_text(encoding='utf-8'));references.close()
        if references.invalid or references.scripts<1 or any(not (source/path).is_file() for path in references.references):
            raise RuntimeError('Build the complete bounded frontend: index references missing or unsupported assets.')
        super().run()
        destination=Path(self.build_lib)/'proofpack/web'
        # Remove only our generated build destination, never source or arbitrary paths.
        if destination.exists():
            root=Path(self.build_lib).resolve();target=destination.resolve()
            if target!=root/'proofpack/web':raise RuntimeError('unexpected generated asset destination')
            shutil.rmtree(target)
        shutil.copytree(source,destination)


setup(cmdclass={'build_py':BuildPy})
