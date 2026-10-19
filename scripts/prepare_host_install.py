"""Offline closed-wheelhouse bundle preparation; no resolution, download or install."""
import argparse
from copy import deepcopy
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import compatible_tags, cpython_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

from capture_support_contracts import verify_wheel
from install_host_bundle import _decode, _json, _ordinary, _python_target, _read, _write_new

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT
MAX_WHEELS = 64
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
PLATFORMS = [f'manylinux_2_{n}_aarch64' for n in range(5, 29)] + ['manylinux2014_aarch64']
TAGS = set(cpython_tags((3, 12), platforms=PLATFORMS)) | set(compatible_tags((3, 12), interpreter='cp312', platforms=PLATFORMS))
REVIEW_FILES = {'stack.template.json', 'deployment-review.json', 'cost-comparison.json', 'host.service', 'operator-handoff.md'}


def _sha(data): return hashlib.sha256(data).hexdigest()


def _digest(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None: raise ValueError('exact SHA required')
    return value


def _review(directory, expected, artifact):
    directory = Path(directory).absolute(); _ordinary(directory, directory=True)
    raw = _read(directory / 'manifest.json', 65536)
    if _sha(raw) != expected: raise ValueError('review manifest mismatch')
    manifest = _decode(raw)
    if (type(manifest) is not dict or manifest.get('deploy_authorized') is not False
            or manifest.get('status') != 'PREPARED_REVIEW_DRAFT' or manifest.get('beta_decision') != 'NO_GO'
            or type(manifest.get('files')) is not dict or set(manifest['files']) != REVIEW_FILES
            or {p.name for p in directory.iterdir()} != REVIEW_FILES | {'manifest.json'}):
        raise ValueError('completed closed review required')
    files = {n: _read(directory / n, 1024 * 1024) for n in sorted(REVIEW_FILES)}
    if any(_sha(data) != _digest(manifest['files'][n]) for n, data in files.items()):
        raise ValueError('review payload mismatch')
    review = _decode(files['deployment-review.json'])
    if (review.get('deploy_authorized') is not False or review.get('aws_resources_created') is not False
            or review.get('application_started') is not False or review.get('change_set_kind') != 'CREATE_ONLY_DRAFT'
            or review.get('updates_supported') is not False or review.get('declared_artifact_sha256') != artifact):
        raise ValueError('create-only matching artifact review required')
    return raw, files


def _metadata(filename, data, *, python_full_version=None):
    name, version, build, tags = parse_wheel_filename(filename)
    legacy_pure = lambda t: t.interpreter == 'py2' and t.abi == 'none' and t.platform == 'any'
    if not tags & TAGS or any(t not in TAGS and not legacy_pure(t) for t in tags):
        raise ValueError('CPython3.12 manylinux ARM or universal wheel required')
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if not 1 <= len(infos) <= 4096 or sum(i.file_size for i in infos) > MAX_EXPANDED:
            raise ValueError('wheel expansion bound exceeded')
        names = set(); aliases = set(); meta = []
        for info in infos:
            n = info.filename; path = PurePosixPath(n)
            if (not n or len(n) > 256 or path.is_absolute() or '..' in path.parts or ':' in n or '\\' in n
                    or n in names or n.casefold() in aliases or stat.S_ISLNK(info.external_attr >> 16)
                    or n.lower().endswith('.pth') or info.flag_bits & 1):
                raise ValueError('unsafe wheel member')
            names.add(n); aliases.add(n.casefold())
            if n.endswith('.dist-info/METADATA'):
                if info.file_size > 128 * 1024: raise ValueError('metadata bound exceeded')
                meta.append(n)
        if len(meta) != 1: raise ValueError('one distribution metadata required')
        wheel_path = meta[0].rsplit('/', 1)[0] + '/WHEEL'
        if wheel_path not in names or z.getinfo(wheel_path).file_size > 128 * 1024:
            raise ValueError('bounded WHEEL metadata required')
        wheel_metadata = BytesParser().parsebytes(z.read(wheel_path))
        if wheel_metadata.get_all('Wheel-Version', []) != ['1.0']:
            raise ValueError('supported wheel format required')
        from packaging.tags import parse_tag
        declared_tags = set()
        for declared in wheel_metadata.get_all('Tag', []): declared_tags |= parse_tag(declared)
        if declared_tags != tags: raise ValueError('filename and WHEEL tags must agree')
        message = BytesParser().parsebytes(z.read(meta[0]))
        if len(message.get_all('Name', [])) != 1 or len(message.get_all('Version', [])) != 1:
            raise ValueError('unambiguous distribution identity required')
        from packaging.version import Version
        if canonicalize_name(message['Name']) != name or Version(message['Version']) != version:
            raise ValueError('wheel filename metadata mismatch')
        pythons = message.get_all('Requires-Python', [])
        if len(pythons) > 1 or (pythons and not SpecifierSet(pythons[0]).contains(python_full_version or '3.12.0', prereleases=True)):
            raise ValueError('Python3.12 target incompatible')
        requirements = [Requirement(r) for r in message.get_all('Requires-Dist', [])]
        if any(r.url for r in requirements): raise ValueError('direct dependency URL forbidden')
        # Kernel facts are never supplied; a Python patch must be explicit, not inferred.
        if any(r.marker and re.search(r'\b(platform_release|platform_version)\b', str(r.marker))
               for r in requirements):
            raise ValueError('exact kernel marker target is not supplied')
        if python_full_version is None and any(r.marker and re.search(r'\b(python_full_version|implementation_version)\b', str(r.marker))
                                               for r in requirements):
            raise ValueError('exact patch marker target is not supplied')
        extras = {canonicalize_name(e) for e in message.get_all('Provides-Extra', [])}
        return dict(name=name, version=version, requirements=requirements, extras=extras,
                    expanded=sum(i.file_size for i in infos))


def _closure(distributions, *, python_full_version=None):
    if 'proofpack' not in distributions: raise ValueError('application wheel required')
    environment = default_environment() | dict(implementation_name='cpython', implementation_version=python_full_version or '3.12.0',
        os_name='posix', platform_machine='aarch64', platform_python_implementation='CPython',
        platform_release='', platform_system='Linux', platform_version='', python_full_version=python_full_version or '3.12.0',
        python_version='3.12', sys_platform='linux')
    wanted = {'proofpack': set()}; visited = {}; pending = ['proofpack']; visits = 0
    while pending:
        visits += 1
        if visits > 4096: raise ValueError('dependency graph bound exceeded')
        name = pending.pop(); selected = wanted[name]
        if name in visited and visited[name] == selected: continue
        visited[name] = set(selected)
        dist = distributions[name]
        if not selected <= dist['extras']: raise ValueError('undeclared requested extra')
        for req in dist['requirements']:
            if req.marker and not any(req.marker.evaluate(environment | {'extra': e}) for e in {''} | selected): continue
            dependency = canonicalize_name(req.name)
            if dependency not in distributions or not req.specifier.contains(distributions[dependency]['version'], prereleases=True):
                raise ValueError('complete compatible dependency closure required')
            extras = {canonicalize_name(e) for e in req.extras}
            if dependency not in wanted:
                wanted[dependency] = extras; pending.append(dependency)
            elif not extras <= wanted[dependency]:
                wanted[dependency] |= extras; pending.append(dependency)
    if set(wanted) != set(distributions): raise ValueError('unreachable distribution forbidden')


def prepare(value, review_directory, wheelhouse):
    plan = deepcopy(value)
    fields = {'schema_version', 'review_manifest_sha256', 'artifact_sha256', 'wheels'}
    if (type(plan) is not dict or set(plan) not in (fields, fields | {'python_full_version'})
            or type(plan['schema_version']) is not int or plan['schema_version'] != 1
            or type(plan['wheels']) is not dict or not 1 <= len(plan['wheels']) <= MAX_WHEELS):
        raise ValueError('closed complete install plan required')
    python_full_version = _python_target(plan)
    _digest(plan['artifact_sha256']); _digest(plan['review_manifest_sha256'])
    raw_review, review = _review(review_directory, plan['review_manifest_sha256'], plan['artifact_sha256'])
    house = Path(wheelhouse).absolute(); _ordinary(house, directory=True)
    if {p.name for p in house.iterdir()} != set(plan['wheels']): raise ValueError('exact wheelhouse inventory required')
    payloads = {}; distributions = {}; total = 0; expanded = 0; application = None
    for filename, expected in sorted(plan['wheels'].items()):
        if type(filename) is not str or re.fullmatch(r'[A-Za-z0-9_.+-]{1,180}\.whl', filename) is None:
            raise ValueError('ordinary wheel filename required')
        data = _read(house / filename, MAX_FILE); total += len(data)
        if total > MAX_TOTAL or _sha(data) != _digest(expected): raise ValueError('wheel digest or total bound mismatch')
        metadata = _metadata(filename, data, python_full_version=python_full_version); expanded += metadata['expanded']
        if expanded > 2 * MAX_EXPANDED or metadata['name'] in distributions: raise ValueError('duplicate or expanded inventory bound')
        distributions[metadata['name']] = metadata
        if metadata['name'] == 'proofpack':
            if _sha(data) != plan['artifact_sha256']: raise ValueError('application digest mismatch')
            application = filename
        payloads['wheelhouse/' + filename] = data
    _closure(distributions, python_full_version=python_full_version)
    runtime = verify_wheel(house / application, SOURCE_ROOT)
    # Check the path read by the existing archive verifier still names our snapshot.
    if _read(house / application, MAX_FILE) != payloads['wheelhouse/' + application]:
        raise ValueError('application changed during source verification')
    requirements = ''.join(f'{name}=={d["version"]} --hash=sha256:{plan["wheels"][filename]}\n'
                           for name, d in sorted(distributions.items())
                           for filename in plan['wheels'] if parse_wheel_filename(filename)[0] == name)
    report = dict(schema_version=1, status='PREPARED_INSTALL_REVIEW', install_authorized=False,
        beta_decision='NO_GO', native_arm_installation='NOT_RUN', dependency_provenance='CALLER_DECLARED_NOT_VERIFIED',
        application_wheel=application, runtime_members=len(runtime), distributions=sorted(distributions),
        target='CPython3.12/Linux/aarch64/glibc>=2.28', application_started=False,
        service_installed=False, existing_host_updates_supported=False)
    report['python_full_version'] = python_full_version
    payloads.update({'plan.json': _json(plan), 'report.json': report, 'requirements.lock': requirements.encode(),
        'install.py': _read(SOURCE_ROOT / 'scripts/install_host_bundle.py', 1024 * 1024),
        'host.service': review['host.service'], 'review-manifest.json': raw_review,
        'operator-handoff.md': review['operator-handoff.md'] + b'\n\nHost bundle: independently review native wheel provenance, actual ARM/glibc/Python, service account and exact manifest SHA. Invoke install.py only under actual host/action authority. No service/config/user/AWS/owner creation or startup. Fixed fresh /opt/proofpack only; retain partial failure, no automatic retry/cleanup/update. Actual native install remains NOT_RUN until separately exercised.\n'})
    return payloads


def write_bundle(value, review_directory, wheelhouse, output):
    plan = deepcopy(value); pack = prepare(plan, review_directory, wheelhouse)
    raw = Path(output)
    if raw.exists() or raw.is_symlink(): raise FileExistsError('new bundle directory required')
    target = raw.resolve(); root = ROOT.resolve()
    if target == root or not target.is_relative_to(root): raise ValueError('bundle output must stay inside checkout')
    payloads = {name: data if isinstance(data, bytes) else _json(data) for name, data in pack.items()}
    target.mkdir(mode=0o700); (target / 'wheelhouse').mkdir(mode=0o700)
    files = {}
    for name, data in payloads.items():
        _write_new(target / name, data)
        if _read(target / name, MAX_FILE) != data: raise OSError('bundle write mismatch')
        files[name] = _sha(data)
    def verify():
        if any(_read(target / name, MAX_FILE) != data for name, data in payloads.items()):
            raise OSError('bundle payload changed before completion')
    verify()
    manifest = dict(schema_version=1, status='PREPARED_INSTALL_REVIEW', files=files,
        plan_sha256=_sha(payloads['plan.json']), install_authorized=False, beta_decision='NO_GO')
    marker = target / 'manifest.json'; encoded = _json(manifest)
    try:
        _write_new(marker, encoded)
        if _read(marker, 65536) != encoded: raise OSError('bundle manifest changed')
        verify()
    except BaseException:
        marker.unlink(missing_ok=True)
        raise
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline ARM install bundle; no downloads, installation or service startup')
    parser.add_argument('--plan', required=True); parser.add_argument('--review', required=True)
    parser.add_argument('--wheelhouse', required=True); parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        plan = _decode(_read(Path(args.plan).absolute(), 65536))
        result = write_bundle(plan, args.review, args.wheelhouse, args.output)
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile):
        print('INSTALL_BUNDLE_HELD: inspect plan, review and complete compatible local wheelhouse; no install or authority implied', file=sys.stderr)
        return 2
    print(json.dumps(dict(status=result['status'], files=len(result['files']), install_authorized=False, beta_decision='NO_GO')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
