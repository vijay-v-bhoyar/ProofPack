# Source and provenance register

## Genuine pinned artifact and Python-target sources — October18,2026

All32 exact-version public PyPI JSON URLs, raw-response hashes and selected filenames are preserved in the [metadata observation](../.loop/repairs/arm-artifacts/metadata-review-v1.json); [download receipt](../.loop/repairs/arm-artifacts/download-receipt-v1.json) binds published/observed SHA256 for32 actual files. [OpenCV5.0.0.93 JSON](https://pypi.org/pypi/opencv-python/5.0.0.93/json) and [cryptography50.0.2 JSON](https://pypi.org/pypi/cryptography/50.0.2/json) are primary release locators. Actual cryptography wheel METADATA supplied the full-Python marker that held without an explicit patch. These establish observed bytes/metadata availability, not independent publisher attestation, native imports or host suitability. No package substitution or install occurred.

[Python3.12.15 release](https://www.python.org/downloads/release/python-31215/) identifies the September30,2026 security/source-only release used as a provisional declared ARM build candidate. No actual image/interpreter was obtained or attested; local tools remain3.12.3. [PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) defines environment-marker context. The new optional exact target supplies Python/implementation patch facts only; kernel facts remain absent. [Current AT contract](../.loop/repairs/arm-artifacts/contract.md) and [verification](../.loop/repairs/arm-artifacts/verification-current-v1.json) define implementation/evidence limits. Earlier no-target marker restrictions below describe the legacy omitted-field path; supplied exact-patch support supersedes their blanket Python-marker wording, while kernel denials remain.

[PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) defines deployment-dependent markers. HI target scope pins OS/architecture/Python minor, so patch/kernel marker mentions are explicitly rejected until an exact-target contract exists. This is a conservative input restriction, not full support for every valid dependency marker.

## Host bundle and fresh installer references — October 18, 2026

Primary sources inform HI01–HI08; no fetched wheel, actual host, package provenance or native release acceptance is claimed. [PyPA platform tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/) defines interpreter/ABI/platform and compressed tag sets, including universal pure formats; [wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/) defines WHEEL/METADATA/archive identity. Local matching metadata is not binary usability. [pip secure installation guidance](https://pip.pypa.io/en/stable/topics/secure-installs/) supports explicit pinned hashes for every dependency and binary-only input; the tool also uses no-index/no-deps with validated supplied closure. Actual package hashes are caller declarations until independently verified. These references do not establish supported ARM artifacts, glibc/Python/AMI suitability, action authority or a successful native install.

## Offline AWS review-tool references — October 18, 2026

These primary references informed DP01–DP08 declarations; they are not provider validation, deployment proof or real pricing estimates. [Local contract](../.loop/repairs/aws-review-pack/contract.md) and [verification](../.loop/repairs/aws-review-pack/verification-current-v1.json) delimit actual evidence.

- [DynamoDB service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_dynamodb.html): transaction operations map to underlying GetItem/PutItem/UpdateItem/DeleteItem/ConditionCheckItem IAM actions; the tool does not invent TransactWriteItems IAM permission.
- [Launch template data](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-launchtemplatedata.html) and [network interfaces](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-networkinterface.html): explicit private-host, metadata and profile draft properties; actual AMI/root layout remains unverified.
- [Security groups](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html): explicit egress and avoidance of two-way embedded security-group references. Local DAG assertions do not prove deployed network controls.
- [Cognito app client](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html): public code-flow client without generated secret. Actual provider/MFA support remains unverified.
- [CloudFormation conditions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/conditions-section-structure.html): updates reevaluate conditions and can remove resources, so generator is CREATE_ONLY_DRAFT with no supported update path.
- [S3 naming rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html): alphanumeric endings and reserved suffix constraints; actual global uniqueness/availability NOT_RUN.

Synthetic calculator URLs/amounts in the example are fake format fixtures, not fetched quotes, E14 evidence or a spending cap. No real region recommendation was established by that arithmetic.

Research date: October 13, 2026. Links support factual platform/rule constraints; architecture, thresholds and schedules are proposed design decisions. No vendor claim proves ProofPack performance. Preserve a fresh dated snapshot/version at implementation and submission when relying on mutable material.

| Source | Use |
|---|---|
| [Devpost overview](https://opencv26.devpost.com/) | Core stack, deliverables, special-path qualification and conflicting deadline times |
| [Devpost rules](https://opencv26.devpost.com/rules) | Rubrics, eligibility, rights, responsible-use and award terms |
| [OpenCV competition site](https://opencv.org/opencv-ai-competition-2026/) | Organizer context; unresolved team-size/older schedule text |
| [Late-entry manager reply](https://opencv26.devpost.com/forum_topics/45369-late-entry-without-a-proposal-and-the-video-shows-the-team) | Proposal omission does not exclude late entrants |
| [OpenCV 5 documentation](https://docs.opencv.org/5.0/) | Current major-version/API/build changes; verify actual imported modules |
| [COOL Marketplace](https://aws.amazon.com/marketplace/pp/prodview-fdvbfiewzuehs) | Version/Arm AMI delivery and separate costs; no license/deployment acceptance implied |
| [COOL benchmarks](https://github.com/opencv/COOL-Benchmark) | Methodology reference; never replace our workload results |
| [Cognito clients](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html) | Authorization code and PKCE configuration |
| [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html) | Atomic writes, conditions and no duplicate item actions |
| [DynamoDB transactional reads](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html) | Consistent multi-item snapshot for effective state and binding checks |
| [DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html) | Cleanup is asynchronous; enforce read-time expiration ourselves |
| [S3 presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html) | Authorized expiring bearer access; app checks still required |
| [Bedrock tool use](https://docs.aws.amazon.com/bedrock/latest/userguide/tool-use.html) | Optional tool-call integration, subject to actual model support |
| [AWS Pricing Calculator](https://calculator.aws/) | Future region/architecture cost comparison; no quote calculated yet |
| [Tulip Laerdal case study](https://tulip.co/case-studies/laerdal-medical/) | Vendor-reported kit checking and photograph capture establish category overlap; refreshed October 13, 2026 |

The [product direction](../VISION.md) owns the accepted positioning and moat hypotheses. Earlier concept iterations and subjective score histories are superseded by that baseline. Devpost connector access to custom submission-form fields remains unavailable; public official pages supplied the rule review.

Source assertions should be rechecked when a version, pricing region, event rule or provider capability changes. Pin resolved software/artifacts, record the actual runtime and keep source links near claims in the technical report.

## Local integration dependency

DynamoDB Local setup, dummy credentials and runtime requirements: [official AWS instructions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html). The downloaded official archive reported version 3.3.1; its published ZIP checksum and all extracted file hashes are pinned in [the dependency lock](../tools/dynamodb-local.lock.json). The source URL is a rolling vendor path, so a changed upstream checksum requires an explicit lock review. Local emulator results are not hosted AWS evidence.

## Cognito authorization flow

Implementation references checked for the local authorization-flow component: [authorization endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html) (state round trip and ID-token nonce), [S256 PKCE](https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html) (authorization challenge and token-exchange verifier), and [token endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html). These sources inform the contract; local flow tests do not establish actual provider configuration, token validation or MFA.

Token-verifier references: [Cognito JWT verification](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html), [ID-token claims](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html), [ACR/AMR and native TOTP level four](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-step-up-authentication.html), and [PyJWT verification usage](https://pyjwt.readthedocs.io/en/stable/usage.html). The current AWS guidance distinguishes authentication factors and original `auth_time` from token refresh, and warns that offline signature checks cannot prove revocation. The local adapter enforces those claim boundaries but still requires actual provider policy and operational validation. PyJWT 2.15.1 and its RSA dependencies are pinned with all 48 Windows runtime/development wheels in the hash lock; this is not an ARM or vulnerability-scan receipt.

## Private evidence object protocol

The raw S3 adapter follows [PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html), [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html) and [conditional write enforcement](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html). Single PUT uses SHA-256 and conditional no-overwrite, explicit SSE-KMS and expected bucket owner. Version-pinned HEAD/GET checksum retrieval needs the applicable KMS permissions; do not send PUT encryption headers on HEAD. Local SDK Stubber tests verify protocol/response handling only; they neither create nor verify a real bucket, key policy, durable object or deletion/recovery behavior.

## Multipart observation boundary

Implementation references checked October 14: [Python Multipart streaming parser API](https://multipart.fastapiexpert.com/api/) and [Starlette request files/body limits](https://starlette.dev/requests/). File limits are separate from non-file part limits; the application explicitly bounds total encoded bytes, per-image bytes, headers/part count and receive time, with authorization before consuming the stream. These references inform parsing, not hosted edge/concurrency or camera qualification.

Python Multipart 0.0.32 is pinned; its downloaded wheel matched the SHA-256 published on [PyPI](https://pypi.org/project/python-multipart/0.0.32/). The exact wheel hash is retained in the Windows lock and dependency-wheel manifest. This is package integrity evidence, not a vulnerability review or ARM compatibility proof.

## Browser capture lifecycle

The operator client uses [fresh video frame callbacks](https://developer.mozilla.org/en-US/docs/Web/API/HTMLVideoElement/requestVideoFrameCallback), [callback cancellation](https://developer.mozilla.org/en-US/docs/Web/API/HTMLVideoElement/cancelVideoFrameCallback), and [track stopping](https://developer.mozilla.org/en-US/docs/Web/API/MediaStreamTrack/stop), checked October 14. Explicit permission, context-bound geometry and conservative lease clearing are application responsibilities. The browser API cannot establish adversarial camera authenticity; canvas-stream tests are synthetic rendering/capture checks, not hardware qualification.

## Selected-asset live-version cleanup

AWS SDK request contracts checked October 14: [ListObjectVersions](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/list_object_versions.html) supplies bounded version/marker listing; [DeleteObjects](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/delete_objects.html) accepts explicit key/version pairs, expected bucket owner and per-version outcomes. ProofPack further restricts listing to its exact derived asset key, checks all returned identities and does not use unversioned deletion or governance-retention bypass. SDK protocol tests and these documents do not prove actual IAM/storage behavior, complete subject-wide erasure, backup deletion or a compliant privacy process.

## ALB target-hop and Cognito deployment alignment

Checked October18,2026: [AWS ALB forwarded headers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html) defines forwarded protocol metadata, and [CloudFormation Cognito client properties](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html) defines OAuth/client-secret configuration. Installed uvicorn/middleware/proxy_headers.py was inspected directly for CIDR peer trust/scheme handling; actual Config.load tests exercise that installed behavior. These sources inform host ingress and matching PKCE public-client wording. They do not establish real ALB/SG/certificate or Cognito/MFA acceptance, pricing, a validated CloudFormation template or permission to provision anything.

