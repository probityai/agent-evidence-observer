# Eight-component host contract

## Exact scope and source selection

The original `SOURCE-SELECTION.json` remains byte-identical to partial feature
`c104d8b7db835f1ed3f88a9ab927067136481079`, SHA-256
`1107cb0621b8b9227d5e7e8615c24bd1a2cee0ecb4cb1e7a15a1e3dd839540d6`.
Current moving main is never silently substituted for a selected component.

| Component | Frozen source | Executed consumption |
| --- | --- | --- |
| Vocabulary | `8c80579ae613d7ae07982321e13a6091c402b2a8` | Actual closed basis/method/result and PEER terms |
| Vectors | `bbdef583c9241138e5c2b5d872bc77f7f539e9ac` | Installed `ReferenceVerifier(pinned_pubs).verify(stmt, raw)` |
| JCS | `40ce923843167629f0ed044590d1319e6a711015` | Real registry `jcs-admit=0.1.1` byte admission |
| DSSE | `f6f6df4bef5544af76dc3f5b05909a2f24a8e51f` | Real registry `dsse=0.1.1` sign and returned verified payload |
| Verify | `e835ce2bd6a960e7a1cc2fa6522f16d55dce728a` | Installed `source_text_coverage/v1`, selected `text_utf8/v1` witness |
| Admission | `20d8924d904a2597276209529ab8f60ceb1aaba9` | Actual pinned `data.sigstore.isCompliant` with external anchors |
| Observer | `c774e0711e4a30c31cdfb184c1e4495a249fbdd0` | Installed native grant, HTTP target, readback and SQLite recovery |
| Atlas | `58c89e18033a3c5fdd10d1a9b65497e25093dcc8` | Actual full register validator and stable original authority record |

Rust release source and selected current source remain separate facts. DSSE's
registry release matches its selected source. JCS's released VCS source is
`33603fc8caf6f8469ea790f41ab74ae64d4f1658`; it differs from selected current
`40ce923...`. The unchanged lock records registry checksums. The chain uses the
released crate APIs, without asserting that the release came from current main.

OPA 1.18.0's official Linux/amd64 static asset is selected by SHA-256
`65d700b14b99b354982b61031b40bdc8e316ea93dadd61818f066d1d9a69dcce`.
Its actual version reports build commit
`cc2c5c60a4c486f15a5e8de457e96ed0fefaf5fe-dirty`. This is an exact binary
selection, not a pristine source-build claim.

The ordinary Python source-wheel versions remain Observer 0.0.1, Vectors 0.15.0
and Verify 0.1.0. Source installation does not publish any version or take the
existing release owner's gate. Python 3.13 is required by selected Vectors.

## External host trust boundary

Trusted setup materializes and checks all original source files, builds wheels
normally and installs them normally. It copies only authenticated original
tracked bytes into a new exclusive runtime source snapshot. Builder outputs and
caches stay outside runtime selection; no build-directory deletion or ignored
executable extras are relied upon. Every source hash and declared head remains
unchanged. Setup requires installed component Python file names and bytes to
match the original wheel source mapping, including Vectors' explicit rail mapping.

`prepare_host.py` creates new random disposable envelope, issuer and target-service
seeds in a separate host-only directory. It records separate public keys and
installs an external policy. These roles are distinct cryptographic keys held by
the same operator; this is neither identity proof nor independent custody.

The operator chooses the complete installation manifest SHA-256 in its protected
job before candidate execution. The candidate cannot choose that hash, manifest,
policy, key, source revision, binary, installed reader or authority identity.
`run_host.py` uses only stdlib imports and is invoked with `-S -B`, so candidate
startup hooks are not loaded by the bootstrap. Before the first child it checks:

1. Original source-selection digest, all eight declared heads, exact source-file
   closure outside inert Git metadata, every selected source byte and path.
2. Complete installed site-packages file-name closure and SHA-256 bindings,
   including dependencies, startup hooks, metadata and existing bytecode.
3. Selected interpreter binary and invocation mapping, `pyvenv.cfg` when a venv
   is used, kit reader/target/launcher code, every wheel, Rust binary and OPA.
4. External policy, private seed file bytes, public-key files and distinct roles.

All component children use `-I -B`; they receive a finite environment allowlist,
without candidate `PYTHONPATH`, loader hooks or provider credentials. Bytecode
writes are suppressed in the complete workflow to preserve installed closure.
Extra harmless `.pth`, `sitecustomize.py`, dependency code and Atlas source code
are explicit no-child refusal controls, not ignored files.

Source and installed closures use explicit error-reporting enumeration. Missing
or unreadable roots/descendants, directory iteration/stat errors, symlinks and
special files refuse before any child. Only a real root-level source `.git`
directory is ignored as metadata; nested `.git` directories remain in the
authenticated closure. Empty directories count against the maximum 100,000
entries and 64 levels. A closure permits at most 1 GiB of regular-file bytes,
with at most 256 MiB per file. These limits cover the selected native binaries
and source artifacts; exceeding them requires a separately reviewed kit change.

Selected content is opened without following final links, with nonblocking
descriptor selection and a regular-file stat check before a bounded read. A
FIFO, socket, device, directory, oversized file or failed read refuses rather
than blocking or disappearing. JSON selections additionally permit at most
16 MiB. The intentional interpreter invocation link is checked separately
against its selected real binary; it creates no source/package link exemption.

The host launcher, interpreter standard library, operating system, protected
filesystem, native clock and SQLite durability remain trusted infrastructure.
Hash checking is not process isolation. The candidate must lack write authority
over those selections throughout execution. Concurrent adversarial changes on
the trusted filesystem, host power loss and independently held authority are
outside this local kit's claim. The kit does not authenticate its own bootstrap
from candidate bytes or establish a general sandbox.

## Executed gates and their separate meanings

Raw candidate AEE is retained unchanged. The installed Rust CLI first admits it
with JCS, signs the admitted canonical bytes, and retains raw/canonical/envelope
links. DSSE verifies using the externally selected host public key, returns its
verified payload, checks the selected payload type and canonical form, and creates
the returned-payload output exclusively. Later readers receive only those exact
returned bytes. Duplicate raw members are refused before lossy Python parsing.

Installed Vectors receives the separately selected published test public key
`496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62`.
Structural validity and crypto tiers are both checked. Every covering row must
be `attested`; valid-but-unattested evidence stops the chain. This key comes from
the published test-key recipe, never from the candidate's record `keyid`.
The healthy candidate is the unchanged signed fixture
`vectors/statements/vcc938c6038536dcb.json`. It is an exposed deterministic
conformance fixture, not a newly observed production execution or blind test.

OPA receives the pinned Rego source and separately selected corpus, substrate,
catch-policy, network posture, demanded `XA` scope and pass-only threshold. The
corpus anchor is `cc1bdef2...`, substrate `018bbaf3...`; full values are retained
in the external policy. Rego's structural signature presence does not replace
Vectors' prior crypto check. OPA's admitted boolean must be present and true with
an empty errors set. Wrong-context, missing-demand and invalid-threshold controls
stop before grant issuance.

The vocabulary checks actual selected closed terms without changing their
proposed/canonical lifecycle. Atlas's original `tools/check_lab.py`
`validate_register` authenticates its full selected register's artifact and
measured-field bindings. The selected `authority-recovery-2026-10-02` record's
provenance authenticates its entire original 110-member archive, unique exact
member closure, every member byte length/digest, and exact original report member.
The old author-operated measurement is reference input; it does not become a new
outside operation or new Atlas acceptance because this host reads it.

Installed Verify selects literal nonclaims in that pinned Atlas provenance under
`source_text_coverage/v1` and `text_utf8/v1`. Source witness, time window, required
spans, record identity and digest are selected externally. The time window is an
author selection attached to already pinned bytes; no independent capture-clock
claim is made. Supported, contradicted, not established and malformed outcomes
remain different native results. Only supported admits. A self-hashed candidate
record or substituted source cannot replace the separately selected witness/pin.

After those gates pass, installed Observer separately creates `ActionRequest`,
`GrantPolicy` and `issue_grant`. The action's content digest is the accepted
returned payload's SHA-256; its tenant, principal, tool, target and invocation
identity are host policy. Evidence signatures do not issue effect authority.

## Native HTTP and recovery controls

Actual separately launched target processes serve the installed native
`TicketStore` over HTTP. An exact POST commits a native intent and then one ticket
revision. A fresh process reopens the same SQLite file using a retained signed
prior head, performs native recovery, and supplies a separate GET readback.
Installed `verify_ticket_result` compares the receipt and retrieved native bytes,
keys, exact request, grant validity, current revocation, native revision and PEER
scope. Fresh POST retries are checked against current authority even after a
commit; they preserve revision 1 rather than producing another revision.

The finite host-only matrix includes successful completion, hard exit after
intent, hard exit inside the effect transaction, hard exit after the effect,
revocation after commit, expiration after commit, valid-window clock rollback
after commit, and native store rollback behind a retained signed head. Hard exits
use actual `os._exit(73)`, not a simulated in-memory exception. Pending work
recovers as incomplete; rolled-back in-transaction effects remain absent. Prior
committed revision 1 survives revocation/expiry/clock refusal. A substituted older
database cannot start under a retained newer signed head. These observations do
not establish host power-loss recovery or distributed exactly-once semantics.

The deterministic grant clock begins at `2026-10-02T12:00:00Z`, expires after
60 seconds and performs the first effect at the separately selected +10-second
offset. The rollback control uses +9 seconds, still inside the grant window, so
clock-predates-effect refusal is distinguishable from grant expiry. Readiness and
child/process/HTTP waits remain finite. Complete failed, timed-out and partial
stdout/stderr streams are retained rather than inferred from exit status alone.

## Retention, review and adoption route

Each run retains original raw evidence, Rust-returned payload/envelope, all child
streams/process receipts, OPA/native gate outputs, public host policy, selected
reference vocabulary/Rego/Atlas register/provenance/original ZIP/report, exact
source selection, HTTP request/response bytes, target startup/exit/recovery
records, native SQLite state and signed heads. Native original and selection
hashes remain distinct from later source/result/archival commits. The workflow
retains ordinary wheels and complete public raw/test artifacts for 90 days.

Private authority seed bytes remain in the external host directory and are
explicitly omitted from public retention. Public key pins, grants and signed
records are retained. The absence of independently held keys/store/clock/retention
is a custody limit, not an artifact retention success. Expiring provider artifacts
require the root program's durable original archive before closeout.

The owned host workflow is an executable adoption route for another relying
party: its maintained job must select the reviewed kit revision, all component
and artifact pins, authority roles and consumer thresholds outside candidate
bytes, then operate the same bounded native chain under its own acceptance and
custody. No external recurring gate is established by author CI alone. Existing
SDK/Inspect/framework publication-gate owners and the recorded distribution
inventory remain the outreach/placement route; this change sends no outreach,
duplicates no existing offer, and takes over no existing component/release owner.

Same-team substantive peer review is separate from independent custody. Normal
protected landing and exact-main/source/original-artifact verification must be
recorded by the owning program; pending readiness is not described as merged.
