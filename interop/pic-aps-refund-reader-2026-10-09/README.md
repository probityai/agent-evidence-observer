# Read the PIC approval and the APS refund record

Do these two records approve the same refund? This reader checks the original
PIC signature and three retained APS cases. It then shows which links exist.

The refund fields match. The approval references do not. The public inputs do
not establish the merchant-decision mapping or an authenticated Conduit handoff.
The reader reports that gap with exit 3. Invalid evidence exits 2.

The PIC key is a public test key. APS verification replays the recorded fixture
clock. The effect evidence concerns a local SQLite row. This reader creates no
approval, operation, payment or provider call.

See the [worked example](../../docs/PIC-APS-REFUND-EVIDENCE.md) and its
[technical reference](../../docs/reference/PIC-APS-REFUND-EVIDENCE.md) for the
run recipe, exact source selection and missing inputs.
