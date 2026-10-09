# Do these records describe the same approved refund?

The refund fields match, but the two approval references do not. This reader
checks the signed PIC example and three saved APS refund records. It shows the
missing links instead of treating two valid records as one completed workflow.

The APS records cover a restart, interruption before the local effect, and a
reissued approval. The interruption stays unconfirmed. Reissue cannot replace
the original evidence of completion.

Fabio Salvadori supplied the PIC refund example. The APS project supplied the
native approval format and refund scenario. Observer supplies the reader and
its retained local records. All contributor fixture bytes stay unchanged.

The PIC signer is a public test key, and the APS checks use their recorded
historical clock. The saved effect is a local database row. These records do not
establish merchant authority, a current approval, or a remote refund.

The [technical reference](reference/PIC-APS-REFUND-EVIDENCE.md) gives the commands,
source pins, refusal controls and the inputs needed for the proposed combined case.
