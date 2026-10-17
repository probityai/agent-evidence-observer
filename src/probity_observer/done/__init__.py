"""``probity done``: seal a definition of done, run an agent, and check its claim from outside.

The package writes the five record formats ``probity-verify`` reads (``docs/done-receipt.md``
there): the done contract, the tree, the observation, the acceptance grade and the tool claims.
It combines the three checks into one done verdict and emits a done receipt. Requires the
``done`` extra (``probityai`` for RFC 8785 and DSSE, ``probity-verify`` for the checks).
"""
