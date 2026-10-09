# Check a tool definition against its signed grade

A server can change a tool after someone grades it. Your consumer needs to check
the definition it holds, the named tool and the grade's expiry before it relies
on that grade.

[Kenneives supplied this AgentAvow case](https://github.com/probityai/agent-evidence-atlas/issues/49#issuecomment-6071630803)
for `ask_wiki_question`. The offline reader checks the original signed grade
and all three saved tool definitions. It preserves the contributor's six cases
and thirteen tool-name cases.

## What happens

The original matching case passes at its historical evaluation time. Observer
then writes a file with that checked binding through its protected dispatcher.
The local grant names those exact file bytes. Changes to the graded definition,
an unknown tool, a different server, an expired grade and a changed signed payload refuse
before a file effect.

The initial run also checks the grade at that run's time. The saved grade expired
on October 2, 2026, so that assessment refuses. The historical replay does not
make the grade current.

A later reader recomputes the binding and checks the retained local file,
selected request and signed effect record. It rechecks the assessment at the
original run time; it does not make a fresh admission decision. Changed file
bytes or a substituted request refuse.

## Use the check

The [technical reference](reference/TOOL-MANIFEST-EFFECT.md) gives the commands,
unchanged source pins, fields and trust inputs.

The file effect records this comparison. It does not invoke DeepWiki. A matching
digest binds the claimed definition to the signed static grade. An actual remote
effect also needs runtime records that bind that invocation and result. The
fixture supplies neither those records nor a claim that an action was safe.
