# Check whether a rejected job already changed a file

A job can lose permission to commit its result after its work has begun. If the
job already wrote a file, rejecting its final output does not undo that write.
This example checks the job decision and the file effect separately.

## What the example does

Three CrewAI runs show the difference: a valid job writes a file; a stale job is
refused before its body runs; and another stale job writes a file before its
output is refused. The recorded result keeps the refusal and the earlier effect.
It also keeps the job's stored output separate from the message later shown to
the user.

Observer records the file writes. A separately installed reader checks the job
records, callback order, signed history, and final files. Verify then checks
whether a body effect was absent during each recorded interval. If that interval
was not covered, absence remains unknown.

## Run and inspect it

The [technical reference](reference/CREWAI-JOB-FENCES.md) links the exact CrewAI
source, installation workflow, retained files, reader checks, and refusal controls.
Use it to reproduce the recorded cases or build a consumer check against them.

## What the result establishes

These runs use fixed inputs without model or provider calls. One author operates
the producers, reader, keys, and storage. The result concerns the selected job
paths and local files; it does not establish an independent witness or the quality
of an agent's answer.
