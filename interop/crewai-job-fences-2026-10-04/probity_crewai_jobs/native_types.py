"""Publisher-native record, conversational flow and threaded worker types."""

from typing import ClassVar
from pydantic import Field, PrivateAttr
from crewai.flow import ConversationState, Flow, listen, start
from crewai.experimental.flow_jobs import JobRecord, JobState, JobWorkFlow, JobWorkState


class Record(JobRecord):
    output_fields: ClassVar[frozenset[str]] = frozenset({"notes", "answer"})
    question: str
    stage: str = "collect"
    notes: list[str] = Field(default_factory=list)
    answer: str = ""


class State(ConversationState, JobState[Record]):
    pass


class WorkState(JobWorkState[Record]):
    pass


class Work(JobWorkFlow[WorkState]):
    _body = PrivateAttr()

    def __init__(self, job, publish, body):
        super().__init__(publish=publish, initial_state=WorkState(job=job),
                         suppress_flow_events=True, tracing=False)
        self._body = body

    @start()
    def collect(self):
        self.check_open()
        self.publish_update("started")
        self.publish_update("stage_completed", stage="collect", outputs={"notes": ["Public fact"]})

    @listen(collect)
    def write(self):
        self.check_open()
        self.publish_update("stage_started", stage="write")
        answer = self._body(self.state.job, self.state.seq)
        self.publish_update("stage_completed", stage="write", outputs={"answer": answer})
        self.publish_update("completed")


class StatusFlow(Flow[State]):
    conversational = True

    def route_turn(self, context):
        return "converse"

    @listen("converse")
    def converse_turn(self):
        job = next(iter(self.state.jobs.values()))
        reply = job.status + ": " + ", ".join(job.notes) + ("; " + job.answer if job.answer else "")
        self.append_assistant_message(reply)
        return reply
