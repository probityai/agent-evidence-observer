"""Selected SDK2.11.0 typed defaults and retry guidance frozen before execution.

Opaque node_info is retained without interpreting internal routing semantics.
MCP2.2.0 typed error serialization has no MCP transport claim.
"""

DEFAULTS = {
    "content": {"parts": None, "role": None},
    "event": {
        "actions": {
            "agent_state": None,
            "artifact_delta": {},
            "compaction": None,
            "end_of_agent": None,
            "escalate": None,
            "render_ui_widgets": None,
            "requested_auth_configs": {},
            "requested_tool_confirmations": {},
            "rewind_before_invocation_id": None,
            "route": None,
            "set_model_response": None,
            "skip_summarization": None,
            "state_delta": {},
            "transfer_reason": None,
            "transfer_to_agent": None,
        },
        "author": "",
        "avg_logprobs": None,
        "branch": None,
        "cache_metadata": None,
        "citation_metadata": None,
        "content": None,
        "custom_metadata": None,
        "environment_id": None,
        "error_code": None,
        "error_message": None,
        "finish_reason": None,
        "go_away": None,
        "grounding_metadata": None,
        "id": "e4f51cda-5c21-4ae1-821c-a2c954e49bb3",
        "input_transcription": None,
        "interaction_id": None,
        "interaction_status": None,
        "interrupted": None,
        "invocation_id": "",
        "isolation_scope": None,
        "live_session_id": None,
        "live_session_resumption_update": None,
        "logprobs_result": None,
        "long_running_tool_ids": None,
        "model_version": None,
        "node_info": {
            "message_as_output": None,
            "output_for": None,
            "path": "probity_ticket@1",
        },
        "output": None,
        "output_transcription": None,
        "partial": None,
        "timestamp": 1790970426.325763,
        "turn_complete": None,
        "turn_complete_reason": None,
        "usage_metadata": None,
        "voice_activity": None,
    },
    "function_call": {
        "args": None,
        "id": None,
        "name": None,
        "partial_args": None,
        "will_continue": None,
    },
    "function_response": {
        "id": None,
        "name": None,
        "parts": None,
        "response": None,
        "scheduling": None,
        "will_continue": None,
    },
    "part": {
        "audio_transcription": None,
        "code_execution_result": None,
        "executable_code": None,
        "file_data": None,
        "function_call": None,
        "function_response": None,
        "inline_data": None,
        "media_processing": None,
        "media_resolution": None,
        "part_metadata": None,
        "speech_metadata": None,
        "text": None,
        "thought": None,
        "thought_signature": None,
        "tool_call": None,
        "tool_response": None,
        "video_metadata": None,
    },
    "reflection_error": {
        "error_details": "selected producer failure before HTTP dispatch",
        "error_type": "RuntimeError",
        "reflection_guidance": "The call to tool `dispatch_ticket` "
        "failed.\n"
        "\n"
        "**Error Details:**\n"
        "```\n"
        "RuntimeError: selected producer "
        "failure before HTTP dispatch\n"
        "```\n"
        "\n"
        "**Tool Arguments Used:**\n"
        "```json\n"
        "{\n"
        '  "content": "DONE"\n'
        "}\n"
        "```\n"
        "\n"
        "**Reflection Guidance:**\n"
        "This is retry attempt **1 of 1**. "
        "Analyze the error and the arguments "
        "you provided. Do not repeat the exact "
        "same call. Consider the following "
        "before your next attempt:\n"
        "\n"
        "1.  **Invalid Parameters**: Does the "
        "error suggest that one or more "
        "arguments are incorrect, badly "
        "formatted, or missing? Review the "
        "tool's schema and your arguments.\n"
        "2.  **State or Preconditions**: Did a "
        "previous step fail or not produce the "
        "necessary state/resource for this "
        "tool to succeed?\n"
        "3.  **Alternative Approach**: Is this "
        "the right tool for the job? Could "
        "another tool or a different sequence "
        "of steps achieve the goal?\n"
        "4.  **Simplify the Task**: Can you "
        "break the problem down into smaller, "
        "simpler steps?\n"
        "5.  **Wrong Function Name**: Does the "
        "error indicates the tool is not "
        "found? Please check again and only "
        "use available tools.\n"
        "\n"
        "Formulate a new plan based on your "
        "analysis and try a corrected or "
        "different approach.",
        "response_type": "ERROR_HANDLED_BY_REFLECT_AND_RETRY_PLUGIN",
        "retry_count": 1,
    },
    "reflection_result": {
        "error_details": "{'_meta': None, 'content': [{'type': "
        "'text', 'text': 'selected producer failure "
        "before HTTP dispatch', 'annotations': "
        "None, '_meta': None}], "
        "'structuredContent': None, 'isError': "
        "True, 'resultType': 'complete'}",
        "error_type": "ToolError",
        "reflection_guidance": "The call to tool `dispatch_ticket` "
        "failed.\n"
        "\n"
        "**Error Details:**\n"
        "```\n"
        "{'_meta': None, 'content': [{'type': "
        "'text', 'text': 'selected producer "
        "failure before HTTP dispatch', "
        "'annotations': None, '_meta': "
        "None}], 'structuredContent': None, "
        "'isError': True, 'resultType': "
        "'complete'}\n"
        "```\n"
        "\n"
        "**Tool Arguments Used:**\n"
        "```json\n"
        "{\n"
        '  "content": "DONE"\n'
        "}\n"
        "```\n"
        "\n"
        "**Reflection Guidance:**\n"
        "This is retry attempt **1 of 1**. "
        "Analyze the error and the arguments "
        "you provided. Do not repeat the "
        "exact same call. Consider the "
        "following before your next attempt:\n"
        "\n"
        "1.  **Invalid Parameters**: Does the "
        "error suggest that one or more "
        "arguments are incorrect, badly "
        "formatted, or missing? Review the "
        "tool's schema and your arguments.\n"
        "2.  **State or Preconditions**: Did "
        "a previous step fail or not produce "
        "the necessary state/resource for "
        "this tool to succeed?\n"
        "3.  **Alternative Approach**: Is "
        "this the right tool for the job? "
        "Could another tool or a different "
        "sequence of steps achieve the goal?\n"
        "4.  **Simplify the Task**: Can you "
        "break the problem down into smaller, "
        "simpler steps?\n"
        "5.  **Wrong Function Name**: Does "
        "the error indicates the tool is not "
        "found? Please check again and only "
        "use available tools.\n"
        "\n"
        "Formulate a new plan based on your "
        "analysis and try a corrected or "
        "different approach.",
        "response_type": "ERROR_HANDLED_BY_REFLECT_AND_RETRY_PLUGIN",
        "retry_count": 1,
    },
    "request_before": {
        "cache_config": None,
        "cache_metadata": None,
        "cacheable_contents_token_count": None,
        "config": {
            "audio_timestamp": None,
            "audio_transcription_config": None,
            "automatic_function_calling": None,
            "cached_content": None,
            "candidate_count": None,
            "continuation_token": None,
            "enable_enhanced_civic_answers": None,
            "frequency_penalty": None,
            "http_options": None,
            "image_config": None,
            "labels": None,
            "logprobs": None,
            "max_output_tokens": None,
            "media_resolution": None,
            "model_armor_config": None,
            "model_selection_config": None,
            "presence_penalty": None,
            "response_json_schema": None,
            "response_logprobs": None,
            "response_mime_type": None,
            "response_modalities": None,
            "response_schema": None,
            "routing_config": None,
            "safety_settings": None,
            "seed": None,
            "service_tier": None,
            "should_return_http_response": None,
            "speech_config": None,
            "stop_sequences": None,
            "system_instruction": "You are an agent. Your "
            "internal name is "
            '"probity_ticket".',
            "temperature": None,
            "thinking_config": None,
            "tool_config": None,
            "tools": [
                {
                    "code_execution": None,
                    "computer_use": None,
                    "enterprise_web_search": None,
                    "exa_ai_search": None,
                    "file_search": None,
                    "function_declarations": [
                        {
                            "behavior": None,
                            "description": "Update "
                            "the "
                            "selected "
                            "synthetic "
                            "protected "
                            "ticket "
                            "using "
                            "literal "
                            "content.",
                            "name": "dispatch_ticket",
                            "parameters": None,
                            "parameters_json_schema": {
                                "properties": {
                                    "content": {"title": "Content", "type": "string"}
                                },
                                "required": ["content"],
                                "title": "dispatch_ticketParams",
                                "type": "object",
                            },
                            "response": None,
                            "response_json_schema": None,
                        }
                    ],
                    "google_maps": None,
                    "google_search": None,
                    "google_search_retrieval": None,
                    "mcp_servers": None,
                    "parallel_ai_search": None,
                    "retrieval": None,
                    "url_context": None,
                }
            ],
            "top_k": None,
            "top_p": None,
        },
        "contents": [],
        "live_connect_config": {
            "avatar_config": None,
            "context_window_compression": None,
            "enable_affective_dialog": None,
            "explicit_vad_signal": None,
            "generation_config": None,
            "history_config": None,
            "http_options": None,
            "input_audio_transcription": {
                "adaptation_phrases": None,
                "custom_vocabulary": None,
                "diarization": None,
                "language_auto": None,
                "language_codes": None,
                "language_hints": None,
                "mode": None,
                "word_timestamp": None,
            },
            "max_output_tokens": None,
            "media_resolution": None,
            "output_audio_transcription": {
                "adaptation_phrases": None,
                "custom_vocabulary": None,
                "diarization": None,
                "language_auto": None,
                "language_codes": None,
                "language_hints": None,
                "mode": None,
                "word_timestamp": None,
            },
            "proactivity": None,
            "realtime_input_config": None,
            "response_modalities": None,
            "safety_settings": None,
            "seed": None,
            "session_resumption": None,
            "speech_config": None,
            "system_instruction": None,
            "temperature": None,
            "thinking_config": None,
            "tools": None,
            "top_k": None,
            "top_p": None,
            "translation_config": None,
        },
        "model": "probity-scripted-no-inference",
        "previous_interaction_id": None,
        "service_tier": None,
    },
    "request_model": {
        "cache_config": None,
        "cache_metadata": None,
        "cacheable_contents_token_count": None,
        "config": {
            "audio_timestamp": None,
            "audio_transcription_config": None,
            "automatic_function_calling": None,
            "cached_content": None,
            "candidate_count": None,
            "continuation_token": None,
            "enable_enhanced_civic_answers": None,
            "frequency_penalty": None,
            "http_options": None,
            "image_config": None,
            "labels": {"adk_agent_name": "probity_ticket"},
            "logprobs": None,
            "max_output_tokens": None,
            "media_resolution": None,
            "model_armor_config": None,
            "model_selection_config": None,
            "presence_penalty": None,
            "response_json_schema": None,
            "response_logprobs": None,
            "response_mime_type": None,
            "response_modalities": None,
            "response_schema": None,
            "routing_config": None,
            "safety_settings": None,
            "seed": None,
            "service_tier": None,
            "should_return_http_response": None,
            "speech_config": None,
            "stop_sequences": None,
            "system_instruction": "You are an agent. Your "
            "internal name is "
            '"probity_ticket".',
            "temperature": None,
            "thinking_config": None,
            "tool_config": None,
            "tools": [
                {
                    "code_execution": None,
                    "computer_use": None,
                    "enterprise_web_search": None,
                    "exa_ai_search": None,
                    "file_search": None,
                    "function_declarations": [
                        {
                            "behavior": None,
                            "description": "Update "
                            "the "
                            "selected "
                            "synthetic "
                            "protected "
                            "ticket "
                            "using "
                            "literal "
                            "content.",
                            "name": "dispatch_ticket",
                            "parameters": None,
                            "parameters_json_schema": {
                                "properties": {
                                    "content": {"title": "Content", "type": "string"}
                                },
                                "required": ["content"],
                                "title": "dispatch_ticketParams",
                                "type": "object",
                            },
                            "response": None,
                            "response_json_schema": None,
                        }
                    ],
                    "google_maps": None,
                    "google_search": None,
                    "google_search_retrieval": None,
                    "mcp_servers": None,
                    "parallel_ai_search": None,
                    "retrieval": None,
                    "url_context": None,
                }
            ],
            "top_k": None,
            "top_p": None,
        },
        "contents": [],
        "live_connect_config": {
            "avatar_config": None,
            "context_window_compression": None,
            "enable_affective_dialog": None,
            "explicit_vad_signal": None,
            "generation_config": None,
            "history_config": None,
            "http_options": None,
            "input_audio_transcription": {
                "adaptation_phrases": None,
                "custom_vocabulary": None,
                "diarization": None,
                "language_auto": None,
                "language_codes": None,
                "language_hints": None,
                "mode": None,
                "word_timestamp": None,
            },
            "max_output_tokens": None,
            "media_resolution": None,
            "output_audio_transcription": {
                "adaptation_phrases": None,
                "custom_vocabulary": None,
                "diarization": None,
                "language_auto": None,
                "language_codes": None,
                "language_hints": None,
                "mode": None,
                "word_timestamp": None,
            },
            "proactivity": None,
            "realtime_input_config": None,
            "response_modalities": None,
            "safety_settings": None,
            "seed": None,
            "session_resumption": None,
            "speech_config": None,
            "system_instruction": None,
            "temperature": None,
            "thinking_config": None,
            "tools": None,
            "top_k": None,
            "top_p": None,
            "translation_config": None,
        },
        "model": "probity-scripted-no-inference",
        "previous_interaction_id": None,
        "service_tier": None,
    },
    "response": {
        "avg_logprobs": None,
        "cache_metadata": None,
        "citation_metadata": None,
        "content": None,
        "custom_metadata": None,
        "environment_id": None,
        "error_code": None,
        "error_message": None,
        "finish_reason": None,
        "go_away": None,
        "grounding_metadata": None,
        "input_transcription": None,
        "interaction_id": None,
        "interaction_status": None,
        "interrupted": None,
        "live_session_id": None,
        "live_session_resumption_update": None,
        "logprobs_result": None,
        "model_version": None,
        "output_transcription": None,
        "partial": None,
        "turn_complete": None,
        "turn_complete_reason": None,
        "usage_metadata": None,
        "voice_activity": None,
    },
    "returned_error": {
        "_meta": None,
        "content": [
            {
                "_meta": None,
                "annotations": None,
                "text": "selected producer failure before HTTP dispatch",
                "type": "text",
            }
        ],
        "isError": True,
        "resultType": "complete",
        "structuredContent": None,
    },
}
