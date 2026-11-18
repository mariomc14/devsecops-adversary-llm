# Experimental configuration

## AWS Bedrock invocation

The final automation preserved in `automation/sce_automation_api.py` invokes Amazon Bedrock through the Converse API. The final common inference configuration is:

```python
inferenceConfig={
    "maxTokens": 8192,
    "temperature": 1,
}
```

No explicit `topP` or `topK` override is supplied by the preserved final automation. The Bedrock client is configured with `read_timeout=3600`, `connect_timeout=30`, and standard retries with `max_attempts=3`.

The source also contains a separate Amazon Titan invocation with `maxTokenCount=50` and `temperature=0.1` inside an AWS connectivity-test helper. That call is only a diagnostic access test and is not part of the Claude experiment-generation workflow described above.

## Chaos Toolkit runtime strategy

Candidates admitted to runtime execution are invoked with the non-default hypothesis strategy:

```bash
chaos run <experiment>.json --hypothesis-strategy=after-method-only
```

The same strategy is present in both `automation/run.sh` and the subprocess invocation inside `automation/sce_automation_api.py`. It causes the steady-state hypothesis to be evaluated after the actions declared in the experiment `method` array.

## Dependencies

The exact pinned Python dependencies available with the experimental automation are provided in `automation/requirements.txt`.
