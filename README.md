# Privaclave NLP Service

## Project Overview

`Privaclave NLP Service` is a Python FastAPI service that performs privacy classification and entity detection. It scans text for sensitive information and returns structured metadata to downstream services such as the orchestrator.

## Purpose

- Detect sensitive data and named entities in text.
- Provide a raw scan API for direct classification requests.
- Offer an OpenAI-compatible chat endpoint for compatibility with orchestration layers.
- Load scanning plugins at startup from configuration.

## Configuration and Plugin Loading

The service loads `config.json` at startup. The config defines which plugins are enabled and their loader settings.

Built-in plugin loaders:

- `spacy`
- `gliner`

Each plugin is loaded during startup and added to the runtime `PLUGIN_REGISTRY`.

To change plugin behavior, update `config.json` and restart the service.

### Example plugin config entry

```json
{
  "name": "gliner",
  "enabled": true,
  "model": "urchade/gliner_multi_pii-v1",
  "labels": ["email", "phone_number", "ssn"]
}
```

## Built-in Plugins

### spaCy

- Loaded from `spacy.load("en_core_web_sm")` by default.
- Performs general named entity recognition (NER).
- Returns entities with:
  - `text`
  - `type`
  - `source`
  - `start`
  - `end`
  - `score`

### GLiNER

- Loaded from `GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")` by default.
- Detects sensitive Personally Identifiable Information (PII).
- Maps raw GLiNER labels to normalized fields and policy labels.
- Returns entities with:
  - `text`
  - `type`
  - `fieldName`
  - `policyLabel`
  - `source`
  - `start`
  - `end`
  - `score`

## Setup Instructions

1. Create and activate a Python virtual environment:

```powershell
cd privaclave-nlp-service
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
python -m pip install fastapi uvicorn pydantic spacy gliner
python -m spacy download en_core_web_sm
```

3. Start the service:

```powershell
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoint Documentation

### POST /v1/scan

Scans text and returns raw NLP detection results.

#### Request example

```json
{
  "text": "Alice lives in Seattle and her email is alice@example.com."
}
```

#### Response example

```json
{
  "nlp_scan": {
    "libraries_used": ["spacy", "gliner"],
    "entities": [
      {
        "text": "Alice",
        "type": "PERSON",
        "source": "spacy",
        "start": 0,
        "end": 5,
        "score": 1.0
      },
      {
        "text": "alice@example.com",
        "type": "email",
        "fieldName": "EMAIL_ADDRESS",
        "policyLabel": "email_id",
        "source": "gliner",
        "start": 33,
        "end": 51,
        "score": 0.987654321
      }
    ],
    "entity_count": 2
  }
}
```

### POST /v1/chat/completions

Accepts OpenAI-style chat payloads, concatenates all message text, and scans it with active plugins.

#### Request example

```json
{
  "messages": [
    {"role": "user", "content": "Check this text for sensitive information."}
  ]
}
```

#### Response example

```json
{
  "id": "nlp-scan",
  "object": "chat.completion",
  "model": "nlp",
  "choices": [],
  "nlp_scan": {
    "libraries_used": ["spacy", "gliner"],
    "entities": [],
    "entity_count": 0
  }
}
```

### GET /v1/models

Returns a static model listing for compatibility.

#### Response example

```json
{
  "object": "list",
  "data": [
    {"id": "nlp", "object": "model", "owned_by": "privaclave"}
  ]
}
```

### GET /health

Returns service health.

#### Response example

```json
{
  "status": "ok",
  "service": "privaclave-nlp-service"
}
```

## Entity Mapping Structure

The service uses `ENTITY_MAPPING` to normalize GLiNER output into consistent field names and policy labels.

Each entity record may contain:

- `fieldName`: the standardized data field name used in outputs.
- `policyLabel`: the normalized privacy classification label.

Example mappings:

- `person` → `fieldName: FULL_NAME`, `policyLabel: name`
- `email` → `fieldName: EMAIL_ADDRESS`, `policyLabel: email_id`
- `ssn` → `fieldName: SOCIAL_SECURITY_NUMBER`, `policyLabel: ssn_no`

This mapping ensures results are consistent and easier to consume.

## Plugin Extension

Custom plugins are loaded from `config.json` at startup. To add or change a plugin, update `config.json` and restart the service.

The current implementation does not expose a runtime `POST /v1/plugins/register` endpoint.

## Dependencies

- `fastapi`
- `uvicorn`
- `pydantic`
- `spacy`
- `gliner`

## Notes

- The service does not call LLMs directly; it performs NLP scanning only.
- If a built-in plugin fails to load, the service continues running with any available plugins.
- The `chat.completions` endpoint is meant for compatibility and returns scan metadata rather than generated text.
