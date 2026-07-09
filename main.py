from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import importlib
import json
import os

app = FastAPI(title="Privaclave NLP Service")

# ─── Plugin Registry ──────────────────────────────────────────────────────────
PLUGIN_REGISTRY: Dict[str, Any] = {}

def register_plugin(name: str, scanner):
    PLUGIN_REGISTRY[name] = {"scanner": scanner}
    print(f"[Plugin Registry] Registered plugin: {name}")

# ─── Load config ──────────────────────────────────────────────────────────────

def load_config() -> dict:
    config_path = os.getenv("CONFIG_PATH", "config.json")
    with open(config_path, "r") as f:
        return json.load(f)

# ─── Plugin loaders ───────────────────────────────────────────────────────────

def load_spacy(plugin_config: dict):
    try:
        import spacy
        model_name = plugin_config.get("model", "en_core_web_sm")
        nlp = spacy.load(model_name)

        def spacy_scan(text: str) -> list:
            doc = nlp(text)
            return [
                {
                    "text":   ent.text,
                    "type":   ent.label_,
                    "source": "spacy",
                    "start":  ent.start_char,
                    "end":    ent.end_char,
                    "score":  1.0
                }
                for ent in doc.ents
            ]

        register_plugin("spacy", spacy_scan)
        print(f"[Startup] Spacy loaded — model: {model_name}")
    except Exception as e:
        print(f"[Startup] Spacy failed to load: {e}")

def load_gliner(plugin_config: dict):
    try:
        from gliner import GLiNER
        model_name = plugin_config.get("model", "urchade/gliner_multi_pii-v1")
        labels     = plugin_config.get("labels", [])

        gliner_model = GLiNER.from_pretrained(model_name)

        def gliner_scan(text: str) -> list:
            entities = gliner_model.predict_entities(text, labels)
            return [
                {
                    "text":        ent["text"],
                    "type":        ent["label"],
                    "fieldName":   ENTITY_MAPPING.get(ent["label"], {}).get("fieldName",   ent["label"].upper()),
                    "policyLabel": ENTITY_MAPPING.get(ent["label"], {}).get("policyLabel", ent["label"].lower()),
                    "source":      "gliner",
                    "start":       ent.get("start", None),
                    "end":         ent.get("end",   None),
                    "score":       round(ent["score"], 11)
                }
                for ent in entities
            ]

        register_plugin("gliner", gliner_scan)
        print(f"[Startup] GLiNER loaded — model: {model_name}")
    except Exception as e:
        print(f"[Startup] GLiNER failed to load: {e}")

# ─── Plugin dispatcher ────────────────────────────────────────────────────────

PLUGIN_LOADERS = {
    "spacy":  load_spacy,
    "gliner": load_gliner,
}

# ─── Entity Mapping ───────────────────────────────────────────────────────────

ENTITY_MAPPING = {
    "person":                  {"fieldName": "FULL_NAME",              "policyLabel": "name"},
    "name":                    {"fieldName": "FULL_NAME",              "policyLabel": "name"},
    "first_name":              {"fieldName": "FULL_NAME",              "policyLabel": "name"},
    "last_name":               {"fieldName": "FULL_NAME",              "policyLabel": "name"},
    "geo_location":            {"fieldName": "GEOLOCATION",            "policyLabel": "geo_location"},
    "geolocation_information": {"fieldName": "GEOLOCATION",            "policyLabel": "geo_location"},
    "longitude":               {"fieldName": "GEOLOCATION",            "policyLabel": "geo_location"},
    "latitude":                {"fieldName": "GEOLOCATION",            "policyLabel": "geo_location"},
    "bank_account":            {"fieldName": "BAN",                    "policyLabel": "ban_no"},
    "bank_account_number":     {"fieldName": "BAN",                    "policyLabel": "ban_no"},
    "account_no":              {"fieldName": "BAN",                    "policyLabel": "ban_no"},
    "payment_card":            {"fieldName": "PAN",                    "policyLabel": "pan_no"},
    "credit_card_number":      {"fieldName": "PAN",                    "policyLabel": "pan_no"},
    "card_number":             {"fieldName": "PAN",                    "policyLabel": "pan_no"},
    "birth_date":              {"fieldName": "DOB",                    "policyLabel": "dob"},
    "DOB":                     {"fieldName": "DOB",                    "policyLabel": "dob"},
    "dob":                     {"fieldName": "DOB",                    "policyLabel": "dob"},
    "date of birth":           {"fieldName": "DOB",                    "policyLabel": "dob"},
    "address":                 {"fieldName": "ADDRESS",                "policyLabel": "address"},
    "street":                  {"fieldName": "ADDRESS",                "policyLabel": "address"},
    "city":                    {"fieldName": "ADDRESS",                "policyLabel": "address"},
    "zip_code":                {"fieldName": "ADDRESS",                "policyLabel": "address"},
    "email":                   {"fieldName": "EMAIL_ADDRESS",          "policyLabel": "email_id"},
    "email_id":                {"fieldName": "EMAIL_ADDRESS",          "policyLabel": "email_id"},
    "phone_number":            {"fieldName": "PHONE_NUMBER",           "policyLabel": "phone_no"},
    "contact_number":          {"fieldName": "PHONE_NUMBER",           "policyLabel": "phone_no"},
    "phone":                   {"fieldName": "PHONE_NUMBER",           "policyLabel": "phone_no"},
    "social_security_number":  {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "SSN":                     {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "ssn":                     {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "ssn_no":                  {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "passport_number":         {"fieldName": "PASSPORT_NUMBER",        "policyLabel": "passport_number"},
    "passport_id":             {"fieldName": "PASSPORT_NUMBER",        "policyLabel": "passport_number"},
    "credit_card_expiry":      {"fieldName": "CARD_EXPIRY",            "policyLabel": "card_expiry"},
    "card_expiry":             {"fieldName": "CARD_EXPIRY",            "policyLabel": "card_expiry"},
    "IP_address":              {"fieldName": "IP_ADDRESS",             "policyLabel": "ip_address"},
    "ip address":              {"fieldName": "IP_ADDRESS",             "policyLabel": "ip_address"},
    "gender":                  {"fieldName": "GENDER",                 "policyLabel": "gender"},
    "cvv_number":              {"fieldName": "CVV",                    "policyLabel": "cvv_no"},
    "CVV":                     {"fieldName": "CVV",                    "policyLabel": "cvv_no"},
    "cvv":                     {"fieldName": "CVV",                    "policyLabel": "cvv_no"},
    "ethnicity":               {"fieldName": "ETHNICITY",              "policyLabel": "ethnicity"},
    "religion":                {"fieldName": "RELIGION",               "policyLabel": "religion"},
    "age":                     {"fieldName": "AGE",                    "policyLabel": "age"},
    "medical_record_number":   {"fieldName": "MRN",                    "policyLabel": "mrn_no"},
    "MRN":                     {"fieldName": "MRN",                    "policyLabel": "mrn_no"},
    "medical record":          {"fieldName": "MRN",                    "policyLabel": "mrn_no"},
    "health_plan_number":      {"fieldName": "HEALTH_PLAN",            "policyLabel": "hpbn"},
    "date_of_discharge":       {"fieldName": "DISCHARGE_DATE",         "policyLabel": "date_of_discharge"},
    "hospital_discharge_date": {"fieldName": "DISCHARGE_DATE",         "policyLabel": "date_of_discharge"},
    "date_of_admission":       {"fieldName": "ADMISSION_DATE",         "policyLabel": "date_of_admission"},
    "hospital_admission_date": {"fieldName": "ADMISSION_DATE",         "policyLabel": "date_of_admission"},
    "date_of_death":           {"fieldName": "DATE_OF_DEATH",          "policyLabel": "date_of_death"},
    "fax_number":              {"fieldName": "FAX",                    "policyLabel": "fax_no"},
    "vin":                     {"fieldName": "VIN",                    "policyLabel": "vin"},
    "vehicle_license_plate":   {"fieldName": "LICENSE_PLATE",          "policyLabel": "license_plate"},
    "device_serial_number":    {"fieldName": "DEVICE_SERIAL_NUMBER",   "policyLabel": "device_serial"},
    "url":                     {"fieldName": "URL",                    "policyLabel": "url"},
    "sexual_orientation":      {"fieldName": "SEXUAL_ORIENTATION",     "policyLabel": "sexual_orientation"},
    "race":                    {"fieldName": "RACE",                   "policyLabel": "race"},
    "organization":            {"fieldName": "ORGANIZATION",           "policyLabel": "organization"},
    "role":                    {"fieldName": "ROLE",                   "policyLabel": "role"},
    "nationality":             {"fieldName": "NATIONALITY",            "policyLabel": "nationality"},
    "health condition":        {"fieldName": "HEALTH_CONDITION",       "policyLabel": "health_condition"},
    "medication":              {"fieldName": "MEDICATION",             "policyLabel": "medication"},
}

# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    print("[Startup] Loading NLP plugins from config...")
    try:
        config  = load_config()
        plugins = config.get("plugins", [])

        for plugin in plugins:
            name    = plugin.get("name")
            enabled = plugin.get("enabled", True)

            if not enabled:
                print(f"[Startup] Skipping disabled plugin: {name}")
                continue

            loader = PLUGIN_LOADERS.get(name)
            if loader:
                loader(plugin)
            else:
                print(f"[Startup] No loader found for plugin: {name}")

    except Exception as e:
        print(f"[Startup] Failed to load config: {e}")

    print(f"[Startup] Active plugins: {list(PLUGIN_REGISTRY.keys())}")

# ─── Models ───────────────────────────────────────────────────────────────────

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[Message]
    model: Optional[str] = None

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/v1/scan")
async def scan(request: dict):
    """Call all enabled plugins, return raw entity output."""
    text        = request.get("text", "")
    all_entities = []

    print(f"\n--- NLP Scan ---")

    for name, plugin in PLUGIN_REGISTRY.items():
        try:
            entities = plugin["scanner"](text)
            all_entities.extend(entities)
            print(f"  [{name}] found {len(entities)} entities")
        except Exception as e:
            print(f"  [{name}] error: {e}")

    return {
        "nlp_scan": {
            "libraries_used": list(PLUGIN_REGISTRY.keys()),
            "entities":       all_entities,
            "entity_count":   len(all_entities)
        }
    }

@app.post("/v1/chat/completions")
async def chat(request: ChatRequest):
    """OpenAI-compatible endpoint for Bifrost compatibility."""
    full_text    = " ".join(m.content for m in request.messages)
    all_entities = []

    for name, plugin in PLUGIN_REGISTRY.items():
        try:
            entities = plugin["scanner"](full_text)
            all_entities.extend(entities)
        except Exception as e:
            print(f"  [{name}] error: {e}")

    return {
        "id":      "nlp-scan",
        "object":  "chat.completion",
        "model":   "nlp",
        "choices": [],
        "nlp_scan": {
            "libraries_used": list(PLUGIN_REGISTRY.keys()),
            "entities":       all_entities,
            "entity_count":   len(all_entities)
        }
    }

@app.get("/v1/models")
def list_models():
    return {
        "object": "list",
        "data": [{"id": "nlp", "object": "model", "owned_by": "privaclave"}]
    }

@app.get("/v1/plugins")
def list_plugins():
    return {
        "active_plugins": list(PLUGIN_REGISTRY.keys()),
        "total":          len(PLUGIN_REGISTRY)
    }

@app.post("/v1/plugins/register")
async def register_custom_plugin(payload: dict):
    """Register a custom NLP plugin at runtime without code changes."""
    try:
        module  = importlib.import_module(payload["module"])
        scanner = getattr(module, payload["scanner_fn"])
        register_plugin(payload["name"], scanner)
        return {"status": "registered", "plugin": payload["name"]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to register plugin: {str(e)}")

@app.get("/health")
def health():
    return {
        "status":         "ok",
        "service":        "privaclave-nlp-service",
        "active_plugins": list(PLUGIN_REGISTRY.keys())
    }