from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import importlib

app = FastAPI(title="Privaclave NLP Service")

# ─── Plugin Registry ──────────────────────────────────────────────────────────
PLUGIN_REGISTRY: Dict[str, Any] = {}

def register_plugin(name: str, scanner):
    PLUGIN_REGISTRY[name] = {"scanner": scanner}
    print(f"[Plugin Registry] Registered plugin: {name}")

# ─── Entity Mapping ───────────────────────────────────────────────────────────
# Maps GLiNER raw labels → standard field names and policy labels
ENTITY_MAPPING = {
    "person": {"fieldName": "FULL_NAME", "policyLabel": "name"},
    "name": {"fieldName": "FULL_NAME", "policyLabel": "name"},
    "first_name": {"fieldName": "FULL_NAME", "policyLabel": "name"},
    "last_name": {"fieldName": "FULL_NAME", "policyLabel": "name"},
    "geo_location": {"fieldName": "GEOLOCATION", "policyLabel": "geo_location"},
    "geolocation_information": {"fieldName": "GEOLOCATION", "policyLabel": "geo_location"},
    "longitude": {"fieldName": "GEOLOCATION", "policyLabel": "geo_location"},
    "latitude": {"fieldName": "GEOLOCATION", "policyLabel": "geo_location"},
    "bank_account": {"fieldName": "BAN", "policyLabel": "ban_no"},
    "bank_account_number": {"fieldName": "BAN", "policyLabel": "ban_no"},
    "account_no": {"fieldName": "BAN", "policyLabel": "ban_no"},
    "payment_card": {"fieldName": "PAN", "policyLabel": "pan_no"},
    "credit_card_number": {"fieldName": "PAN", "policyLabel": "pan_no"},
    "card_number": {"fieldName": "PAN", "policyLabel": "pan_no"},
    "birth_date": {"fieldName": "DOB", "policyLabel": "dob"},
    "DOB": {"fieldName": "DOB", "policyLabel": "dob"},
    "dob": {"fieldName": "DOB", "policyLabel": "dob"},
    "date of birth": {"fieldName": "DOB", "policyLabel": "dob"},
    "address": {"fieldName": "ADDRESS", "policyLabel": "address"},
    "street": {"fieldName": "ADDRESS", "policyLabel": "address"},
    "city": {"fieldName": "ADDRESS", "policyLabel": "address"},
    "zip_code": {"fieldName": "ADDRESS", "policyLabel": "address"},
    "email": {"fieldName": "EMAIL_ADDRESS", "policyLabel": "email_id"},
    "email_id": {"fieldName": "EMAIL_ADDRESS", "policyLabel": "email_id"},
    "phone_number": {"fieldName": "PHONE_NUMBER", "policyLabel": "phone_no"},
    "contact_number": {"fieldName": "PHONE_NUMBER", "policyLabel": "phone_no"},
    "phone": {"fieldName": "PHONE_NUMBER", "policyLabel": "phone_no"},
    "social_security_number": {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "SSN": {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "ssn": {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "ssn_no": {"fieldName": "SOCIAL_SECURITY_NUMBER", "policyLabel": "ssn_no"},
    "passport_number": {"fieldName": "PASSPORT_NUMBER", "policyLabel": "passport_number"},
    "passport_id": {"fieldName": "PASSPORT_NUMBER", "policyLabel": "passport_number"},
    "credit_card_expiry": {"fieldName": "CARD_EXPIRY", "policyLabel": "card_expiry"},
    "card_expiry": {"fieldName": "CARD_EXPIRY", "policyLabel": "card_expiry"},
    "IP_address": {"fieldName": "IP_ADDRESS", "policyLabel": "ip_address"},
    "ip address": {"fieldName": "IP_ADDRESS", "policyLabel": "ip_address"},
    "gender": {"fieldName": "GENDER", "policyLabel": "gender"},
    "cvv_number": {"fieldName": "CVV", "policyLabel": "cvv_no"},
    "CVV": {"fieldName": "CVV", "policyLabel": "cvv_no"},
    "cvv": {"fieldName": "CVV", "policyLabel": "cvv_no"},
    "ethnicity": {"fieldName": "ETHNICITY", "policyLabel": "ethnicity"},
    "religion": {"fieldName": "RELIGION", "policyLabel": "religion"},
    "age": {"fieldName": "AGE", "policyLabel": "age"},
    "medical_record_number": {"fieldName": "MRN", "policyLabel": "mrn_no"},
    "MRN": {"fieldName": "MRN", "policyLabel": "mrn_no"},
    "medical record": {"fieldName": "MRN", "policyLabel": "mrn_no"},
    "health_plan_number": {"fieldName": "HEALTH_PLAN", "policyLabel": "hpbn"},
    "date_of_discharge": {"fieldName": "DISCHARGE_DATE", "policyLabel": "date_of_discharge"},
    "hospital_discharge_date": {"fieldName": "DISCHARGE_DATE", "policyLabel": "date_of_discharge"},
    "date_of_admission": {"fieldName": "ADMISSION_DATE", "policyLabel": "date_of_admission"},
    "hospital_admission_date": {"fieldName": "ADMISSION_DATE", "policyLabel": "date_of_admission"},
    "date_of_death": {"fieldName": "DATE_OF_DEATH", "policyLabel": "date_of_death"},
    "fax_number": {"fieldName": "FAX", "policyLabel": "fax_no"},
    "vin": {"fieldName": "VIN", "policyLabel": "vin"},
    "vehicle_license_plate": {"fieldName": "LICENSE_PLATE", "policyLabel": "license_plate"},
    "device_serial_number": {"fieldName": "DEVICE_SERIAL_NUMBER", "policyLabel": "device_serial"},
    "url": {"fieldName": "URL", "policyLabel": "url"},
    "sexual_orientation": {"fieldName": "SEXUAL_ORIENTATION", "policyLabel": "sexual_orientation"},
    "race": {"fieldName": "RACE", "policyLabel": "race"},
    "organization": {"fieldName": "ORGANIZATION", "policyLabel": "organization"},
    "role": {"fieldName": "ROLE", "policyLabel": "role"},
    "nationality": {"fieldName": "NATIONALITY", "policyLabel": "nationality"},
    "health condition": {"fieldName": "HEALTH_CONDITION", "policyLabel": "health_condition"},
    "medication": {"fieldName": "MEDICATION", "policyLabel": "medication"},
}

# ─── Built-in Plugins ─────────────────────────────────────────────────────────

def load_spacy():
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")

        def spacy_scan(text: str) -> list:
            doc = nlp(text)
            results = []
            for ent in doc.ents:
                results.append({
                    "text":   ent.text,
                    "type":   ent.label_,
                    "source": "spacy",
                    "start":  ent.start_char,
                    "end":    ent.end_char,
                    "score":  1.0
                })
            return results

        register_plugin("spacy", spacy_scan)
        print("[Startup] Spacy loaded successfully")
    except Exception as e:
        print(f"[Startup] Spacy failed to load: {e}")

def load_gliner():
    try:
        from gliner import GLiNER

        # Labels from entity mapping file
        GLINER_LABELS = [
            "person", "name", "geo_location", "bank_account", "payment_card",
            "birth_date", "dob", "address", "street", "city", "zip_code",
            "email", "phone_number", "social_security_number", "ssn",
            "passport_number", "credit_card_expiry", "card_expiry",
            "IP_address", "gender", "cvv_number", "ethnicity", "religion",
            "age", "medical_record_number", "health_plan_number",
            "date_of_discharge", "date_of_admission", "date_of_death",
            "fax_number", "vin", "vehicle_license_plate", "device_serial_number",
            "url", "sexual_orientation", "race", "organization", "role",
            "nationality", "health condition", "medication", "credit_card_number",
            "bank_account_number", "email_id", "phone", "MRN", "CVV", "ssn_no"
        ]

        gliner_model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")

        def gliner_scan(text: str) -> list:
            entities = gliner_model.predict_entities(text, GLINER_LABELS)
            results = []
            for ent in entities:
                mapped = ENTITY_MAPPING.get(ent["label"], {
                    "fieldName":   ent["label"].upper(),
                    "policyLabel": ent["label"].lower()
                })
                results.append({
                    "text":        ent["text"],
                    "type":        ent["label"],
                    "fieldName":   mapped["fieldName"],
                    "policyLabel": mapped["policyLabel"],
                    "source":      "gliner",
                    "start":       ent.get("start", None),
                    "end":         ent.get("end",   None),
                    "score":       round(ent["score"], 11)
                })
            return results

        register_plugin("gliner", gliner_scan)
        print("[Startup] GLiNER loaded successfully")
    except Exception as e:
        print(f"[Startup] GLiNER failed to load: {e}")

# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    print("[Startup] Loading NLP plugins...")
    load_spacy()
    load_gliner()
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
    """Call spaCy and GLiNER, return raw entity output with char positions."""
    text = request.get("text", "")
    all_entities = []

    print(f"\n--- NLP Scan ---")

    if "spacy" in PLUGIN_REGISTRY:
        try:
            entities = PLUGIN_REGISTRY["spacy"]["scanner"](text)
            all_entities.extend(entities)
            print(f"  [spacy] found {len(entities)} entities")
        except Exception as e:
            print(f"  [spacy] error: {e}")

    if "gliner" in PLUGIN_REGISTRY:
        try:
            entities = PLUGIN_REGISTRY["gliner"]["scanner"](text)
            all_entities.extend(entities)
            print(f"  [gliner] found {len(entities)} entities")
        except Exception as e:
            print(f"  [gliner] error: {e}")

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
    full_text = " ".join(m.content for m in request.messages)
    all_entities = []

    if "spacy" in PLUGIN_REGISTRY:
        try:
            entities = PLUGIN_REGISTRY["spacy"]["scanner"](full_text)
            all_entities.extend(entities)
        except Exception as e:
            print(f"  [spacy] error: {e}")

    if "gliner" in PLUGIN_REGISTRY:
        try:
            entities = PLUGIN_REGISTRY["gliner"]["scanner"](full_text)
            all_entities.extend(entities)
        except Exception as e:
            print(f"  [gliner] error: {e}")

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
        "total": len(PLUGIN_REGISTRY)
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
        "status": "ok",
        "service": "privaclave-nlp-service",
        "active_plugins": list(PLUGIN_REGISTRY.keys())
    }