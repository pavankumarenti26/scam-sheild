import os
import uuid
import json
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from detectors.url_detector import analyze_url
from detectors.scam_detector import analyze_text
from detectors.voice_detector import analyze_audio
from detectors.caller_detector import analyze_caller
from detectors.risk_engine import calculate_risk

from database import (
    init_database,
    save_threat,
    get_recent_threats,
    delete_all_threats
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="ScamShield API",
    description="AI-powered scam, phishing and voice scam detection system",
    version="1.0.0"
)


# ============================================================
# DATABASE
# ============================================================

init_database()


# ============================================================
# SECURITY SETTINGS
# ============================================================

MAX_AUDIO_SIZE = 10 * 1024 * 1024

ALLOWED_AUDIO_EXTENSIONS = {
    ".mp3",
    ".wav",
    ".m4a",
    ".mp4",
    ".ogg",
    ".webm"
}


# ============================================================
# REQUEST MODELS
# ============================================================

class URLRequest(BaseModel):
    url: str


class TextRequest(BaseModel):
    text: str


class CallerRequest(BaseModel):
    phone_number: str


class CombinedRiskRequest(BaseModel):
    url_risk: int = 0
    scam_language_risk: int = 0
    voice_risk: int = 0
    caller_risk: int = 0
    ai_voice_risk: int = 0


class AnalyzeRequest(BaseModel):
    type: str
    content: str = ""
    phone_number: str = ""


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def make_reasons_list(result):
    """
    Extract possible reasons from detector output.
    Different detectors may return reasons in slightly
    different formats.
    """

    reasons = result.get("reasons", [])

    if reasons is None:
        return []

    if isinstance(reasons, str):
        return [reasons]

    if isinstance(reasons, list):
        return reasons

    return []


def save_analysis(
    threat_type,
    final_risk,
    reasons,
    input_summary
):
    """
    Save an analysis result into SQLite.
    """

    try:

        save_threat(
            threat_type=threat_type,
            risk_score=final_risk.get("risk_score", 0),
            risk_level=final_risk.get("risk_level", "SAFE"),
            recommendation=final_risk.get(
                "recommendation",
                "No major risk detected"
            ),
            reasons=json.dumps(reasons),
            input_summary=input_summary
        )

    except Exception as error:

        print("Database save error:", error)


# ============================================================
# BASIC API STATUS
# ============================================================

@app.get("/api")
def api_status():

    return {
        "status": "online",
        "application": "ScamShield",
        "version": "1.0.0",
        "message": "ScamShield backend is running"
    }


# ============================================================
# URL ANALYSIS
# ============================================================

@app.post("/analyze-url")
def analyze_url_endpoint(request: URLRequest):

    result = analyze_url(request.url)

    url_risk = result.get("risk_score", 0)

    final_risk = calculate_risk(
        url_risk=url_risk
    )

    reasons = make_reasons_list(result)

    save_analysis(
        threat_type="URL",
        final_risk=final_risk,
        reasons=reasons,
        input_summary=request.url[:200]
    )

    return {
        "type": "URL",
        "url": request.url,
        "url_analysis": result,
        "risk": final_risk,
        "reasons": reasons
    }


# ============================================================
# TEXT / MESSAGE ANALYSIS
# ============================================================

@app.post("/analyze-text")
def analyze_text_endpoint(request: TextRequest):

    result = analyze_text(request.text)

    scam_language_risk = result.get("risk_score", 0)

    final_risk = calculate_risk(
        scam_language_risk=scam_language_risk
    )

    reasons = make_reasons_list(result)

    save_analysis(
        threat_type="MESSAGE",
        final_risk=final_risk,
        reasons=reasons,
        input_summary=request.text[:200]
    )

    return {
        "type": "MESSAGE",
        "text": request.text,
        "scam_language": result,
        "risk": final_risk,
        "reasons": reasons
    }


# ============================================================
# CALLER ANALYSIS
# ============================================================

@app.post("/analyze-caller")
def analyze_caller_endpoint(request: CallerRequest):

    result = analyze_caller(request.phone_number)

    caller_risk = result.get("risk_score", 0)

    final_risk = calculate_risk(
        caller_risk=caller_risk
    )

    reasons = make_reasons_list(result)

    save_analysis(
        threat_type="CALLER",
        final_risk=final_risk,
        reasons=reasons,
        input_summary=request.phone_number[:100]
    )

    return {
        "type": "CALLER",
        "phone_number": request.phone_number,
        "caller_analysis": result,
        "risk": final_risk,
        "reasons": reasons
    }


# ============================================================
# RISK ENGINE DIRECT TEST
# ============================================================

@app.post("/calculate-risk")
def calculate_risk_endpoint(request: CombinedRiskRequest):

    result = calculate_risk(
        url_risk=request.url_risk,
        scam_language_risk=request.scam_language_risk,
        voice_risk=request.voice_risk,
        caller_risk=request.caller_risk,
        ai_voice_risk=request.ai_voice_risk
    )

    return result


# ============================================================
# COMBINED ANALYSIS
# ============================================================

@app.post("/analyze-combined")
def analyze_combined(request: CombinedRiskRequest):

    result = calculate_risk(
        url_risk=request.url_risk,
        scam_language_risk=request.scam_language_risk,
        voice_risk=request.voice_risk,
        caller_risk=request.caller_risk,
        ai_voice_risk=request.ai_voice_risk
    )

    reasons = []

    if request.url_risk >= 60:
        reasons.append("Suspicious or phishing URL detected")

    if request.scam_language_risk >= 60:
        reasons.append("Scam-like language detected")

    if request.voice_risk >= 60:
        reasons.append("Suspicious voice characteristics detected")

    if request.caller_risk >= 60:
        reasons.append("Suspicious caller number detected")

    if request.ai_voice_risk >= 60:
        reasons.append("Possible AI-generated voice characteristics detected")

    save_analysis(
        threat_type="COMBINED",
        final_risk=result,
        reasons=reasons,
        input_summary="Combined multi-signal analysis"
    )

    return {
        "risk": result,
        "signals": {
            "url_risk": request.url_risk,
            "scam_language_risk": request.scam_language_risk,
            "voice_risk": request.voice_risk,
            "caller_risk": request.caller_risk,
            "ai_voice_risk": request.ai_voice_risk
        },
        "reasons": reasons
    }


# ============================================================
# UNIFIED ANALYZE ENDPOINT
# ============================================================

@app.post("/analyze")
def analyze(request: AnalyzeRequest):

    analysis_type = request.type.lower().strip()

    # --------------------------------------------------------
    # MESSAGE
    # --------------------------------------------------------

    if analysis_type in {
        "message",
        "text",
        "sms"
    }:

        if not request.content.strip():

            raise HTTPException(
                status_code=400,
                detail="Message text is required"
            )

        result = analyze_text(request.content)

        scam_language_risk = result.get(
            "risk_score",
            0
        )

        final_risk = calculate_risk(
            scam_language_risk=scam_language_risk
        )

        reasons = make_reasons_list(result)

        save_analysis(
            threat_type="MESSAGE",
            final_risk=final_risk,
            reasons=reasons,
            input_summary=request.content[:200]
        )

        return {
            "type": "MESSAGE",
            "content": request.content,
            "scam_language": result,
            "risk": final_risk,
            "reasons": reasons
        }

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if analysis_type in {
        "url",
        "link",
        "phishing"
    }:

        if not request.content.strip():

            raise HTTPException(
                status_code=400,
                detail="URL is required"
            )

        result = analyze_url(request.content)

        url_risk = result.get(
            "risk_score",
            0
        )

        final_risk = calculate_risk(
            url_risk=url_risk
        )

        reasons = make_reasons_list(result)

        save_analysis(
            threat_type="URL",
            final_risk=final_risk,
            reasons=reasons,
            input_summary=request.content[:200]
        )

        return {
            "type": "URL",
            "content": request.content,
            "url_analysis": result,
            "risk": final_risk,
            "reasons": reasons
        }

    # --------------------------------------------------------
    # CALLER
    # --------------------------------------------------------

    if analysis_type in {
        "caller",
        "phone",
        "call"
    }:

        phone = request.phone_number.strip()

        if not phone:

            phone = request.content.strip()

        if not phone:

            raise HTTPException(
                status_code=400,
                detail="Phone number is required"
            )

        caller_result = analyze_caller(phone)

        caller_risk = caller_result.get(
            "risk_score",
            0
        )

        scam_result = None
        scam_language_risk = 0

        # If transcript/content is provided,
        # analyze the caller's speech as well.
        if request.content.strip():

            scam_result = analyze_text(
                request.content
            )

            scam_language_risk = scam_result.get(
                "risk_score",
                0
            )

        final_risk = calculate_risk(
            caller_risk=caller_risk,
            scam_language_risk=scam_language_risk
        )

        reasons = []

        reasons.extend(
            make_reasons_list(caller_result)
        )

        if scam_result:

            reasons.extend(
                make_reasons_list(scam_result)
            )

        save_analysis(
            threat_type="CALLER",
            final_risk=final_risk,
            reasons=reasons,
            input_summary=phone[:100]
        )

        return {
            "type": "CALLER",
            "phone_number": phone,
            "caller_analysis": caller_result,
            "scam_language": scam_result,
            "risk": final_risk,
            "reasons": reasons
        }

    # --------------------------------------------------------
    # UNKNOWN TYPE
    # --------------------------------------------------------

    raise HTTPException(
        status_code=400,
        detail=(
            "Unknown analysis type. "
            "Use message, url, or caller."
        )
    )


# ============================================================
# AUDIO ANALYSIS
# ============================================================

@app.post("/analyze-audio")
async def analyze_audio_endpoint(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Check filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="Audio file is required"
        )

    original_filename = file.filename

    extension = Path(
        original_filename
    ).suffix.lower()

    # --------------------------------------------------------
    # Check extension
    # --------------------------------------------------------

    if extension not in ALLOWED_AUDIO_EXTENSIONS:

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported audio format. "
                "Allowed formats: MP3, WAV, M4A, MP4, "
                "OGG and WEBM."
            )
        )

    # --------------------------------------------------------
    # Read uploaded file
    # --------------------------------------------------------

    data = await file.read()

    if not data:

        raise HTTPException(
            status_code=400,
            detail="Uploaded audio file is empty"
        )

    # --------------------------------------------------------
    # Check file size
    # --------------------------------------------------------

    if len(data) > MAX_AUDIO_SIZE:

        raise HTTPException(
            status_code=413,
            detail="Audio file is too large. Maximum size is 10 MB."
        )

    # --------------------------------------------------------
    # Temporary filename
    # --------------------------------------------------------

    temp_filename = (
        f"scamshield_{uuid.uuid4().hex}"
        f"{extension}"
    )

    temp_path = BASE_DIR / temp_filename

    try:

        # Save temporary audio
        with open(temp_path, "wb") as audio_file:

            audio_file.write(data)

        # ----------------------------------------------------
        # Run Whisper + audio detector
        # ----------------------------------------------------

        result = analyze_audio(
            str(temp_path)
        )

        # ----------------------------------------------------
        # Extract detector scores
        # ----------------------------------------------------

        voice_risk = result.get(
            "voice_risk",
            0
        )

        scam_language = result.get(
            "scam_language",
            {}
        )

        scam_language_risk = scam_language.get(
            "risk_score",
            0
        )

        voice_analysis = result.get(
            "voice_analysis",
            {}
        )

        ai_voice_risk = voice_analysis.get(
            "ai_voice_risk",
            0
        )

        # ----------------------------------------------------
        # Calculate final combined risk
        # ----------------------------------------------------

        final_risk = calculate_risk(
            scam_language_risk=scam_language_risk,
            voice_risk=voice_risk,
            ai_voice_risk=ai_voice_risk
        )

        # ----------------------------------------------------
        # Build reasons
        # ----------------------------------------------------

        reasons = []

        reasons.extend(
            make_reasons_list(
                scam_language
            )
        )

        voice_reasons = voice_analysis.get(
            "reasons",
            []
        )

        if isinstance(voice_reasons, list):

            reasons.extend(
                voice_reasons
            )

        elif isinstance(voice_reasons, str):

            reasons.append(
                voice_reasons
            )

        # Remove duplicate reasons
        reasons = list(
            dict.fromkeys(reasons)
        )

        # ----------------------------------------------------
        # Transcript
        # ----------------------------------------------------

        transcript = result.get(
            "transcript",
            ""
        )

        # ----------------------------------------------------
        # Save result
        # ----------------------------------------------------

        save_analysis(
            threat_type="AUDIO",
            final_risk=final_risk,
            reasons=reasons,
            input_summary=(
                transcript[:200]
                if transcript
                else original_filename[:200]
            )
        )

        # ----------------------------------------------------
        # Return result
        # ----------------------------------------------------

        return {

            "type": "AUDIO",

            "filename": original_filename,

            "transcript": transcript,

            "voice_risk": voice_risk,

            "audio_properties": result.get(
                "audio_properties",
                {}
            ),

            "voice_analysis": voice_analysis,

            "scam_language": scam_language,

            "reasons": reasons,

            "risk": final_risk
        }

    except Exception as error:

        print(
            "Audio analysis error:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Audio analysis failed. "
                "Please check that the audio file "
                "is valid."
            )
        )

    finally:

        # ----------------------------------------------------
        # IMPORTANT:
        # Delete temporary audio after analysis.
        # We do NOT permanently store the user's recording.
        # ----------------------------------------------------

        try:

            if temp_path.exists():

                temp_path.unlink()

        except Exception as cleanup_error:

            print(
                "Temporary file cleanup error:",
                cleanup_error
            )


# ============================================================
# RECENT THREATS
# ============================================================

@app.get("/recent-threats")
def recent_threats():

    try:

        threats = get_recent_threats(
            limit=20
        )

        # Convert JSON reasons back to Python lists
        for threat in threats:

            try:

                threat["reasons"] = json.loads(
                    threat.get("reasons", "[]")
                )

            except Exception:

                threat["reasons"] = []

        return {
            "count": len(threats),
            "threats": threats
        }

    except Exception as error:

        print(
            "Recent threats error:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve recent threats"
        )


# ============================================================
# DELETE RECENT THREATS
# ============================================================

@app.delete("/recent-threats")
def delete_recent_threats():

    try:

        delete_all_threats()

        return {
            "success": True,
            "message": "Threat history deleted"
        }

    except Exception as error:

        print(
            "Delete threats error:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to delete threat history"
        )


# ============================================================
# FRONTEND
# ============================================================

@app.get("/")
def home():

    file_path = FRONTEND_DIR / "index.html"

    if not file_path.exists():

        raise HTTPException(
            status_code=404,
            detail="Frontend index.html not found"
        )

    return FileResponse(
        file_path
    )


@app.get("/index.html")
def index_page():

    file_path = FRONTEND_DIR / "index.html"

    return FileResponse(
        file_path
    )


@app.get("/login")
def login_page():

    file_path = FRONTEND_DIR / "login.html"

    return FileResponse(
        file_path
    )


@app.get("/login.html")
def login_html_page():

    file_path = FRONTEND_DIR / "login.html"

    return FileResponse(
        file_path
    )


@app.get("/signup")
def signup_page():

    file_path = FRONTEND_DIR / "signup.html"

    return FileResponse(
        file_path
    )


@app.get("/signup.html")
def signup_html_page():

    file_path = FRONTEND_DIR / "signup.html"

    return FileResponse(
        file_path
    )


@app.get("/scam")
def scam_page():

    file_path = FRONTEND_DIR / "scam.html"

    return FileResponse(
        file_path
    )


@app.get("/scam.html")
def scam_html_page():

    file_path = FRONTEND_DIR / "scam.html"

    return FileResponse(
        file_path
    )