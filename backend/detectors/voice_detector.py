import os
import subprocess
import whisper
import librosa
import numpy as np

from detectors.scam_detector import analyze_text


print("Loading Whisper model...")
model = whisper.load_model("base")
print("Whisper model loaded!")


def convert_to_wav(input_path):
    output_path = os.path.splitext(input_path)[0] + "_converted.wav"

    command = [
        "ffmpeg",
        "-y",
        "-i",
        input_path,
        "-vn",
        "-ac",
        "1",
        "-ar",
        "16000",
        output_path
    ]

    subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    )

    return output_path


def calculate_audio_anomaly(audio, sample_rate):
    """
    Calculate a simple explainable audio anomaly signal.

    This is NOT a definitive AI/deepfake detector.
    It only identifies unusual acoustic characteristics.
    """

    # Calculate RMS energy
    rms = librosa.feature.rms(y=audio)[0]

    average_energy = float(np.mean(rms))
    energy_variation = float(np.std(rms))

    # Calculate spectral centroid
    spectral_centroid = librosa.feature.spectral_centroid(
        y=audio,
        sr=sample_rate
    )[0]

    average_centroid = float(np.mean(spectral_centroid))

    risk = 0
    reasons = []

    # Very low energy variation can indicate unusually uniform audio.
    if energy_variation < 0.01:
        risk += 20
        reasons.append("Low variation in audio energy")

    # Very high spectral centroid can indicate unusually bright/high-frequency audio.
    if average_centroid > 4000:
        risk += 15
        reasons.append("Unusual high-frequency characteristics")

    risk = min(risk, 100)

    if risk >= 60:
        confidence = "MEDIUM"
    elif risk >= 30:
        confidence = "LOW"
    else:
        confidence = "LOW"

    if not reasons:
        reasons.append("No strong acoustic anomaly detected")

    return {
        "ai_voice_risk": risk,
        "confidence": confidence,
        "reasons": reasons,
        "average_energy": round(average_energy, 5),
        "energy_variation": round(energy_variation, 5),
        "average_spectral_centroid": round(average_centroid, 2)
    }


def analyze_audio(audio_path):

    # 1. Convert audio/video to WAV
    wav_path = convert_to_wav(audio_path)

    # 2. Load audio
    audio, sample_rate = librosa.load(
        wav_path,
        sr=None,
        mono=True
    )

    # 3. Audio properties
    duration = librosa.get_duration(
        y=audio,
        sr=sample_rate
    )

    # 4. Acoustic anomaly analysis
    voice_analysis = calculate_audio_anomaly(
        audio,
        sample_rate
    )

    # 5. Speech transcription
    result = model.transcribe(wav_path)

    transcript = result["text"].strip()

    # 6. Scam-language analysis
    scam_result = analyze_text(transcript)

    return {
        "transcript": transcript,

        "voice_risk": scam_result["risk_score"],

        "audio_properties": {
            "duration_seconds": round(duration, 2),
            "sample_rate": sample_rate,
            "channels": 1
        },

        "voice_analysis": voice_analysis,

        "scam_language": scam_result
    }