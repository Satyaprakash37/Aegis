import asyncio
import edge_tts
from pathlib import Path

VOICE = "hi-IN-MadhurNeural"
OUTPUT_FILE = Path("/home/satya/voice.mp3")

SCRIPT = """
Namaste. Main SatyaPrakash hoon.
Kuch mahine pehle ek cheez notice ki - har website mein security holes hain.
Aur jo tools unhe dhundte hain... wo ya toh lakhon rupaye ke hain... ya sirf shayad bolte hain. Proof nahi.
Toh maine khud ek platform banaya. AEGIS.
Ye sirf scan nahi karta. VERIFY karta hai. Proof ke saath.
Cloudflare jaisi security ke piche chhupe servers tak dhundhta hai.
Maine apni hi university ki website pe test kiya. Permission ke saath.
234 subdomains. 11 confirmed vulnerabilities. Sab documented.
Aur ye sab open source hai. Free. GitHub pe.
Main SatyaPrakash Sahu. Aur ye sirf shuruaat hai.
Stay secure.
""".strip()

async def main():
    print(f"[*] Generating voiceover using {VOICE} with +15% rate...")
    # +15% rate produces ~60s natural, energetic pacing
    communicate = edge_tts.Communicate(SCRIPT, VOICE, rate="+15%", pitch="+0Hz")
    await communicate.save(str(OUTPUT_FILE))
    print(f"[✓] Voiceover saved cleanly to {OUTPUT_FILE}!")

if __name__ == "__main__":
    asyncio.run(main())
