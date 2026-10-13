#!/usr/bin/env python3
"""AEGIS Promotional Product Advertisement Video Generator.

Generates a 60-second high-definition (1920x1080 @ 30fps) cinematic promo
with subtle Ken Burns animations, styled typography overlays, and seamless transitions.
"""

import math
import os
import shutil
import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

BASE_DIR = Path("/home/satya/.gemini/antigravity/scratch/aegis")
ASSETS_DIR = BASE_DIR / "video_assets"
FRAME_DIR = BASE_DIR / "video_frames"
OUTPUT_MP4 = Path("/home/satya/aegis-promo.mp4")

WIDTH = 1920
HEIGHT = 1080
FPS = 30
TOTAL_DURATION = 60  # seconds
TOTAL_FRAMES = TOTAL_DURATION * FPS  # 1800 frames

# Clean and prepare frames directory
if FRAME_DIR.exists():
    shutil.rmtree(FRAME_DIR)
FRAME_DIR.mkdir(parents=True, exist_ok=True)

# Fonts
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REGULAR_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_MONO_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

def load_fonts():
    return {
        "title_large": ImageFont.truetype(FONT_BOLD_PATH, 68),
        "title_medium": ImageFont.truetype(FONT_BOLD_PATH, 52),
        "headline": ImageFont.truetype(FONT_BOLD_PATH, 42),
        "body": ImageFont.truetype(FONT_REGULAR_PATH, 32),
        "badge_num": ImageFont.truetype(FONT_BOLD_PATH, 36),
        "badge_label": ImageFont.truetype(FONT_BOLD_PATH, 24),
        "mono_url": ImageFont.truetype(FONT_MONO_PATH, 46),
        "sub": ImageFont.truetype(FONT_REGULAR_PATH, 26),
    }

FONTS = load_fonts()

# Color definitions (AEGIS Navy / Cyber theme)
COLOR_BG_DARK = (10, 15, 29)          # Deep navy/slate #0a0f1d
COLOR_CYAN = (6, 182, 212)            # Accent cyan #06b6d4
COLOR_TEAL = (20, 184, 166)           # Accent teal #14b8a6
COLOR_EMERALD = (16, 185, 129)        # Verified emerald
COLOR_ROSE = (244, 63, 94)            # Alert rose #f43f5e
COLOR_PURPLE = (168, 85, 247)         # Purple accent
COLOR_WHITE = (255, 255, 255)
COLOR_MUTED = (148, 163, 184)         # Slate 400

# Cache loaded screenshots
SCREENSHOTS = {
    1: Image.open(ASSETS_DIR / "01_login_page.png").convert("RGBA"),
    2: Image.open(ASSETS_DIR / "02_dashboard.png").convert("RGBA"),
    3: Image.open(ASSETS_DIR / "03_scan_initiation.png").convert("RGBA"),
    4: Image.open(ASSETS_DIR / "04_scan_progress.png").convert("RGBA"),
    5: Image.open(ASSETS_DIR / "05_vulns_table.png").convert("RGBA"),
    6: Image.open(ASSETS_DIR / "06_evidence_drawer.png").convert("RGBA"),
    7: Image.open(ASSETS_DIR / "07_origin_infrastructure_map.png").convert("RGBA"),
    8: Image.open(ASSETS_DIR / "08_pdf_report_view.png").convert("RGBA"),
}

def ease_in_out(t):
    """Smooth cubic ease-in-out curve (0.0 to 1.0)."""
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)

def apply_ken_burns(img, progress, zoom_start=1.0, zoom_end=1.06, pan_x=0, pan_y=0):
    """Crop and resize with subtle Ken Burns zoom and pan."""
    zoom = zoom_start + (zoom_end - zoom_start) * progress
    crop_w = int(WIDTH / zoom)
    crop_h = int(HEIGHT / zoom)
    
    # Calculate offset
    max_dx = WIDTH - crop_w
    max_dy = HEIGHT - crop_h
    offset_x = int((max_dx / 2) + pan_x * progress * (max_dx / 2))
    offset_y = int((max_dy / 2) + pan_y * progress * (max_dy / 2))
    
    offset_x = max(0, min(WIDTH - crop_w, offset_x))
    offset_y = max(0, min(HEIGHT - crop_h, offset_y))
    
    cropped = img.crop((offset_x, offset_y, offset_x + crop_w, offset_y + crop_h))
    return cropped.resize((WIDTH, HEIGHT), Image.Resampling.BILINEAR)

def draw_pill_badge(draw, x, y, num_text, label_text, color=COLOR_CYAN):
    """Render a modern cybersecurity telemetry floating pill badge with shadow."""
    padding_x = 24
    padding_y = 14
    
    # Measure texts
    num_bbox = draw.textbbox((0, 0), num_text, font=FONTS["badge_num"])
    num_w = num_bbox[2] - num_bbox[0]
    
    label_bbox = draw.textbbox((0, 0), label_text, font=FONTS["badge_label"])
    label_w = label_bbox[2] - label_bbox[0]
    
    total_w = num_w + 14 + label_w + (padding_x * 2)
    total_h = 56
    
    # Backdrop container
    rect = [x, y, x + total_w, y + total_h]
    # Subtle dark pill with cyber accent border
    draw.rounded_rectangle(rect, radius=28, fill=(10, 15, 29, 235), outline=color, width=2)
    
    # Text
    draw.text((x + padding_x, y + 9), num_text, font=FONTS["badge_num"], fill=color)
    draw.text((x + padding_x + num_w + 14, y + 16), label_text, font=FONTS["badge_label"], fill=COLOR_WHITE)

def draw_top_cyber_bar(draw, section_label):
    """Render subtle header HUD tag."""
    # Top HUD
    draw.rectangle([0, 0, WIDTH, 48], fill=(5, 9, 20, 220))
    draw.line([(0, 48), (WIDTH, 48)], fill=(30, 41, 59, 255), width=1)
    
    hud_title = "AEGIS // AUTOMATED VULNERABILITY MANAGEMENT & RECON PLATFORM"
    draw.text((40, 14), hud_title, font=FONTS["sub"], fill=COLOR_CYAN)
    
    draw.text((WIDTH - 360, 14), section_label, font=FONTS["sub"], fill=COLOR_MUTED)

print(f"[*] Rendering {TOTAL_FRAMES} frames across 4 narrative acts...")

for f in range(TOTAL_FRAMES):
    sec = f / FPS
    frame = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 255))
    draw = ImageDraw.Draw(frame)

    # -------------------------------------------------------------
    # ACT 1: THE HOOK (0.0s - 10.0s)
    # -------------------------------------------------------------
    if sec < 10.0:
        # Dark cinematic navy gradient background
        draw.rectangle([0, 0, WIDTH, HEIGHT], fill=(6, 10, 22, 255))
        
        # Grid aesthetic
        for gx in range(0, WIDTH, 120):
            draw.line([(gx, 0), (gx, HEIGHT)], fill=(15, 23, 42, 60), width=1)
        for gy in range(0, HEIGHT, 120):
            draw.line([(0, gy), (WIDTH, gy)], fill=(15, 23, 42, 60), width=1)
            
        draw_top_cyber_bar(draw, "[ THREAT INTELLIGENCE ]")

        if sec < 5.0:
            # Line 1: Har website mein security holes hote hain...
            p = sec / 5.0
            alpha = int(255 * (ease_in_out(min(1.0, p * 2.5)) if p < 0.8 else max(0.0, (1.0 - p) * 5.0)))
            
            # Glowing accent shield icon / badge
            draw.ellipse([WIDTH//2 - 60, 290, WIDTH//2 + 60, 410], fill=(244, 63, 94, int(alpha * 0.15)), outline=(244, 63, 94, alpha), width=3)
            draw.text((WIDTH//2 - 20, 320), "⚠️", font=FONTS["title_large"], fill=(255, 255, 255, alpha))

            t1 = "Har website mein security holes hote hain..."
            bbox = draw.textbbox((0, 0), t1, font=FONTS["title_large"])
            w = bbox[2] - bbox[0]
            # Shadow
            draw.text(((WIDTH - w)//2 + 3, 473), t1, font=FONTS["title_large"], fill=(0, 0, 0, alpha))
            draw.text(((WIDTH - w)//2, 470), t1, font=FONTS["title_large"], fill=(255, 255, 255, alpha))

            sub1 = "Over 30,000 Common Vulnerabilities & Exposures published every year."
            s_bbox = draw.textbbox((0, 0), sub1, font=FONTS["body"])
            sw = s_bbox[2] - s_bbox[0]
            draw.text(((WIDTH - sw)//2, 570), sub1, font=FONTS["body"], fill=(203, 213, 225, alpha))

        else:
            # Line 2: Aur ek student ne tool bana di.
            p = (sec - 5.0) / 5.0
            alpha = int(255 * (ease_in_out(min(1.0, p * 2.5)) if p < 0.8 else max(0.0, (1.0 - p) * 5.0)))

            draw.ellipse([WIDTH//2 - 60, 290, WIDTH//2 + 60, 410], fill=(6, 182, 212, int(alpha * 0.18)), outline=(6, 182, 212, alpha), width=3)
            draw.text((WIDTH//2 - 24, 320), "🛡️", font=FONTS["title_large"], fill=(255, 255, 255, alpha))

            t2 = "Aur ek student ne tool bana di."
            bbox = draw.textbbox((0, 0), t2, font=FONTS["title_large"])
            w = bbox[2] - bbox[0]
            draw.text(((WIDTH - w)//2 + 3, 473), t2, font=FONTS["title_large"], fill=(0, 0, 0, alpha))
            draw.text(((WIDTH - w)//2, 470), t2, font=FONTS["title_large"], fill=(6, 182, 212, alpha))

            sub2 = "Engineered from scratch for continuous, automated vulnerability intelligence."
            s_bbox = draw.textbbox((0, 0), sub2, font=FONTS["body"])
            sw = s_bbox[2] - s_bbox[0]
            draw.text(((WIDTH - sw)//2, 570), sub2, font=FONTS["body"], fill=(226, 232, 240, alpha))

    # -------------------------------------------------------------
    # ACT 2: THE PROBLEM (10.0s - 20.0s)
    # -------------------------------------------------------------
    elif sec < 20.0:
        draw.rectangle([0, 0, WIDTH, HEIGHT], fill=(8, 12, 24, 255))
        draw_top_cyber_bar(draw, "[ THE INDUSTRY DILEMMA ]")
        
        # Grid aesthetic
        for gx in range(0, WIDTH, 120):
            draw.line([(gx, 0), (gx, HEIGHT)], fill=(15, 23, 42, 60), width=1)
        for gy in range(0, HEIGHT, 120):
            draw.line([(0, gy), (WIDTH, gy)], fill=(15, 23, 42, 60), width=1)

        p = (sec - 10.0) / 10.0
        alpha = int(255 * (ease_in_out(min(1.0, p * 2.0)) if p < 0.85 else max(0.0, (1.0 - p) * 6.0)))

        # Card 1 (Left): Commercial tools
        card1_rect = [200, 280, 880, 780]
        draw.rounded_rectangle(card1_rect, radius=20, fill=(15, 23, 42, int(alpha * 0.9)), outline=(239, 68, 68, alpha), width=2)
        draw.text((250, 330), "COMMERCIAL SCANNERS", font=FONTS["badge_label"], fill=(239, 68, 68, alpha))
        draw.text((250, 390), "Lakhon Rupaye", font=FONTS["title_medium"], fill=(255, 255, 255, alpha))
        draw.text((250, 480), "• Exorbitant per-target enterprise pricing", font=FONTS["body"], fill=(203, 213, 225, alpha))
        draw.text((250, 540), "• Proprietary vendor lock-in", font=FONTS["body"], fill=(203, 213, 225, alpha))
        draw.text((250, 600), "• Heavy enterprise licensing barriers", font=FONTS["body"], fill=(203, 213, 225, alpha))
        draw.text((250, 680), "❌ Unaffordable for students & SMEs", font=FONTS["headline"], fill=(244, 63, 94, alpha))

        # Card 2 (Right): Free tools
        card2_rect = [1040, 280, 1720, 780]
        draw.rounded_rectangle(card2_rect, radius=20, fill=(15, 23, 42, int(alpha * 0.9)), outline=(245, 158, 11, alpha), width=2)
        draw.text((1090, 330), "TRADITIONAL FREE TOOLS", font=FONTS["badge_label"], fill=(245, 158, 11, alpha))
        draw.text((1090, 390), "Sirf 'Shayad' — Proof Nahi", font=FONTS["title_medium"], fill=(255, 255, 255, alpha))
        draw.text((1090, 480), "• High rate of false positives", font=FONTS["body"], fill=(203, 213, 225, alpha))
        draw.text((1090, 540), "• Outdated static banner matches", font=FONTS["body"], fill=(203, 213, 225, alpha))
        draw.text((1090, 600), "• Zero verification proof or evidence", font=FONTS["body"], fill=(203, 213, 225, alpha))
        draw.text((1090, 680), "❌ High noise, zero confidence", font=FONTS["headline"], fill=(251, 146, 60, alpha))

    # -------------------------------------------------------------
    # ACT 3: SOLUTION SHOWCASE (20.0s - 45.0s) — MAIN SECTION
    # -------------------------------------------------------------
    elif sec < 45.0:
        act_sec = sec - 20.0  # 0.0s to 25.0s
        
        # 8 Scenes distribution:
        # Scene 1: 0 - 2.5s (2.5s) - Login Page
        # Scene 2: 2.5 - 6.5s (4.0s) - Dashboard with live data
        # Scene 3: 6.5 - 9.5s (3.0s) - Scan initiation (typing target)
        # Scene 4: 9.5 - 13.5s (4.0s) - Live scan progress
        # Scene 5: 13.5 - 17.5s (4.0s) - Vulnerabilities table
        # Scene 6: 17.5 - 21.5s (4.0s) - Evidence drawer open
        # Scene 7: 21.5 - 24.5s (3.0s) - Origin infrastructure map
        # Scene 8: 24.5 - 25.0s -> extends into 45s (3.0s total until 47.5 if needed)
        
        # Timings list: (start, end, scene_id, zoom_in/out, pill_num, pill_label, footer_text)
        TIMINGS = [
            (0.0, 2.5, 1, (1.0, 1.04, 0, 0), "SECURE RBAC", "Role-Based Access Control", "JWT Authentication · Account Lockout Defense · Enterprise Session Tokens"),
            (2.5, 6.5, 2, (1.0, 1.06, 0.2, 0.1), "267 VULNS", "Prioritized Live SOC Telemetry", "Contextual Risk Engine: CVSS (60%) + Asset Criticality (40%)"),
            (6.5, 9.5, 3, (1.02, 1.07, -0.2, 0), "TARGET RESOLVER", "Single-Click Direct Scan Pipeline", "Instant Hostname/IP Sanitization & Injection Defense"),
            (9.5, 13.5, 4, (1.0, 1.05, 0.1, 0.2), "3 MULTI-ENGINE", "Nmap + Nuclei v3 + testssl.sh", "Parallel Reconnaissance, Subdomain Probing & SSL Auditing"),
            (13.5, 17.5, 5, (1.0, 1.06, -0.1, 0.1), "11 VERIFIED", "Dynamic Finding Verification", "Version Matching · NSE Proof · Nuclei Payloads"),
            (17.5, 21.5, 6, (1.0, 1.05, 0.2, -0.1), "100%", "Evidence-Based Verification Drawer", "Raw CLI Output · Command Payloads · Danger Blast Radius"),
            (21.5, 24.0, 7, (1.0, 1.06, 0.1, 0.2), "54 ORIGIN SERVERS", "Origin Infrastructure Mapped", "Virtual Host Discovery & Cloudflare/CDN WAF Bypass Detection"),
            (24.0, 25.0, 8, (1.0, 1.04, 0, 0), "COMPLIANCE", "Automated PDF & Excel Reporting", "Executive Risk Briefings · Technical Dossiers · One-Click Export"),
        ]

        # Find current scene
        current_scene = None
        for start, end, s_id, kb_params, p_num, p_lbl, foot in TIMINGS:
            if start <= act_sec < end:
                current_scene = (start, end, s_id, kb_params, p_num, p_lbl, foot)
                break
        if not current_scene:
            current_scene = TIMINGS[-1]

        start, end, s_id, (z_start, z_end, px, py), p_num, p_lbl, foot = current_scene
        dur = end - start
        prog = (act_sec - start) / dur

        # Render screenshot with Ken Burns
        img = SCREENSHOTS[s_id]
        bg = apply_ken_burns(img, ease_in_out(prog), z_start, z_end, px, py)
        frame.paste(bg, (0, 0))

        # Vignette & Gradient Overlays for readability
        overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
        o_draw = ImageDraw.Draw(overlay)
        
        # Top gradient banner
        o_draw.rectangle([0, 0, WIDTH, 80], fill=(5, 9, 20, 210))
        o_draw.line([(0, 80), (WIDTH, 80)], fill=(30, 41, 59, 220), width=1)
        
        # Bottom gradient banner
        o_draw.rectangle([0, HEIGHT - 100, WIDTH, HEIGHT], fill=(5, 9, 20, 230))
        o_draw.line([(0, HEIGHT - 100), (WIDTH, HEIGHT - 100)], fill=(30, 41, 59, 220), width=1)
        
        frame = Image.alpha_composite(frame, overlay)
        draw = ImageDraw.Draw(frame)

        # Header Title
        draw_top_cyber_bar(draw, f"[ LIVE SHOWCASE: SCENE 0{s_id}/08 ]")

        # Telemetry Pill Badge (Top Right)
        draw_pill_badge(draw, WIDTH - 580, 105, p_num, p_lbl, COLOR_CYAN if s_id != 5 else COLOR_EMERALD)

        # Footer Text Overlay
        draw.text((60, HEIGHT - 70), foot, font=FONTS["headline"], fill=COLOR_WHITE)
        draw.text((60, HEIGHT - 35), "AEGIS VULNERABILITY MANAGEMENT & RECONNAISSANCE PLATFORM", font=FONTS["badge_label"], fill=COLOR_CYAN)

    # -------------------------------------------------------------
    # ACT 4: OUTRO (45.0s - 60.0s)
    # -------------------------------------------------------------
    else:
        out_sec = sec - 45.0  # 0.0s to 15.0s
        
        # Deep cinematic cyber gradient
        draw.rectangle([0, 0, WIDTH, HEIGHT], fill=(6, 10, 24, 255))
        
        # Grid aesthetic
        for gx in range(0, WIDTH, 100):
            draw.line([(gx, 0), (gx, HEIGHT)], fill=(15, 23, 42, 70), width=1)
        for gy in range(0, HEIGHT, 100):
            draw.line([(0, gy), (WIDTH, gy)], fill=(15, 23, 42, 70), width=1)

        draw_top_cyber_bar(draw, "[ PROJECT ARCHITECTURE ]")

        if out_sec < 5.0:
            # 45.0s - 50.0s: Creator introduction & Open Source milestone
            p = out_sec / 5.0
            alpha = int(255 * (ease_in_out(min(1.0, p * 2.5)) if p < 0.8 else max(0.0, (1.0 - p) * 5.0)))

            # Logo & Brand Name
            draw.text((WIDTH//2 - 200, 220), "🛡️  A E G I S", font=FONTS["title_large"], fill=(6, 182, 212, alpha))
            
            tag = "OPEN SOURCE CYBERSECURITY PLATFORM"
            t_bbox = draw.textbbox((0, 0), tag, font=FONTS["badge_label"])
            tw = t_bbox[2] - t_bbox[0]
            draw.text(((WIDTH - tw)//2, 320), tag, font=FONTS["badge_label"], fill=(148, 163, 184, alpha))

            # Creator Badge
            credit = "Designed & Built by SatyaPrakash Sahu"
            c_bbox = draw.textbbox((0, 0), credit, font=FONTS["headline"])
            cw = c_bbox[2] - c_bbox[0]
            draw.text(((WIDTH - cw)//2, 450), credit, font=FONTS["headline"], fill=(255, 255, 255, alpha))

            tech_stack = "FastAPI · PostgreSQL · React 18 · TailwindCSS · Nmap · Nuclei · Docker"
            ts_bbox = draw.textbbox((0, 0), tech_stack, font=FONTS["body"])
            tsw = ts_bbox[2] - ts_bbox[0]
            draw.text(((WIDTH - tsw)//2, 540), tech_stack, font=FONTS["body"], fill=(100, 116, 139, alpha))

            sub_open = "Sab documented. 100% Free & Open Source."
            so_bbox = draw.textbbox((0, 0), sub_open, font=FONTS["body"])
            sow = so_bbox[2] - so_bbox[0]
            draw.text(((WIDTH - sow)//2, 630), sub_open, font=FONTS["body"], fill=(6, 182, 212, alpha))

        elif out_sec < 11.5:
            # 50.0s - 56.5s: PROMINENT GITHUB LINK OVERLAY CARD (Task 2)
            # The voiceover speaks "Link description mein"
            p = (out_sec - 5.0) / 6.5
            fade_in = ease_in_out(min(1.0, p * 3.5))
            fade_out = 1.0 if p < 0.85 else max(0.0, (1.0 - p) * 6.66)
            alpha = int(255 * fade_in * fade_out)

            # Subtle breathing glow/pulse effect on border & accent
            pulse = math.sin((out_sec - 5.0) * 4.0) * 0.5 + 0.5  # 0.0 to 1.0 oscillation
            glow_intensity = int(180 + pulse * 75)
            glow_color = (6, glow_intensity, 212, alpha)

            # Prominent Centered GitHub Card
            card_w = 1160
            card_h = 520
            card_x1 = (WIDTH - card_w) // 2
            card_y1 = 260
            card_x2 = card_x1 + card_w
            card_y2 = card_y1 + card_h

            # Outer subtle glow box
            draw.rounded_rectangle([card_x1 - 6, card_y1 - 6, card_x2 + 6, card_y2 + 6], radius=28, outline=(6, 182, 212, int(alpha * 0.35 * (0.6 + 0.4 * pulse))), width=3)
            # Main dark container
            draw.rounded_rectangle([card_x1, card_y1, card_x2, card_y2], radius=24, fill=(10, 15, 29, int(alpha * 0.95)), outline=glow_color, width=3)

            # Card Header: 🛡️  A E G I S
            brand = "🛡️  A E G I S"
            b_bbox = draw.textbbox((0, 0), brand, font=FONTS["title_large"])
            bw = b_bbox[2] - b_bbox[0]
            draw.text(((WIDTH - bw)//2, card_y1 + 45), brand, font=FONTS["title_large"], fill=(255, 255, 255, alpha))

            # Sub-header: Official Open Source Repository
            repo_lbl = "OFFICIAL OPEN-SOURCE REPOSITORY"
            rl_bbox = draw.textbbox((0, 0), repo_lbl, font=FONTS["badge_label"])
            rlw = rl_bbox[2] - rl_bbox[0]
            draw.text(((WIDTH - rlw)//2, card_y1 + 135), repo_lbl, font=FONTS["badge_label"], fill=(148, 163, 184, alpha))

            # GitHub URL Highlight Box
            url_box = [card_x1 + 60, card_y1 + 185, card_x2 - 60, card_y1 + 300]
            draw.rounded_rectangle(url_box, radius=16, fill=(15, 23, 42, alpha), outline=(6, 182, 212, int(alpha * 0.8)), width=2)
            gh_url = "github.com/Satyaprakash37/Aegis"
            u_bbox = draw.textbbox((0, 0), gh_url, font=FONTS["mono_url"])
            uw = u_bbox[2] - u_bbox[0]
            draw.text(((WIDTH - uw)//2, card_y1 + 218), gh_url, font=FONTS["mono_url"], fill=(6, glow_intensity, 212, alpha))

            # Divider line inside card
            draw.line([(card_x1 + 160, card_y1 + 350), (card_x2 - 160, card_y1 + 350)], fill=(30, 41, 59, alpha), width=2)

            # Motto: Detect nahi. Verify.
            motto = "Detect nahi. Verify."
            m_bbox = draw.textbbox((0, 0), motto, font=FONTS["headline"])
            mw = m_bbox[2] - m_bbox[0]
            draw.text(((WIDTH - mw)//2, card_y1 + 385), motto, font=FONTS["headline"], fill=(255, 255, 255, alpha))

            # Footnote: Link description mein
            desc_hint = "📌 Link description mein available hai"
            dh_bbox = draw.textbbox((0, 0), desc_hint, font=FONTS["body"])
            dhw = dh_bbox[2] - dh_bbox[0]
            draw.text(((WIDTH - dhw)//2, card_y1 + 445), desc_hint, font=FONTS["body"], fill=(203, 213, 225, alpha))

        else:
            # 56.5s - 60.0s: Final 3.5 seconds - Fade to "STAY SECURE 🛡️" Finale Card
            p = (out_sec - 11.5) / 3.5
            if p < 0.65:
                alpha = int(255 * ease_in_out(min(1.0, p * 2.5)))
            else:
                alpha = int(255 * max(0.0, (1.0 - p) * 2.85))

            final_motto = "STAY SECURE  🛡️"
            fm_bbox = draw.textbbox((0, 0), final_motto, font=FONTS["title_large"])
            fm_w = fm_bbox[2] - fm_bbox[0]
            draw.text(((WIDTH - fm_w)//2, 450), final_motto, font=FONTS["title_large"], fill=(6, 182, 212, alpha))
            
            sub_motto = "Continuous Reconnaissance · Contextual Risk Engine · Verifiable Defense"
            sm_bbox = draw.textbbox((0, 0), sub_motto, font=FONTS["body"])
            sm_w = sm_bbox[2] - sm_bbox[0]
            draw.text(((WIDTH - sm_w)//2, 550), sub_motto, font=FONTS["body"], fill=(255, 255, 255, alpha))

    # Save rendered frame
    frame_rgb = frame.convert("RGB")
    frame_filename = FRAME_DIR / f"frame_{f:05d}.jpg"
    frame_rgb.save(frame_filename, quality=95)

    if f % 150 == 0 or f == TOTAL_FRAMES - 1:
        print(f"[*] Processed frame {f}/{TOTAL_FRAMES} ({(f/TOTAL_FRAMES)*100:.1f}%) — {sec:.1f}s")

print(f"\n[✓] All {TOTAL_FRAMES} frames generated cleanly in {FRAME_DIR}!")

# -----------------------------------------------------------------
# FFmpeg Video Assembly Pipeline
# -----------------------------------------------------------------
print(f"[*] Invoking FFmpeg to assemble H.264 MP4: {OUTPUT_MP4}...")

ffmpeg_cmd = [
    "ffmpeg",
    "-y",
    "-framerate", str(FPS),
    "-i", str(FRAME_DIR / "frame_%05d.jpg"),
    "-c:v", "libx264",
    "-preset", "medium",
    "-crf", "18",  # Visually lossless high quality
    "-pix_fmt", "yuv420p",
    "-movflags", "+faststart",
    str(OUTPUT_MP4),
]

subprocess.run(ffmpeg_cmd, check=True)
print(f"\n[✓] Promotional Video successfully rendered at: {OUTPUT_MP4}!")
