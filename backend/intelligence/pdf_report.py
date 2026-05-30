import os
from typing import List, Any
from datetime import datetime
from backend.models import AttackerAction

try:
    from fpdf import FPDF
    _FPDF_AVAILABLE = True
except ImportError:
    _FPDF_AVAILABLE = False
    FPDF = object


class ShadowMeshReport(FPDF if _FPDF_AVAILABLE else object):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.set_text_color(226, 75, 74)
        self.cell(0, 10, 'ShadowMesh Threat Intelligence Report', border=False, align='C', new_x='LMARGIN', new_y='NEXT')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def generate_pdf_report(attacker_ip: str, profile: Any, actions: List[AttackerAction], threat_score: dict) -> bytes:
    if not _FPDF_AVAILABLE:
        return b"PDF generation unavailable - install fpdf2: pip install fpdf2"

    pdf = ShadowMeshReport()
    pdf.add_page()

    # Handle profile type
    if isinstance(profile, dict):
        skill = profile.get("skill_level", "Unknown")
        objective = profile.get("objective", "Unknown")
        tools = profile.get("tools_detected", [])
        summary = profile.get("summary", "No summary available.")
        apt = profile.get("apt_resemblance", "Unknown")
        confidence = profile.get("confidence", 0.0)
    else:
        skill = getattr(profile, "skill_level", "Unknown")
        objective = getattr(profile, "objective", "Unknown")
        tools = getattr(profile, "tools_detected", [])
        summary = getattr(profile, "summary", "No summary available.")
        apt = getattr(profile, "apt_resemblance", "Unknown")
        confidence = getattr(profile, "confidence", 0.0)

    score_val = threat_score.get('threat_score', 0) if threat_score else 0

    # Attacker Overview
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(255, 255, 255)
    pdf.set_fill_color(30, 30, 30)
    pdf.cell(0, 10, f' Target IP: {attacker_ip}', fill=True, new_x='LMARGIN', new_y='NEXT')
    
    pdf.set_font('helvetica', '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)
    
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'Skill Level:', new_x='RIGHT')
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 8, skill.upper(), new_x='LMARGIN', new_y='NEXT')

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'APT Resemblance:', new_x='RIGHT')
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 8, apt, new_x='LMARGIN', new_y='NEXT')

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'Anomaly Score:', new_x='RIGHT')
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 8, f"{score_val*100:.0f}%", new_x='LMARGIN', new_y='NEXT')

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'Objective:', new_x='RIGHT')
    pdf.set_font('helvetica', '', 10)
    pdf.multi_cell(0, 8, objective, new_x='LMARGIN', new_y='NEXT')

    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(40, 8, 'Tools Detected:', new_x='RIGHT')
    pdf.set_font('helvetica', '', 10)
    pdf.multi_cell(0, 8, ", ".join(tools) if tools else "None detected", new_x='LMARGIN', new_y='NEXT')
    
    pdf.ln(5)
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, ' Executive Summary', fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('helvetica', '', 10)
    pdf.ln(2)
    pdf.multi_cell(0, 6, summary, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)

    # Action Timeline
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, ' Action Timeline (MITRE ATT&CK)', fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    pdf.set_font('helvetica', '', 9)
    for action in actions[-20:]: # Last 20 actions
        ts = datetime.fromtimestamp(action.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        tech = action.mitre_technique_name or action.action_type
        tid = f"[{action.mitre_technique_id}]" if action.mitre_technique_id else ""
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 6, ts, new_x='RIGHT')
        pdf.set_font('helvetica', '', 9)
        pdf.multi_cell(0, 6, f"{tech} {tid} - {action.detail}", new_x='LMARGIN', new_y='NEXT')
        pdf.ln(1)

    return bytes(pdf.output())
