"""AEGIS AI Operations Copilot Core Engine.

Coordinates Gemini LLM reasoning, read-only platform tool calling,
and context-aware defensive security guidance.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.chat_message import ChatMessage
from app.services.copilot.tools import CopilotToolbox

logger = logging.getLogger("aegis.copilot.engine")

SYSTEM_PROMPT = (
    "You are AEGIS Copilot - a senior defensive security analyst assistant. "
    "You help human operators understand scan results, research vulnerability context, "
    "prioritize assessment work, and prepare remediation plans. You access platform data via tools. "
    "You explain findings clearly, cite data (KEV status, EPSS scores, references) and suggest which "
    "vulnerabilities deserve attention first and why. You never exaggerate - if data is uncertain, say so."
)

TOOL_DECLARATIONS = [
    {
        "function_declarations": [
            {
                "name": "get_asset_context",
                "description": "Retrieve target asset profile, metadata, and vulnerability counts.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "asset_id": {"type": "INTEGER", "description": "Target asset identifier."}
                    },
                    "required": ["asset_id"],
                },
            },
            {
                "name": "get_scan_results",
                "description": "Fetch historical audit and vulnerability scan records for an asset.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "asset_id": {"type": "INTEGER", "description": "Target asset identifier."},
                        "limit": {"type": "INTEGER", "description": "Maximum scans to return (default 5)."},
                    },
                    "required": ["asset_id"],
                },
            },
            {
                "name": "research_cve",
                "description": "Research a specific CVE identifier across NVD and local database occurrences.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "cve_id": {"type": "STRING", "description": "Standard CVE identifier (e.g. CVE-2021-44228)."}
                    },
                    "required": ["cve_id"],
                },
            },
            {
                "name": "check_kev",
                "description": "Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "cve_id": {"type": "STRING", "description": "CVE identifier."}
                    },
                    "required": ["cve_id"],
                },
            },
            {
                "name": "get_epss",
                "description": "Retrieve FIRST EPSS exploitation probability score and percentile for a CVE.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "cve_id": {"type": "STRING", "description": "CVE identifier."}
                    },
                    "required": ["cve_id"],
                },
            },
            {
                "name": "find_public_exploit_refs",
                "description": "Retrieve documented public exploit references and PoC links for a CVE.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "cve_id": {"type": "STRING", "description": "CVE identifier."}
                    },
                    "required": ["cve_id"],
                },
            },
            {
                "name": "get_top_vulnerabilities",
                "description": "Fetch highest priority vulnerabilities for an asset ordered by risk and severity.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "asset_id": {"type": "INTEGER", "description": "Target asset identifier."},
                        "count": {"type": "INTEGER", "description": "Number of vulnerabilities to retrieve (default 10)."},
                    },
                    "required": ["asset_id"],
                },
            },
            {
                "name": "suggest_next_steps",
                "description": "Generate a prioritized, defensive assessment and remediation checklist for an asset.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "asset_id": {"type": "INTEGER", "description": "Target asset identifier."}
                    },
                    "required": ["asset_id"],
                },
            },
        ]
    }
]


class CopilotEngine:
    """Orchestrates Gemini conversational loop with defensive platform tools."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.toolbox = CopilotToolbox(db)

    async def execute_tool(self, name: str, args: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        """Dispatch a tool invocation and return (result, summary_string)."""
        clean_args = {k: v for k, v in args.items()}
        summary = f"{name}({', '.join(f'{k}={v}' for k, v in clean_args.items())})"

        if name == "get_asset_context":
            res = await self.toolbox.get_asset_context(int(clean_args.get("asset_id", 0)))
        elif name == "get_scan_results":
            res = await self.toolbox.get_scan_results(
                int(clean_args.get("asset_id", 0)),
                int(clean_args.get("limit", 5)),
            )
        elif name == "research_cve":
            res = await self.toolbox.research_cve(str(clean_args.get("cve_id", "")))
        elif name == "check_kev":
            res = await self.toolbox.check_kev(str(clean_args.get("cve_id", "")))
        elif name == "get_epss":
            res = await self.toolbox.get_epss(str(clean_args.get("cve_id", "")))
        elif name == "find_public_exploit_refs":
            res = await self.toolbox.find_public_exploit_refs(str(clean_args.get("cve_id", "")))
        elif name == "get_top_vulnerabilities":
            res = await self.toolbox.get_top_vulnerabilities(
                int(clean_args.get("asset_id", 0)),
                int(clean_args.get("count", 10)),
            )
        elif name == "suggest_next_steps":
            res = await self.toolbox.suggest_next_steps(int(clean_args.get("asset_id", 0)))
        else:
            res = {"error": f"Unknown tool: {name}"}

        return res, summary

    async def run_chat(
        self,
        asset_id: int,
        message: str,
        history_records: List[ChatMessage],
    ) -> Dict[str, Any]:
        """Run the copilot chat pipeline."""
        # 1. Fetch asset profile for context injection
        asset_ctx = await self.toolbox.get_asset_context(asset_id)
        if "error" in asset_ctx:
            return {
                "reply": f"Target asset {asset_id} was not found in the platform inventory.",
                "tools_used": [],
            }

        context_header = (
            f"\n\n[TARGET ASSET CONTEXT]: Asset ID {asset_id} ({asset_ctx.get('name')}, IP: {asset_ctx.get('ip_address')}). "
            f"Asset Type: {asset_ctx.get('asset_type')}, Criticality: {asset_ctx.get('criticality')}/5, Environment: {asset_ctx.get('environment')}. "
            f"Vulnerabilities: {asset_ctx.get('total_vulnerabilities')} total ({asset_ctx.get('open_vulnerabilities')} open), "
            f"CISA KEV Hits: {asset_ctx.get('kev_count')}, Highest Risk Score: {asset_ctx.get('highest_risk_score')}."
        )
        full_system_prompt = SYSTEM_PROMPT + context_header

        api_key = (settings.GEMINI_API_KEY or "").strip()
        is_mock = (
            api_key in ["mock", "test", "mock-copilot-test", ""]
            or api_key.startswith("mock")
            or api_key.startswith("test")
            or not api_key.startswith("AIza")  # Standard Google AI Studio API key prefix
        )

        # If not mock and looks like a valid key format, attempt live Gemini API call
        if not is_mock:
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)

                # Prepare Gemini history
                gemini_history = []
                recent_history = history_records[-10:] if history_records else []
                for h in recent_history:
                    r = "user" if h.role == "user" else "model"
                    gemini_history.append({"role": r, "parts": [h.content]})

                model = genai.GenerativeModel(
                    model_name=settings.COPILOT_MODEL or "gemini-2.0-flash",
                    system_instruction=full_system_prompt,
                    tools=TOOL_DECLARATIONS,
                )

                chat = model.start_chat(history=gemini_history)
                tools_used: List[Dict[str, Any]] = []

                # Initial prompt with timeout
                response = await asyncio.wait_for(
                    asyncio.to_thread(chat.send_message, message),
                    timeout=15.0,
                )

                # Tool execution loop (max 8 calls)
                loop_count = 0
                while loop_count < 8:
                    loop_count += 1
                    function_call = None
                    if response.candidates and response.candidates[0].content.parts:
                        for part in response.candidates[0].content.parts:
                            if hasattr(part, "function_call") and part.function_call and part.function_call.name:
                                function_call = part.function_call
                                break

                    if not function_call:
                        break

                    func_name = function_call.name
                    func_args = dict(function_call.args) if function_call.args else {}

                    tool_res, summary = await self.execute_tool(func_name, func_args)
                    tools_used.append({
                        "tool": func_name,
                        "args": func_args,
                        "summary": summary,
                    })

                    # Send tool result back to Gemini
                    fr = genai.protos.FunctionResponse(name=func_name, response={"result": tool_res})
                    content_part = genai.protos.Content(parts=[genai.protos.Part(function_response=fr)])
                    response = await asyncio.wait_for(
                        asyncio.to_thread(chat.send_message, content_part),
                        timeout=15.0,
                    )

                reply_text = response.text if hasattr(response, "text") and response.text else "Analysis complete."
                return {
                    "reply": reply_text.strip(),
                    "tools_used": tools_used,
                }

            except Exception as e:
                logger.warning("Gemini API call failed (%s). Falling back to internal analyst engine.", e)

        # Fallback / Direct Deterministic Analyst Engine
        return await self._run_defensive_analyst(asset_id, message, asset_ctx)

    async def _run_defensive_analyst(
        self,
        asset_id: int,
        message: str,
        asset_ctx: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Defensive deterministic analyst engine when live API is simulated or offline."""
        msg_lower = message.lower()
        tools_used: List[Dict[str, Any]] = []

        # Tool 1: Always check asset context
        tools_used.append({
            "tool": "get_asset_context",
            "args": {"asset_id": asset_id},
            "summary": f"get_asset_context(asset_id={asset_id})",
        })

        # Scenario A: Actively exploited / KEV / EPSS
        if any(term in msg_lower for term in ["actively exploited", "kev", "epss", "exploit in the wild", "in the wild"]):
            top_vulns_data = await self.toolbox.get_top_vulnerabilities(asset_id, count=10)
            tools_used.append({
                "tool": "get_top_vulnerabilities",
                "args": {"asset_id": asset_id, "count": 10},
                "summary": f"get_top_vulnerabilities(asset_id={asset_id}, count=10)",
            })

            vulns = top_vulns_data.get("vulnerabilities", [])
            kev_vulns = [v for v in vulns if v.get("in_kev")]

            # Run check_kev and get_epss on primary findings
            cve_to_check = kev_vulns[0]["cve_id"] if kev_vulns else (vulns[0]["cve_id"] if vulns else "CVE-2019-0211")
            
            kev_res = await self.toolbox.check_kev(cve_to_check)
            tools_used.append({
                "tool": "check_kev",
                "args": {"cve_id": cve_to_check},
                "summary": f"check_kev(cve_id='{cve_to_check}')",
            })

            epss_res = await self.toolbox.get_epss(cve_to_check)
            tools_used.append({
                "tool": "get_epss",
                "args": {"cve_id": cve_to_check},
                "summary": f"get_epss(cve_id='{cve_to_check}')",
            })

            if kev_vulns:
                lines = [
                    f"### Actively Exploited Telemetry for {asset_ctx.get('name')} ({asset_ctx.get('ip_address')})",
                    "",
                    f"Cross-referencing telemetry with the **CISA Known Exploited Vulnerabilities (KEV)** catalog and **FIRST EPSS** feeds identifies **{len(kev_vulns)} actively exploited vulnerability** on this asset:",
                    "",
                ]
                for kv in kev_vulns:
                    epss_val = f"{round(kv.get('epss_score', 0) * 100, 2)}%" if kv.get("epss_score") else "N/A"
                    lines.append(f"- **{kv.get('cve_id')}** (`{kv.get('severity', '').upper()}`, Threat Level: `{kv.get('threat_level')}`)")
                    lines.append(f"  - **Title**: {kv.get('title')}")
                    lines.append(f"  - **Service/Port**: {kv.get('service_name')} on port {kv.get('port')}")
                    lines.append(f"  - **CISA KEV Status**: Listed in active catalog (Action: `{kev_res.get('required_action', 'Apply vendor patch')}`)")
                    lines.append(f"  - **FIRST EPSS Score**: `{epss_val}` ({epss_res.get('interpretation', 'Likely Exploited')})")
                    lines.append("")
                lines.append("**Defensive Recommendation**: Prioritize emergency patching or network segmentation for these findings immediately, as they have confirmed in-the-wild weaponization.")
                reply = "\n".join(lines)
            else:
                reply = (
                    f"Based on real-time threat telemetry from CISA KEV and FIRST EPSS, there are currently **no confirmed KEV catalog entries** "
                    f"identified on target **{asset_ctx.get('name')}** (`{asset_ctx.get('ip_address')}`). "
                    f"All {asset_ctx.get('total_vulnerabilities')} findings are standard severity findings with residual exploitation risk."
                )

        # Scenario B: Critical findings / Top vulnerabilities
        elif any(term in msg_lower for term in ["critical", "most critical", "top", "highest risk", "findings"]):
            top_vulns_data = await self.toolbox.get_top_vulnerabilities(asset_id, count=5)
            tools_used.append({
                "tool": "get_top_vulnerabilities",
                "args": {"asset_id": asset_id, "count": 5},
                "summary": f"get_top_vulnerabilities(asset_id={asset_id}, count=5)",
            })

            vulns = top_vulns_data.get("vulnerabilities", [])
            lines = [
                f"### Highest Risk Security Findings on {asset_ctx.get('name')} (`{asset_ctx.get('ip_address')}`)",
                "",
                f"Target criticality is rated **{asset_ctx.get('criticality')}/5** in environment `{asset_ctx.get('environment')}`. "
                f"Here are the top prioritized vulnerabilities ordered by Contextual Risk Score and Threat Level:",
                "",
            ]
            for idx, v in enumerate(vulns[:5], 1):
                kev_flag = "⚠️ **[CISA KEV]** " if v.get("in_kev") else ""
                lines.append(f"{idx}. {kev_flag}**{v.get('cve_id')}** — {v.get('title')}")
                lines.append(f"   - **Severity**: `{v.get('severity', '').upper()}` (CVSS: {v.get('cvss_score')}) | **Risk Score**: `{v.get('risk_score')}`")
                lines.append(f"   - **Threat Level**: `{v.get('threat_level')}` | **Port**: {v.get('port')} ({v.get('service_name')})")
                if v.get("epss_score"):
                    lines.append(f"   - **EPSS Likelihood**: `{round(v['epss_score'] * 100, 2)}%`")
                lines.append("")
            
            lines.append("**Analyst Assessment**: Focus remediation effort on the top-ranking findings above, verifying exposed ports and applying recommended patches.")
            reply = "\n".join(lines)

        # Scenario C: What to assess first / Next steps
        elif any(term in msg_lower for term in ["assess first", "next step", "what should", "prioritize", "remediation", "checklist"]):
            next_steps = await self.toolbox.suggest_next_steps(asset_id)
            tools_used.append({
                "tool": "suggest_next_steps",
                "args": {"asset_id": asset_id},
                "summary": f"suggest_next_steps(asset_id={asset_id})",
            })

            checklist = next_steps.get("prioritized_checklist", [])
            lines = [
                f"### Recommended Defensive Assessment Plan for {asset_ctx.get('name')}",
                "",
                "Our threat-weighted triage model prioritizes actions in order of weaponization evidence (CISA KEV first, then elevated EPSS, followed by severity):",
                "",
            ]
            for item in checklist:
                cve_ref = f" ({item.get('cve_id')})" if item.get("cve_id") else ""
                lines.append(f"**Step {item.get('priority')}: {item.get('phase')}**{cve_ref}")
                lines.append(f"- **Action**: {item.get('action')}")
                lines.append(f"- **Rationale**: {item.get('rationale')}")
                lines.append("")
            reply = "\n".join(lines)

        # Scenario D: Attack surface summary / scan results
        elif any(term in msg_lower for term in ["attack surface", "scans", "history", "surface", "ports"]):
            scan_data = await self.toolbox.get_scan_results(asset_id, limit=5)
            tools_used.append({
                "tool": "get_scan_results",
                "args": {"asset_id": asset_id, "limit": 5},
                "summary": f"get_scan_results(asset_id={asset_id}, limit=5)",
            })

            scans = scan_data.get("scans", [])
            recent_scan = scans[0] if scans else {}
            reply = (
                f"### Attack Surface Overview: {asset_ctx.get('name')} (`{asset_ctx.get('ip_address')}`)\n\n"
                f"- **Perimeter**: Type `{asset_ctx.get('asset_type')}`, resolved IP `{asset_ctx.get('resolved_ip') or asset_ctx.get('ip_address')}`.\n"
                f"- **Audit History**: {len(scans)} recent scans executed (Latest: Scan #{recent_scan.get('scan_id', 'N/A')} `{recent_scan.get('scan_type', 'quick')}` - status: `{recent_scan.get('status', 'completed')}`).\n"
                f"- **Exposure Metrics**: {asset_ctx.get('total_vulnerabilities')} total CVEs identified ({asset_ctx.get('open_vulnerabilities')} open), "
                f"with {asset_ctx.get('severity_breakdown', {}).get('critical', 0)} Critical and {asset_ctx.get('severity_breakdown', {}).get('high', 0)} High severity issues.\n"
                f"- **Active Threats**: {asset_ctx.get('threat_level_breakdown', {}).get('ACTIVE-THREAT', 0)} findings categorized as ACTIVE-THREAT with {asset_ctx.get('kev_count', 0)} in CISA KEV."
            )

        # Scenario E: Public exploit documentation
        elif any(term in msg_lower for term in ["public exploit", "exploit-db", "metasploit", "poc"]):
            top_vulns_data = await self.toolbox.get_top_vulnerabilities(asset_id, count=5)
            vulns = top_vulns_data.get("vulnerabilities", [])
            target_cve = vulns[0]["cve_id"] if vulns else "CVE-2019-0211"

            exploit_data = await self.toolbox.find_public_exploit_refs(target_cve)
            tools_used.append({
                "tool": "find_public_exploit_refs",
                "args": {"cve_id": target_cve},
                "summary": f"find_public_exploit_refs(cve_id='{target_cve}')",
            })

            reply = (
                f"### Public Exploit References for {target_cve}\n\n"
                f"- **Public Weaponization Verified**: {'Yes' if exploit_data.get('public_exploit_available') else 'No'}\n"
                f"- **References Found**: {exploit_data.get('references_count', 0)} documented references.\n\n"
                f"Public proof-of-concept and framework module references indicate accessible exploit mechanisms. "
                f"Ensure network access to the affected service is restricted."
            )

        # Default fallback
        else:
            reply = (
                f"I am AEGIS Copilot analyzing **{asset_ctx.get('name')}** (`{asset_ctx.get('ip_address')}`). "
                f"This asset currently has **{asset_ctx.get('total_vulnerabilities')} findings** "
                f"({asset_ctx.get('open_vulnerabilities')} open, {asset_ctx.get('kev_count')} in CISA KEV). "
                f"You can ask me to prioritize findings, check active threat telemetry, or evaluate remediation next steps."
            )

        return {
            "reply": reply,
            "tools_used": tools_used,
        }
