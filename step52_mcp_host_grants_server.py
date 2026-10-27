
#!/usr/bin/env python3
"""Step 52: MCP proxy with a trusted-host grant channel.

Includes GenAI diagnostic logging to step52_guard_debug.json.

Security behavior is unchanged:
- Invalid grants are blocked.
- Unauthorized destinations are blocked.
- GenAI REVIEW and BLOCK do not authorize storage.
- Storage is simulated.

The localhost host channel is a prototype, not production authentication.
"""

import asyncio
import hmac
import inspect
import json
import os
import secrets
import sys
from contextlib import asynccontextmanager
from dataclasses import asdict, is_dataclass
from pathlib import Path

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

from step21_reference_gateway import ReferenceGateway
from step33_v3_ai_guard import ImprovedTrustGateAIGuard
from step40_frozen_evaluation import WORKFLOWS
from step45_authorized_gateway import TrustedGrantIssuer
from step50_all_tools_gateway import AllToolsGateway


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

DEBUG_FILE = ROOT / "step52_guard_debug.json"

_gateway = None
_issuer = None
_session_id = None


def response(decision, reason, **extra):
    return json.dumps({
        "decision": decision,
        "reason": reason,
        **extra
    })


def assessment_to_dict(assessment):
    """Convert an assessment to a JSON-compatible dictionary."""

    if is_dataclass(assessment):
        return asdict(assessment)

    if hasattr(assessment, "model_dump"):
        return assessment.model_dump()

    if isinstance(assessment, dict):
        return dict(assessment)

    fields = [
        "attack_detected",
        "attack_type",
        "risk_level",
        "intent_aligned",
        "recommended_action",
        "explanation",
        "reason",
        "confidence"
    ]

    return {
        field: getattr(assessment, field)
        for field in fields
        if hasattr(assessment, field)
    }


class DiagnosticAIGuard:
    """Wrap the real guard without changing its assessment."""

    def __init__(self):
        self.guard = ImprovedTrustGateAIGuard()

    async def assess(
        self,
        user_request,
        tool_output,
        proposed_tool,
        proposed_arguments,
        classification
    ):
        diagnostic = {
            "trusted_request": user_request,
            "proposed_tool": proposed_tool,
            "proposed_arguments": proposed_arguments,
            "classification": classification,
            "tool_output_type": type(tool_output).__name__,
            "tool_output_length": len(str(tool_output))
        }

        try:
            result = self.guard.assess(
                user_request=user_request,
                tool_output=tool_output,
                proposed_tool=proposed_tool,
                proposed_arguments=proposed_arguments,
                classification=classification
            )

            if inspect.isawaitable(result):
                result = await result

            diagnostic["assessment"] = assessment_to_dict(result)

            print(
                "\n=== TRUSTGATE GENAI ASSESSMENT ===",
                file=sys.stderr,
                flush=True
            )

            print(
                json.dumps(
                    diagnostic,
                    indent=2,
                    default=str
                ),
                file=sys.stderr,
                flush=True
            )

            return result

        except Exception as exc:
            diagnostic["error"] = {
                "type": type(exc).__name__,
                "message": str(exc)
            }

            print(
                "[TrustGate GenAI Error]",
                repr(exc),
                file=sys.stderr,
                flush=True
            )

            raise

        finally:
            # The file is for local debugging only.
            # Do not log raw document content or grant tokens.
            try:
                DEBUG_FILE.write_text(
                    json.dumps(
                        diagnostic,
                        indent=2,
                        default=str
                    ),
                    encoding="utf-8"
                )
            except Exception as exc:
                print(
                    "[TrustGate Diagnostic Write Error]",
                    repr(exc),
                    file=sys.stderr,
                    flush=True
                )


@asynccontextmanager
async def lifespan(server):
    global _gateway, _issuer, _session_id

    secret = os.environ.get(
        "TG52_HOST_SECRET", ""
    )

    port = int(
        os.environ.get("TG52_HOST_PORT", "0")
    )

    trusted_request = os.environ.get(
        "TG52_TRUSTED_REQUEST", ""
    )

    trusted_dest = os.environ.get(
        "TG52_ALLOWED_DEST", ""
    )

    if len(secret) < 40 or not (1024 <= port <= 65535):
        raise RuntimeError(
            "Trusted host secret and localhost port required"
        )

    if trusted_dest not in ("external", "local"):
        raise RuntimeError(
            "Invalid trusted destination"
        )

    if not trusted_request:
        raise RuntimeError(
            "Trusted user request is required"
        )

    if (
        trusted_dest == "external"
        and "external" not in trusted_request.lower()
    ):
        raise RuntimeError(
            "External export requires explicit trusted host request"
        )

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "server.py")]
    )

    async with stdio_client(params) as (reader, writer):

        async with ClientSession(reader, writer) as session:

            await session.initialize()

            _issuer = TrustedGrantIssuer()

            _session_id = secrets.token_urlsafe(18)

            backend = ReferenceGateway(
                session,
                WORKFLOWS["public_export"]
            )

            _gateway = AllToolsGateway(
                reference_gateway=backend,
                ai_guard=DiagnosticAIGuard(),
                issuer=_issuer,
                session_id=_session_id,
                user_request=trusted_request,
                allowed_reads=frozenset({
                    "read_public_notice"
                }),
                summarize=lambda content: content[:300]
            )

            async def host_control(r, w):

                try:
                    raw = await asyncio.wait_for(
                        r.readline(),
                        timeout=5
                    )

                    if len(raw) > 4096:
                        raise ValueError(
                            "Oversized host request"
                        )

                    data = json.loads(
                        raw.decode("utf-8")
                    )

                    supplied = data.get(
                        "secret", ""
                    )

                    if (
                        not isinstance(supplied, str)
                        or not hmac.compare_digest(
                            supplied,
                            secret
                        )
                    ):
                        answer = {
                            "ok": False,
                            "reason": "Host authentication failed"
                        }

                    elif data.get("operation") == "health":

                        answer = {
                            "ok": True
                        }

                    elif data.get("operation") == "issue":

                        ref = data.get("document_ref")
                        dest = data.get("destination")

                        documents = (
                            _gateway
                            ._AllToolsGateway__documents
                        )

                        doc = (
                            documents.get(ref)
                            if isinstance(ref, str)
                            else None
                        )

                        if (
                            not doc
                            or doc.get("source")
                            != "read_public_notice"
                            or dest != trusted_dest
                        ):
                            answer = {
                                "ok": False,
                                "reason": "Reference or scope denied"
                            }

                        else:
                            token = _issuer.issue(
                                session_id=_session_id,
                                document_ref=ref,
                                action="store_document_ref",
                                destination=dest
                            )

                            answer = {
                                "ok": True,
                                "grant_token": token
                            }

                    else:
                        answer = {
                            "ok": False,
                            "reason": "Unknown host operation"
                        }

                except Exception as exc:

                    answer = {
                        "ok": False,
                        "reason": (
                            "Invalid host request: "
                            + type(exc).__name__
                        )
                    }

                try:
                    w.write(
                        (
                            json.dumps(answer) + "\n"
                        ).encode("utf-8")
                    )

                    await w.drain()

                finally:
                    w.close()
                    await w.wait_closed()

            control = await asyncio.start_server(
                host_control,
                "127.0.0.1",
                port
            )

            try:
                yield

            finally:
                control.close()
                await control.wait_closed()

                _gateway = None
                _issuer = None
                _session_id = None


mcp = FastMCP(
    "TrustGate-Host-Authorized-MCP",
    lifespan=lifespan
)


async def dispatch(name, args):

    if _gateway is None:
        return response(
            "BLOCK",
            "Gateway unavailable",
            executed=False
        )

    try:
        result = await _gateway.call_tool(
            name,
            args
        )

        if name == "store_document_ref":

            print(
                "[TrustGate Step52]",
                f"decision={result.decision}",
                f"ai={result.ai_decision}",
                f"reason={result.reason}",
                file=sys.stderr,
                flush=True
            )

        return response(
            result.decision,
            result.reason,
            executed=result.executed,
            data=result.data,
            ai_decision=result.ai_decision
        )

    except Exception as exc:

        print(
            "[TrustGate Gateway Exception]",
            repr(exc),
            file=sys.stderr,
            flush=True
        )

        return response(
            "BLOCK",
            "Gateway exception: "
            + type(exc).__name__,
            executed=False
        )


@mcp.tool()
async def read_public_notice() -> str:
    """Read a public notice through TrustGate."""

    return await dispatch(
        "read_public_notice",
        {}
    )


@mcp.tool()
async def read_report() -> str:
    """Request a confidential report, blocked in this demo."""

    return await dispatch(
        "read_report",
        {}
    )


@mcp.tool()
async def summarize_report(document_ref: str) -> str:
    """Summarize a tracked document."""

    return await dispatch(
        "summarize_report",
        {
            "document_ref": document_ref
        }
    )


@mcp.tool()
async def store_document_ref(
    document_ref: str,
    workspace: str,
    grant_token: str
) -> str:
    """Store a document using a trusted-host-issued grant."""

    return await dispatch(
        "store_document_ref",
        {
            "document_ref": document_ref,
            "workspace": workspace,
            "grant_token": grant_token
        }
    )


if __name__ == "__main__":

    if not (ROOT / "server.py").is_file():
        raise SystemExit(
            "Missing server.py"
        )

    mcp.run(transport="stdio")
