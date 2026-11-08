"""``/v1/firmware``, ``/v1/signing-keys`` and the local artifact download route."""

from __future__ import annotations

import base64
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse

from ..models import FirmwareOut, FirmwarePage, SigningKeyOut, rfc3339
from ..problems import Problem
from ..storage import ArtifactError, LocalArtifactStore
from ..upload import parse_firmware_upload
from .deps import Admin, Cursor, Limit, Viewer, container_of, services_of

router = APIRouter(tags=["firmware"])

UPLOAD_SCHEMA = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["image", "metadata"],
                    "properties": {
                        "image": {"type": "string", "format": "binary"},
                        "metadata": {
                            "type": "string",
                            "description": "JSON {product, version, version_code, "
                            "min_version_code?, notes?, severity?}",
                        },
                    },
                }
            }
        },
    }
}


@router.post(
    "/v1/firmware",
    status_code=201,
    response_model=FirmwareOut,
    openapi_extra=UPLOAD_SCHEMA,
    summary="Upload, hash, sign and store a firmware image (admin)",
)
async def upload_firmware(request: Request, principal: Admin) -> FirmwareOut:
    settings = container_of(request).settings
    parsed = await parse_firmware_upload(
        request.headers.get("content-type"),
        request.headers.get("content-length"),
        request.stream(),
        max_image=settings.max_image_bytes,
        max_metadata=settings.max_metadata_bytes,
    )
    with parsed:
        fw = await services_of(request).firmware.upload(principal, parsed)
    return FirmwareOut.of(fw)


@router.get("/v1/firmware", response_model=FirmwarePage)
async def list_firmware(
    request: Request,
    principal: Viewer,
    product: Annotated[str | None, Query(max_length=64)] = None,
    cursor: Cursor = None,
    limit: Limit = 50,
) -> FirmwarePage:
    page = await services_of(request).firmware.list_page(
        principal.tenant_id, product, cursor, limit
    )
    return FirmwarePage(items=[FirmwareOut.of(f) for f in page.items], next_cursor=page.next_cursor)


@router.get("/v1/firmware/by-hash/{sha256_hex}", response_model=FirmwareOut)
async def firmware_by_hash(request: Request, principal: Viewer, sha256_hex: str) -> FirmwareOut:
    return FirmwareOut.of(
        await services_of(request).firmware.by_hash(principal.tenant_id, sha256_hex)
    )


@router.get("/v1/firmware/{firmware_id}", response_model=FirmwareOut)
async def get_firmware(request: Request, principal: Viewer, firmware_id: str) -> FirmwareOut:
    return FirmwareOut.of(await services_of(request).firmware.get(principal.tenant_id, firmware_id))


@router.get(
    "/v1/firmware/{firmware_id}/manifest",
    response_class=Response,
    responses={200: {"content": {"application/cbor": {}}}},
)
async def get_manifest(request: Request, principal: Viewer, firmware_id: str) -> Response:
    fw = await services_of(request).firmware.get(principal.tenant_id, firmware_id)
    return Response(
        content=fw.signed_manifest,
        media_type="application/cbor",
        headers={"Content-Disposition": f'attachment; filename="{fw.product}-{fw.version}.sig"'},
    )


@router.get("/v1/firmware/{firmware_id}/image", status_code=302, response_class=RedirectResponse)
async def get_image(request: Request, principal: Viewer, firmware_id: str) -> RedirectResponse:
    services = services_of(request)
    fw = await services.firmware.get(principal.tenant_id, firmware_id)
    return RedirectResponse(await services.firmware.image_url(fw), status_code=302)


@router.get("/v1/signing-keys", response_model=list[SigningKeyOut], tags=["signing"])
async def signing_keys(request: Request, _principal: Viewer) -> list[SigningKeyOut]:
    signer = container_of(request).signer
    return [
        SigningKeyOut(
            key_id=k.key_id,
            algorithm=k.algorithm,
            public_key_b64=base64.b64encode(k.public_key).decode(),
            active=k.active,
            created_at=rfc3339(k.created_at) or "",
        )
        for k in signer.list_keys()
    ]


@router.get("/v1/artifacts/{key:path}", include_in_schema=False)
async def download_artifact(
    request: Request,
    key: str,
    exp: Annotated[int, Query()],
    sig: Annotated[str, Query(max_length=128)],
) -> FileResponse:
    """Device download for the filesystem store; authorised by the HMAC link only."""
    store = container_of(request).store
    if not isinstance(store, LocalArtifactStore):
        raise Problem(404, "artifact downloads are served by object storage")
    if not store.signer.verify(key, exp, sig):
        raise Problem(403, "download link invalid or expired")
    try:
        path = store.path_for(key)
    except ArtifactError as exc:
        raise Problem(404, "artifact not found") from exc
    if not path.is_file():
        raise Problem(404, "artifact not found")
    return FileResponse(path, media_type="application/octet-stream")
