from fastapi import HTTPException, status


ROLE_PERMISSIONS = {
    "candidate": frozenset(
        {"master_cv:read", "master_cv:write", "master_cv:delete"}
    ),
}


def authorize_resource_access(
    *,
    role: str,
    subject_id: str,
    owner_id: str,
    permission: str,
) -> None:
    if permission not in ROLE_PERMISSIONS.get(role, frozenset()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role does not permit this action",
        )
    if subject_id != owner_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found",
        )
