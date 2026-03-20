from __future__ import annotations

import os

import httpx

from dbgov.logging import logger


def should_post_comment() -> bool:
    return os.environ.get("GITHUB_EVENT_NAME") == "pull_request" and bool(
        os.environ.get("GITHUB_REPOSITORY")
    )


def post_pr_comment(markdown: str) -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    ref = os.environ.get("GITHUB_REF", "")

    if not token or not repo:
        logger.warning("Missing GITHUB_TOKEN or GITHUB_REPOSITORY, skipping PR comment")
        return

    pr_number = _extract_pr_number(ref)
    if not pr_number:
        logger.warning("Could not extract PR number from GITHUB_REF, skipping", github_ref=ref)
        return

    api_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    existing_id = _find_existing_comment(api_url, headers)

    if existing_id:
        update_url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}"
        resp = httpx.patch(update_url, headers=headers, json={"body": markdown}, timeout=30)
    else:
        resp = httpx.post(api_url, headers=headers, json={"body": markdown}, timeout=30)

    if resp.status_code in (200, 201):
        logger.info("PR comment posted successfully", pr_number=pr_number)
    else:
        logger.error(
            "Failed to post PR comment",
            status_code=resp.status_code,
            response=resp.text,
        )


def _extract_pr_number(ref: str) -> str | None:
    parts = ref.split("/")
    if len(parts) >= 3 and parts[1] == "pull":
        return parts[2]
    return None


def _find_existing_comment(api_url: str, headers: dict[str, str]) -> int | None:
    resp = httpx.get(api_url, headers=headers, timeout=30)
    if resp.status_code != 200:
        return None

    for comment in resp.json():
        body = comment.get("body", "")
        if body.startswith("## 🔐 DBGov Plan"):
            return comment["id"]

    return None
