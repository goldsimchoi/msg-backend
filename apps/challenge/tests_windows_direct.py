import json
import os
import uuid
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.challenge.checker_auth import mint_job_token
from apps.challenge.checker_dispatch import checker_request, dispatch_submission
from apps.challenge.models import ExeSubmission
from apps.challenge.tests_exe_submissions import ExeFixtures, harmless_pe


POOL_ID = "00000000-0000-0000-0000-000000000001"


@override_settings(
    EXE_WINDOWS_DIRECT_RUNTIME_ENABLED=True,
    EXE_WINDOWS_RUNTIME_POOL_ID=POOL_ID,
    SCHEDULER_API_TOKEN="",
)
class WindowsDirectRuntimeTests(ExeFixtures, TestCase):
    def test_submission_uses_local_assignment_without_scheduler(self):
        with override_settings(SCHEDULER_API_TOKEN=""):
            row = self.accepted()
        self.assertEqual(row.status, ExeSubmission.Status.ASSIGNED)
        self.assertEqual(str(row.worker_id), POOL_ID)
        self.assertIsNotNone(row.lease_id)
        self.assertIsNone(row.lease_expires_at)
        self.assertEqual(row.config_snapshot["assignment_mode"], "broker_pool")
        with patch("apps.challenge.checker_dispatch.checker_request", return_value={"checker_job_id": "job-1"}) as send:
            dispatch_submission(row.pk)
        send.assert_called_once()
        row.refresh_from_db()
        self.assertEqual(row.dispatch_state, "CONFIRMED")
        self.assertEqual(row.checker_job_id, "job-1")

    def test_checker_metadata_selects_broker_pool_and_omits_scheduler_vm(self):
        row = self.accepted()
        row.config_snapshot["execution_provenance"] = {
            "checker_commit_sha": "a" * 40,
            "vm_template_sha256": "b" * 64,
            "driver_sha256": "c" * 64,
            "config_version": "fixture-v1",
        }
        row.save(update_fields=["config_snapshot"])
        captured = []

        class Response:
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def read(self, *_args):
                return json.dumps({"code": "SUCCESS", "data": {"submission_id": str(row.pk), "assignment_id": str(row.lease_id), "checker_job_id": "job-1"}}).encode()

        class Opener:
            def open(self, request, **_kwargs):
                captured.append(json.loads(request.data))
                return Response()

        with patch("apps.challenge.checker_dispatch.build_opener", return_value=Opener()):
            checker_request(row, "POST")
        self.assertEqual(captured[0]["selection_mode"], "broker_pool")
        self.assertNotIn("vm_id", captured[0])
        self.assertNotIn("readiness_check_id", captured[0])

    def test_runtime_fetch_and_result_callback_without_scheduler_lease(self):
        row = self.accepted()
        with patch("apps.challenge.checker_dispatch.checker_request", return_value={"checker_job_id": "job-1"}):
            dispatch_submission(row.pk)
        row.refresh_from_db()
        runtime = APIClient()
        runtime.credentials(HTTP_AUTHORIZATION="Bearer " + mint_job_token(row))
        payload = runtime.get(f"/internal/v1/checker-submissions/{row.pk}/payload")
        self.assertEqual(payload.status_code, 200)
        self.assertEqual(b"".join(payload.streaming_content), harmless_pe())
        observed = timezone.now().isoformat()
        event = {
            "request_version": 1,
            "event_id": str(uuid.uuid4()),
            "assignment_id": str(row.lease_id),
            "payload_sha256": row.payload_sha256,
            "event_type": "RESULT",
            "observed_at": observed,
            "checker_commit_sha": "a" * 40,
            "vm_template_sha256": "b" * 64,
            "driver_sha256": "c" * 64,
            "config_version": "fixture-v1",
            "execution_status": "COMPLETED",
            "started": True,
            "started_at": observed,
            "finished_at": observed,
            "output": {"stdout": "ok\n", "stderr": "", "encoding": "utf-8", "stdout_truncated": False, "stderr_truncated": False},
            "cleanup_complete": None,
            "exit_code": 0,
        }
        response = runtime.post(f"/internal/v1/checker-submissions/{row.pk}/events", event, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        row.refresh_from_db()
        self.assertEqual((row.status, row.stdout, row.exit_code), ("COMPLETED", "ok\n", 0))
        self.assertIsNone(row.lease_expires_at)

    def test_runtime_service_renews_job_token_after_long_vm_wait(self):
        row = self.accepted()
        url = f"/internal/v1/checker-submissions/{row.pk}/token"
        request = {"assignment_id": str(row.lease_id), "payload_sha256": row.payload_sha256}
        runtime = APIClient()
        self.assertEqual(runtime.post(url, request, format="json").status_code, 401)
        runtime.credentials(HTTP_AUTHORIZATION="Bearer " + os.environ["EXE_CHECKER_FIXTURE_TOKEN"])
        response = runtime.post(url, request, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["data"]["assignment_id"], str(row.lease_id))
        runtime.credentials(HTTP_AUTHORIZATION="Bearer " + response.data["data"]["job_token"])
        payload = runtime.get(f"/internal/v1/checker-submissions/{row.pk}/payload")
        self.assertEqual(payload.status_code, 200)
        self.assertEqual(b"".join(payload.streaming_content), harmless_pe())
