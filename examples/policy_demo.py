"""Demonstrate policy decisions without executing a tool or changing live state."""
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import accessible_approval_broker as broker
import broker_policy

with tempfile.TemporaryDirectory(prefix='approval-demo-') as temporary:
    root=Path(temporary)
    with patch.dict(os.environ, {'ACCESSIBLE_APPROVAL_TEST_MODE':'1','CODEX_ACCESSIBLE_APPROVAL_STATE_DIR':str(root/'state')}):
        with patch.object(broker, '_safe_routine_bash', return_value=False):
            payload={'session_id':'isolated-demo','cwd':str(root),'tool_name':'Bash','tool_input':{'command':'example-request-never-executed','description':'Demonstration'}}
            for mode in ('prompt','no_prompt'):
                policy=broker_policy.policy_path(broker._state_root())
                policy.write_text(json.dumps({'version':1,'mode':mode}))
                policy.chmod(0o600)
                decision=broker._permission_request(payload)['hookSpecificOutput']['decision']['behavior']
                print(mode+': '+('broker allows the request' if decision=='allow' else 'confirmation required'))
print('No shell, SSH, or UI action was executed.')
