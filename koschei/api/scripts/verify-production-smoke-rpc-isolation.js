'use strict';

const fs = require('fs');
const path = require('path');

const workflowPath = path.resolve(__dirname, '../../../.github/workflows/public-product-smoke.yml');
const workflow = fs.readFileSync(workflowPath, 'utf8');

function requireText(value, label) {
  if (!workflow.includes(value)) throw new Error(`${label}_missing`);
}

function forbidText(value, label) {
  if (workflow.includes(value)) throw new Error(`${label}_present`);
}

requireText('- cron: "17 3 * * *"', 'daily_full_scan_schedule');
requireText("github.event_name == 'workflow_dispatch' || (github.event_name == 'schedule' && github.event.schedule == '17 3 * * *')", 'controlled_full_scan_condition');
requireText('Run full production investigation', 'full_scan_step');
requireText('Publish full scan outcome to issue 756', 'full_scan_issue_step');
forbidText("if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'\n        run: node koschei/api/scripts/verify-production-full-scan.js", 'push_full_scan_execution');
forbidText("if: (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && success()", 'push_full_scan_print');
forbidText("if: (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && always()", 'push_full_scan_publish');

console.log('production smoke RPC isolation contract OK');
