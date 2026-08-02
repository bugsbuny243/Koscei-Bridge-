import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const {mapVerdictCard}=require('../verdict-card-market-context.js');

const base={
  generated_at:'2026-07-17T04:00:00Z',
  source_context:{launch_time:'2026-07-17T00:00:00Z'},
  final_verdict:{signed:true,signature:'abc123',verdict:'no_grade_trigger'},
  holder_intelligence:{available:true,top_owner_percentage:36},
  market:{available:true,liquidity_usd:100000},
  modules:[{module_id:'holder_concentration',signed:true,evidence_status:'VERIFIED',metrics:{owner_resolved_top_holder_pct:36}}]
};

test('burned LP evidence fills amount, status, accounts and slot',()=>{
  const vm=mapVerdictCard({...base,lp_control:{available:true,status:'burned',pool_address:'Pool111',lp_mint:'LP111',read_slot:777,token_reserve:1000000,quote_reserve:50000,burned_share_pct:99}});
  const row=vm.checklist.find(item=>item.id==='liquidity');
  assert.equal(row.state,'verified');
  assert.match(row.value,/burned \(99%\)/);
  assert.match(row.detail,/Pool111/);
  assert.match(row.detail,/slot 777/);
});

test('bonding curve is not applicable instead of pending',()=>{
  const vm=mapVerdictCard({...base,market:{available:false},lp_control:{available:false,status:'not_applicable',reason_code:'bonding_curve_no_amm_pool'}},{lang:'tr'});
  const row=vm.checklist.find(item=>item.id==='liquidity');
  assert.equal(row.state,'not_applicable');
  assert.match(row.value,/Bonding curve/);
});

test('Jupiter sell impact is labelled as routing simulation with slot',()=>{
  const vm=mapVerdictCard({...base,jupiter_market_context:{available:true,price_available:true,price_usd:0.25,price_block_id:800,sell_impact_available:true,estimated_price_impact_pct:12.5,quote_context_slot:889}});
  const row=vm.checklist.find(item=>item.id==='concentration');
  assert.match(row.value,/routing simulation/);
  assert.match(row.value,/12\.5%/);
  assert.match(row.value,/slot 889/);
  assert.match(row.detail,/Jupiter price/);
});

test('fixed-notional exit quotes are visible on the liquidity row',()=>{
  const payload={...base};
  payload.exit_liquidity={
    available:true,
    status:'complete',
    quote_only:true,
    tiers:[
      {requested_notional_usd:1000,available:true,status:'quoted',estimated_proceeds_usd:970,execution_shortfall_pct:3,quote_context_slot:901},
      {requested_notional_usd:10000,available:true,status:'quoted',estimated_proceeds_usd:8200,execution_shortfall_pct:18,quote_context_slot:902}
    ]
  };
  const vm=mapVerdictCard(payload);
  const row=vm.checklist.find(item=>item.id==='liquidity');
  assert.equal(row.state,'observed');
  assert.match(row.value,/Jupiter read-only exit simulation/);
  assert.match(row.value,/\$1,000\.00 sell → \$970\.00/);
  assert.match(row.value,/\$10,000\.00 sell → \$8,200\.00/);
  assert.match(row.detail,/18% execution shortfall/);
});

test('program row shows upgrade authority and deployment age without inferring intent',()=>{
  const payload={...base};
  payload.program_security={
    available:true,
    status:'complete',
    authority_coverage_complete:true,
    age_coverage_complete:true,
    programs:[{
      available:true,
      status:'upgrade_authority_open',
      role:'launch_program',
      program_id:'Program11111111111111111111111111111111111',
      upgrade_authority:'Authority111111111111111111111111111111111',
      upgrade_authority_open:true,
      immutable:false,
      age_available:true,
      last_deployment_or_upgrade_age_days:12.5
    }]
  };
  const vm=mapVerdictCard(payload);
  const row=vm.checklist.find(item=>item.id==='program');
  assert.equal(row.state,'verified');
  assert.match(row.value,/upgrade authority open/);
  assert.match(row.value,/12\.5 days ago/);
  assert.match(row.detail,/not proof of malicious intent/);
});
