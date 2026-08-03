package handlers

// Transaction Guard v2/v3 remain analysis-only until their incomplete-evidence
// branches have an explicit enforcement contract. The production Firewall
// endpoint uses currentTransactionFirewallPolicy instead.
const transactionFirewallMode = transactionFirewallShadowMode
