package handlers

import "koschei/api/internal/services"

type transactionGuardAuthorityEvent struct {
	InstructionSource         string `json:"instruction_source"`
	InstructionIndex          int    `json:"instruction_index"`
	InnerSequence             int    `json:"inner_sequence,omitempty"`
	ParentProgramID           string `json:"parent_program_id,omitempty"`
	ProgramID                 string `json:"program_id"`
	Kind                      string `json:"kind"`
	Account                   string `json:"account,omitempty"`
	Mint                      string `json:"mint,omitempty"`
	Source                    string `json:"source,omitempty"`
	Destination               string `json:"destination,omitempty"`
	CurrentAuthority          string `json:"current_authority,omitempty"`
	NewAuthority              string `json:"new_authority,omitempty"`
	Delegate                  string `json:"delegate,omitempty"`
	WithdrawWithheldAuthority string `json:"withdraw_withheld_authority,omitempty"`
	AuthorityType             *int   `json:"authority_type,omitempty"`
	AuthorityTypeName         string `json:"authority_type_name,omitempty"`
	Scope                     string `json:"scope"`
	AmountRaw                 string `json:"amount_raw,omitempty"`
	Decimals                  *int   `json:"decimals,omitempty"`
	Amount                    string `json:"amount,omitempty"`
	TransferFeeBasisPoints    *int   `json:"transfer_fee_basis_points,omitempty"`
	MaximumFeeRaw             string `json:"maximum_fee_raw,omitempty"`
	ExpectedFeeRaw            string `json:"expected_fee_raw,omitempty"`
	TransferHookProgramID     string `json:"transfer_hook_program_id,omitempty"`
	Persistent                bool   `json:"persistent"`
	MintWide                  bool   `json:"mint_wide"`
	CanTransfer               bool   `json:"can_transfer"`
	CanBurn                   bool   `json:"can_burn"`
	EffectivelyUnlimited      bool   `json:"effectively_unlimited"`
	PostStateAvailable        bool   `json:"post_state_available"`
	ActiveAfterSimulation     *bool  `json:"active_after_simulation,omitempty"`
	PostDelegate              string `json:"post_delegate,omitempty"`
	PostDelegatedAmountRaw    string `json:"post_delegated_amount_raw,omitempty"`
	PostOwner                 string `json:"post_owner,omitempty"`
	PostCloseAuthority        string `json:"post_close_authority,omitempty"`
	PostMintAuthority         string `json:"post_mint_authority,omitempty"`
	PostFreezeAuthority       string `json:"post_freeze_authority,omitempty"`
	EvidenceStatus            string `json:"evidence_status"`
	Explanation               string `json:"explanation"`
}

type transactionGuardAuthoritySurfaceAnalysis struct {
	Requested              bool                             `json:"requested"`
	Required               bool                             `json:"required"`
	Available              bool                             `json:"available"`
	Complete               bool                             `json:"complete"`
	Status                 string                           `json:"status"`
	EventCount             int                              `json:"event_count"`
	PersistentEventCount   int                              `json:"persistent_event_count"`
	MintWideEventCount     int                              `json:"mint_wide_event_count"`
	ActiveDelegateCount    int                              `json:"active_delegate_count"`
	TransferHookProgramIDs []string                         `json:"transfer_hook_program_ids"`
	Events                 []transactionGuardAuthorityEvent `json:"events"`
	Limitations            []string                         `json:"limitations"`
}

type transactionGuardAuthorityInstruction struct {
	Source          string
	Index           int
	InnerSequence   int
	ParentProgramID string
	ProgramID       string
	Accounts        []string
	Data            []byte
}

type transactionGuardAuthoritySnapshots struct {
	PreOrder  []string
	PostOrder []string
	Pre       []*services.SolanaAccountInfo
	Post      []*services.SolanaAccountInfo
}
