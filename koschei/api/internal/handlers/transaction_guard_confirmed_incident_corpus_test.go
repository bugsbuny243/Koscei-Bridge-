package handlers

import "testing"

func TestTransactionGuardConfirmedIncidentCorpusNoSubjectsIsCompleteAndNonAuthoritative(t *testing.T) {
	out := (&Handler{}).collectTransactionGuardConfirmedIncidentCorpus(
		t.Context(), "solana-mainnet", "tx-sha256:test", transactionGuardDecodedTransaction{}, "",
	)
	if !out.Complete || out.Status != "no_subjects" {
		t.Fatalf("unexpected no-subject result: %+v", out)
	}
	if out.SubjectsChecked != 0 || out.IncidentCount != 0 || out.ActorsMatched != 0 {
		t.Fatalf("unexpected counts: %+v", out)
	}
	if out.VerdictAuthority || out.CausationClaim || out.RealWorldIdentityClaim || out.WrongdoingClaim || out.SafetyClaim {
		t.Fatalf("confirmed incident corpus must remain context-only: %+v", out)
	}
}

func TestTransactionGuardConfirmedIncidentCorpusUnavailableDBDoesNotCreateClaim(t *testing.T) {
	const recipient = "Vote111111111111111111111111111111111111111"
	decoded := transactionGuardDecodedTransaction{
		SOLTransfers: []transactionGuardDecodedSOLTransfer{
			{Kind: "transfer", Recipient: recipient, Lamports: "1"},
		},
	}
	out := (&Handler{}).collectTransactionGuardConfirmedIncidentCorpus(
		t.Context(), "solana-mainnet", "tx-sha256:test", decoded, "",
	)
	if out.Complete || out.Status != "source_unavailable" {
		t.Fatalf("unexpected unavailable result: %+v", out)
	}
	if out.SubjectsChecked != 1 {
		t.Fatalf("subjects_checked=%d want=1", out.SubjectsChecked)
	}
	if out.VerdictAuthority || out.CausationClaim || out.RealWorldIdentityClaim || out.WrongdoingClaim || out.SafetyClaim {
		t.Fatalf("unavailable corpus must not acquire authority: %+v", out)
	}
}
