package services

import "strings"

var arvisBaseAssetMints = map[string]bool{
	"So11111111111111111111111111111111111111112":  true,
	"Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": true,
	"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": true,
}

func selectArvisTargetMint(mints []string) string {
	for _, mint := range mints {
		mint = strings.TrimSpace(mint)
		if mint != "" && isLikelyRadarSolanaAddress(mint) && !arvisBaseAssetMints[mint] {
			return mint
		}
	}
	for _, mint := range mints {
		mint = strings.TrimSpace(mint)
		if mint != "" && isLikelyRadarSolanaAddress(mint) {
			return mint
		}
	}
	return ""
}
