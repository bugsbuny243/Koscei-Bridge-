package services

// worseUnifiedGrade is the shared compatibility helper used by later unified
// Radar rule layers. The implementation lives in the v1.1.1 correction so all
// deterministic grade caps use one ordering contract.
func worseUnifiedGrade(current, cap string) string {
	return worseUnifiedGradeV111(current, cap)
}
