package detector

// TruncateCorrectionMessage limits parser feedback included in retry prompts.
func TruncateCorrectionMessage(message string) string {
	const maxCorrectionBytes = 512
	if len(message) <= maxCorrectionBytes {
		return message
	}
	return message[:maxCorrectionBytes] + "...(truncated)"
}
