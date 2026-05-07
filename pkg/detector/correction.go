package detector

// TruncateCorrectionMessage limits parser feedback included in retry prompts.
func TruncateCorrectionMessage(message string) string {
	return string(TruncateCorrectionBytes([]byte(message)))
}

// TruncateCorrectionBytes limits byte-oriented parser feedback included in retry prompts.
func TruncateCorrectionBytes(message []byte) []byte {
	// maxCorrectionBytes applies to the original parser message before the
	// truncation suffix is appended.
	const maxCorrectionBytes = 512
	if len(message) <= maxCorrectionBytes {
		return message
	}
	truncated := make([]byte, 0, maxCorrectionBytes+len("...(truncated)"))
	truncated = append(truncated, message[:maxCorrectionBytes]...)
	truncated = append(truncated, "...(truncated)"...)
	return truncated
}

// BuildCorrectionPrompt appends bounded parser feedback to an original prompt.
func BuildCorrectionPrompt(prompt, prefix, message, instruction string) string {
	return prompt + "\n\n" + prefix + ": " + TruncateCorrectionMessage(message) + "\n" + instruction
}
