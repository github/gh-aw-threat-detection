package detector

// TruncateCorrectionMessage limits parser feedback included in retry prompts.
func TruncateCorrectionMessage(message string) string {
	const maxCorrectionBytes = 512
	if len(message) <= maxCorrectionBytes {
		return message
	}
	return message[:maxCorrectionBytes] + "...(truncated)"
}

// BuildCorrectionPrompt appends bounded parser feedback to an original prompt.
func BuildCorrectionPrompt(prompt, prefix, message, instruction string) string {
	return prompt + "\n\n" + prefix + ": " + TruncateCorrectionMessage(message) + "\n" + instruction
}
