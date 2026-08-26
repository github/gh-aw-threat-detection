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
// The message is truncated because it may embed model-authored or parser text
// of unbounded length; use BuildTrustedCorrectionPrompt for feedback the
// detector composed itself.
func BuildCorrectionPrompt(prompt, prefix, message, instruction string) string {
	return BuildTrustedCorrectionPrompt(prompt, prefix, TruncateCorrectionMessage(message), instruction)
}

// BuildTrustedCorrectionPrompt appends detector-authored feedback to an original
// prompt without truncating it.
//
// The truncation applied by BuildCorrectionPrompt exists to bound text that
// originates outside the detector. Applying it to feedback the detector composed
// from its own fixed strings is a category error with a real cost: when more
// than one threat category is rejected at once, the joined explanation exceeds
// the bound and the trailing categories are cut mid-sentence, so the model is
// told its verdict was rejected without being told why for every category it
// must re-answer. Detector-authored feedback is bounded by construction, so it
// is passed through whole.
func BuildTrustedCorrectionPrompt(prompt, prefix, message, instruction string) string {
	return prompt + "\n\n" + prefix + ": " + message + "\n" + instruction
}
