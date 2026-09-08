package agent

const (
	// tokenBudget is the context we are willing to send per copilot turn.
	// Matches transcriptBudget (~4 chars/token) so trimTranscript and the
	// meter describe the same window.
	tokenBudget     = transcriptBudget / 4
	compactRatio    = 72 // percent of tokenBudget that triggers auto-compact
	keepTurnsAuto   = 4
	keepTurnsManual = 2
)

func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}

func messagesTokens(msgs []Message) int {
	n := 0
	for _, m := range msgs {
		n += estimateTokens(m.Content) + estimateTokens(m.ToolName) + 8
	}
	return n
}

func compactThreshold() int {
	return tokenBudget * compactRatio / 100
}

func contextTokens(system, summary string, msgs []Message) int {
	return estimateTokens(system) + estimateTokens(summary) + messagesTokens(msgs) + 24
}

func formatTok(n int) string {
	if n < 1000 {
		return itoa(n)
	}
	if n < 10_000 {
		whole, frac := n/1000, (n%1000)/100
		if frac == 0 {
			return itoa(whole) + "k"
		}
		return itoa(whole) + "." + itoa(frac) + "k"
	}
	return itoa((n+500)/1000) + "k"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
