package config

import (
	"testing"
)

func TestXAIAPIKeyEnvWins(t *testing.T) {
	t.Setenv("AI_API_KEY", "")
	t.Setenv("LITELLM_API_KEY", "")
	t.Setenv("XAI_API_KEY", "from-env")
	c := &Config{XAIAPIKeyField: "from-file"}
	if got := c.AIAPIKey(); got != "from-env" {
		t.Fatalf("got %q", got)
	}
	if !c.AIKeyFromEnv() {
		t.Fatal("expected key from env")
	}
}

func TestAIAPIKeyPrefersAIEnv(t *testing.T) {
	t.Setenv("AI_API_KEY", "ai-env")
	t.Setenv("XAI_API_KEY", "xai-env")
	c := &Config{XAIAPIKeyField: "from-file"}
	if got := c.AIAPIKey(); got != "ai-env" {
		t.Fatalf("got %q", got)
	}
}

func TestXAIAPIKeyFallsBackToField(t *testing.T) {
	t.Setenv("AI_API_KEY", "")
	t.Setenv("LITELLM_API_KEY", "")
	t.Setenv("XAI_API_KEY", "")
	c := &Config{XAIAPIKeyField: "from-file"}
	if got := c.AIAPIKey(); got != "from-file" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeAIRemapsLegacyModels(t *testing.T) {
	c := &Config{AIModel: "claude-opus-4-8", AIMaxIterations: 0}
	c.NormalizeAI()
	if c.AIModel != "GLM-5.3-Flash" {
		t.Fatalf("model=%s", c.AIModel)
	}
	if c.AIMaxIterations != 40 {
		t.Fatalf("max=%d", c.AIMaxIterations)
	}
	c2 := &Config{AIModel: "grok-4.6"}
	c2.NormalizeAI()
	if c2.AIModel != "GLM-5.3-Flash" {
		t.Fatalf("grok remap=%s", c2.AIModel)
	}
}

func TestAIBaseURLDefaultAndEnv(t *testing.T) {
	t.Setenv("AI_BASE_URL", "")
	c := &Config{}
	if got := c.AIBaseURL(); got != "https://litellm.合.xyz/v1" {
		t.Fatalf("default=%s", got)
	}
	t.Setenv("AI_BASE_URL", "https://litellm.example/v1/")
	if got := c.AIBaseURL(); got != "https://litellm.example/v1" {
		t.Fatalf("env fallback=%s", got)
	}
	c.AIBaseURLField = "https://from-ui.example/v1/"
	if got := c.AIBaseURL(); got != "https://from-ui.example/v1" {
		t.Fatalf("saved field should win over env, got %s", got)
	}
}

func TestApplyEnvSkipsPresentJSONKeys(t *testing.T) {
	t.Setenv("AI_MODEL", "from-env")
	t.Setenv("AI_ENABLED", "false")
	c := &Config{AIModel: "from-file", AIEnabled: true}
	c.applyEnvOverrides([]byte(`{"ai_model":"from-file","ai_enabled":true}`))
	if c.AIModel != "from-file" {
		t.Fatalf("model=%s", c.AIModel)
	}
	if !c.AIEnabled {
		t.Fatal("ai_enabled from file should stick")
	}
}

func TestApplyEnvFillsMissingJSONKeys(t *testing.T) {
	t.Setenv("AI_MODEL", "from-env")
	c := &Config{AIModel: "default"}
	c.applyEnvOverrides([]byte(`{"ai_enabled":true}`))
	if c.AIModel != "from-env" {
		t.Fatalf("model=%s", c.AIModel)
	}
}

func TestNormalizeAIFillsNewKnobs(t *testing.T) {
	c := &Config{}
	c.NormalizeAI()
	if c.AIMaxTokens != 8192 || c.AIHunterCycleMinutes != 12 || c.AIHunterHTTPPerMin != 20 {
		t.Fatalf("%+v", c)
	}
}
