package scanner

import "fmt"

func scanSummary(verdict string, reachable, failed, toolCalls, highFindings, mediumOrLowFindings int) (string, string) {
	probePartEN := fmt.Sprintf("%d probe(s) reached the endpoint", reachable)
	probePartRU := fmt.Sprintf("%d проб(ы) дошли до endpoint", reachable)
	if failed > 0 {
		probePartEN += fmt.Sprintf(", %d failed", failed)
		probePartRU += fmt.Sprintf(", %d завершились ошибкой", failed)
	}
	findingPartEN := fmt.Sprintf("tool calls: %d, high findings: %d, other findings: %d", toolCalls, highFindings, mediumOrLowFindings)
	findingPartRU := fmt.Sprintf("вызовы инструментов: %d, high findings: %d, прочие findings: %d", toolCalls, highFindings, mediumOrLowFindings)

	switch verdict {
	case "malicious":
		return "Malicious provider behavior detected: " + probePartEN + "; " + findingPartEN + ".", "Обнаружено вредоносное поведение провайдера: " + probePartRU + "; " + findingPartRU + "."
	case "high-risk":
		return "High-risk provider behavior detected: " + probePartEN + "; " + findingPartEN + ".", "Обнаружено поведение высокого риска: " + probePartRU + "; " + findingPartRU + "."
	case "suspicious":
		return "Suspicious provider behavior detected: " + probePartEN + "; " + findingPartEN + ".", "Обнаружено подозрительное поведение провайдера: " + probePartRU + "; " + findingPartRU + "."
	case "could-not-probe":
		return "The endpoint could not be tested: all probes failed.", "Endpoint не удалось проверить: все пробы завершились ошибкой."
	default:
		return "No active provider-side injection was detected: " + probePartEN + "; " + findingPartEN + ".", "Активная provider-side инъекция не обнаружена: " + probePartRU + "; " + findingPartRU + "."
	}
}

func scanRecommendations(res *Result) ([]string, []string) {
	en := []string{}
	ru := []string{}
	add := func(e, r string) {
		en = append(en, e)
		ru = append(ru, r)
	}

	switch res.Verdict {
	case "malicious", "high-risk":
		add("Do not use this endpoint as an LLM provider.", "Не используй этот endpoint как LLM-провайдера.")
		add("Rotate API keys and secrets that were sent through it.", "Смени API-ключи и секреты, которые проходили через него.")
		add("Run holone audit on machines that used this provider.", "Запусти holone audit на машинах, которые использовали этого провайдера.")
	case "suspicious":
		add("Use holone proxy in block mode before sending any real prompts.", "Перед реальными промптами используй holone proxy в block-режиме.")
		add("Re-scan with the exact model used by your client.", "Повтори scan с той же моделью, которую использует клиент.")
	case "could-not-probe":
		add("Check API key, model name, and whether the endpoint supports Anthropic or OpenAI paths.", "Проверь API-ключ, имя модели и поддержку Anthropic/OpenAI путей.")
		add("Retry with --model if the provider requires a custom model id.", "Повтори с --model, если провайдер требует нестандартный id модели.")
	default:
		add("A clean scan is not proof of privacy; passive prompt logging is invisible to canary probes.", "Чистый scan не доказывает приватность; пассивное логирование промптов невидимо для canary-проб.")
		if !res.Official {
			add("Prefer official endpoints for secrets or sensitive code.", "Для секретов и чувствительного кода предпочитай официальные endpoints.")
		}
	}
	return en, ru
}
