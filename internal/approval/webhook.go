package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hd25071/AgentGate/internal/store"
)

// WebhookNotifier posts a pending-approval card to an HTTP endpoint.
//
// Two body shapes are supported: "generic" (the approval object itself, easy to
// consume from a script) and "feishu" (an interactive card, so the second stage
// of the rollout needs only a URL, not a new integration). DingTalk/WeCom land
// the same way -- only the envelope differs.
type WebhookNotifier struct {
	URL    string
	Shape  string // "generic" | "feishu"
	Client *http.Client
}

// NewWebhookNotifier builds a notifier.
func NewWebhookNotifier(url, shape string) *WebhookNotifier {
	if shape == "" {
		shape = "generic"
	}
	return &WebhookNotifier{
		URL:    url,
		Shape:  shape,
		Client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (w *WebhookNotifier) Name() string { return "webhook:" + w.Shape }

// Notify posts the card.
func (w *WebhookNotifier) Notify(ctx context.Context, ap *store.Approval) error {
	if w.URL == "" {
		return fmt.Errorf("webhook notifier has no URL")
	}
	var body any
	switch w.Shape {
	case "feishu":
		body = feishuCard(ap)
	default:
		body = map[string]any{
			"type":        "agentgate.approval.pending",
			"approval":    ap,
			"approve_url": fmt.Sprintf("/admin/approvals/%s/approve", ap.ID),
			"reject_url":  fmt.Sprintf("/admin/approvals/%s/reject", ap.ID),
			"note":        "approve by POSTing {\"actor\":\"<you>\",\"action_hash\":\"" + ap.ActionHash + "\"}",
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func feishuCard(ap *store.Approval) map[string]any {
	reasons := ""
	for _, r := range ap.Reasons {
		reasons += "• " + r + "\n"
	}
	approverHint := fmt.Sprintf("需要 %d 人审批；请求方 %s 不能自批", ap.Required, ap.Subject)
	return map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"config": map[string]any{"wide_screen_mode": true},
			"header": map[string]any{
				"template": "red",
				"title":    map[string]any{"tag": "plain_text", "content": "AgentGate 待审批动作 (" + ap.Risk + ")"},
			},
			"elements": []any{
				map[string]any{
					"tag": "div",
					"fields": []any{
						map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": "**Agent**\n" + ap.Subject}},
						map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": "**工具**\n" + ap.Tool}},
					},
				},
				map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": "**动作**\n" + ap.Summary}},
				map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": "**命中策略**\n" + reasons}},
				map[string]any{"tag": "hr"},
				map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": "**action_hash**\n`" + ap.ActionHash + "`\n" + approverHint}},
				map[string]any{"tag": "note", "elements": []any{
					map[string]any{"tag": "plain_text", "content": "审批时必须回填该 hash；动作参数改动一个字节即作废。"},
				}},
			},
		},
	}
}

// MultiNotifier fans out to several channels.
type MultiNotifier []Notifier

func (m MultiNotifier) Name() string {
	names := make([]string, 0, len(m))
	for _, n := range m {
		names = append(names, n.Name())
	}
	return fmt.Sprint(names)
}

// Notify attempts every channel and reports the first failure.
func (m MultiNotifier) Notify(ctx context.Context, ap *store.Approval) error {
	var firstErr error
	for _, n := range m {
		if err := n.Notify(ctx, ap); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
