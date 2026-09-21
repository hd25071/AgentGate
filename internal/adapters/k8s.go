package adapters

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/hd25071/AgentGate/internal/action"
)

// K8sConfig configures the Kubernetes adapter.
//
// The adapter talks to the API server directly instead of pulling in
// k8s.io/client-go. See docs/adr/0002-kubernetes-transport.md: the gateway
// exists to be the smallest possible mediation point, and a 40-odd-package
// client tree is itself surface area. Server-side dry-run is a query parameter,
// not a client feature, so nothing of value is lost.
type K8sConfig struct {
	Name string
	Env  string
	// Mode is "cluster" or "mock".
	Mode string

	Server     string
	Token      string
	CAData     []byte
	Insecure   bool
	Kubeconfig string
	Context    string

	Timeout time.Duration
}

// K8sAdapter executes Kubernetes actions over the REST API.
type K8sAdapter struct {
	cfg    K8sConfig
	client *http.Client
	base   string
	token  string
}

// NewK8sAdapter resolves credentials and builds an HTTP client.
func NewK8sAdapter(cfg K8sConfig) (*K8sAdapter, error) {
	if cfg.Name == "" {
		cfg.Name = "k8s-primary"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	a := &K8sAdapter{cfg: cfg}

	server, token, ca, insecure, err := resolveK8sAuth(cfg)
	if err != nil {
		return nil, err
	}
	if server == "" {
		return nil, fmt.Errorf("kubernetes adapter: no API server configured (set AG_K8S_SERVER or run in-cluster)")
	}
	a.base = strings.TrimRight(server, "/")
	a.token = token

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in for local dev clusters only
	if len(ca) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("kubernetes adapter: CA bundle did not parse")
		}
		tlsCfg.RootCAs = pool
	}
	a.client = &http.Client{
		Timeout:       cfg.Timeout,
		Transport:     &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConnsPerHost: 4},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return a, nil
}

func (a *K8sAdapter) Kind() action.Kind { return action.KindK8s }
func (a *K8sAdapter) Name() string      { return a.cfg.Name }

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------

func resolveK8sAuth(cfg K8sConfig) (server, token string, ca []byte, insecure bool, err error) {
	// 1. Explicit configuration wins.
	if cfg.Server != "" {
		return cfg.Server, cfg.Token, cfg.CAData, cfg.Insecure, nil
	}
	// 2. In-cluster service account.
	const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	if host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
		tok, rerr := os.ReadFile(filepath.Join(saDir, "token"))
		if rerr != nil {
			return "", "", nil, false, fmt.Errorf("in-cluster service account token unreadable: %w", rerr)
		}
		cab, _ := os.ReadFile(filepath.Join(saDir, "ca.crt"))
		return "https://" + host + ":" + port, strings.TrimSpace(string(tok)), cab, false, nil
	}
	// 3. Kubeconfig.
	path := cfg.Kubeconfig
	if path == "" {
		if home, herr := os.UserHomeDir(); herr == nil {
			path = filepath.Join(home, ".kube", "config")
		}
	}
	if path != "" {
		if _, serr := os.Stat(path); serr == nil {
			return fromKubeconfig(path, cfg.Context)
		}
	}
	return "", "", nil, false, nil
}

type kubeconfigFile struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func fromKubeconfig(path, wanted string) (string, string, []byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", nil, false, err
	}
	var kc kubeconfigFile
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return "", "", nil, false, fmt.Errorf("parse kubeconfig: %w", err)
	}
	if wanted == "" {
		wanted = kc.CurrentContext
	}
	clusterName, userName := "", ""
	for _, c := range kc.Contexts {
		if c.Name == wanted {
			clusterName, userName = c.Context.Cluster, c.Context.User
		}
	}
	if clusterName == "" {
		return "", "", nil, false, fmt.Errorf("kubeconfig has no context %q", wanted)
	}
	var (
		server   string
		caData   []byte
		insecure bool
	)
	for _, c := range kc.Clusters {
		if c.Name != clusterName {
			continue
		}
		server = c.Cluster.Server
		insecure = c.Cluster.InsecureSkipTLSVerify
		switch {
		case c.Cluster.CertificateAuthorityData != "":
			caData, _ = base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorityData)
		case c.Cluster.CertificateAuthority != "":
			caData, _ = os.ReadFile(c.Cluster.CertificateAuthority)
		}
	}
	token := ""
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		token = strings.TrimSpace(u.User.Token)
		if token == "" && u.User.TokenFile != "" {
			b, _ := os.ReadFile(u.User.TokenFile)
			token = strings.TrimSpace(string(b))
		}
		// Client-certificate auth is intentionally not implemented: it would
		// mean the gateway holding a long-lived client key, which is exactly
		// what the token model exists to avoid. Use a projected token instead.
		if token == "" && (u.User.ClientCertificateData != "" || u.User.ClientCertificate != "") {
			return "", "", nil, false, fmt.Errorf(
				"kubeconfig user %q uses client-certificate auth, which this adapter does not support; "+
					"issue a short-lived token (kubectl create token) or run the gateway in-cluster", userName)
		}
	}
	return server, token, caData, insecure, nil
}

// ---------------------------------------------------------------------------
// Kind resolution
// ---------------------------------------------------------------------------

type gvr struct {
	Group      string
	Version    string
	Resource   string
	Namespaced bool
}

// kindTable covers the kinds an ops Agent actually names. Unknown kinds fall
// back to API discovery, so CRDs work without a table entry.
var kindTable = map[string]gvr{
	"pod":                            {"", "v1", "pods", true},
	"service":                        {"", "v1", "services", true},
	"configmap":                      {"", "v1", "configmaps", true},
	"secret":                         {"", "v1", "secrets", true},
	"serviceaccount":                 {"", "v1", "serviceaccounts", true},
	"persistentvolumeclaim":          {"", "v1", "persistentvolumeclaims", true},
	"namespace":                      {"", "v1", "namespaces", false},
	"node":                           {"", "v1", "nodes", false},
	"persistentvolume":               {"", "v1", "persistentvolumes", false},
	"endpoints":                      {"", "v1", "endpoints", true},
	"event":                          {"", "v1", "events", true},
	"deployment":                     {"apps", "v1", "deployments", true},
	"statefulset":                    {"apps", "v1", "statefulsets", true},
	"daemonset":                      {"apps", "v1", "daemonsets", true},
	"replicaset":                     {"apps", "v1", "replicasets", true},
	"job":                            {"batch", "v1", "jobs", true},
	"cronjob":                        {"batch", "v1", "cronjobs", true},
	"ingress":                        {"networking.k8s.io", "v1", "ingresses", true},
	"networkpolicy":                  {"networking.k8s.io", "v1", "networkpolicies", true},
	"role":                           {"rbac.authorization.k8s.io", "v1", "roles", true},
	"rolebinding":                    {"rbac.authorization.k8s.io", "v1", "rolebindings", true},
	"clusterrole":                    {"rbac.authorization.k8s.io", "v1", "clusterroles", false},
	"clusterrolebinding":             {"rbac.authorization.k8s.io", "v1", "clusterrolebindings", false},
	"storageclass":                   {"storage.k8s.io", "v1", "storageclasses", false},
	"customresourcedefinition":       {"apiextensions.k8s.io", "v1", "customresourcedefinitions", false},
	"mutatingwebhookconfiguration":   {"admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations", false},
	"validatingwebhookconfiguration": {"admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", false},
	"apiservice":                     {"apiregistration.k8s.io", "v1", "apiservices", false},
}

func (a *K8sAdapter) resolve(kind string) (gvr, error) {
	if g, ok := kindTable[strings.ToLower(kind)]; ok {
		return g, nil
	}
	g, err := a.discover(strings.ToLower(kind))
	if err != nil {
		return gvr{}, fmt.Errorf("cannot resolve kind %q: %w", kind, err)
	}
	return g, nil
}

// discover walks the API groups looking for a kind. One request per group
// version; the gateway's kind vocabulary is small so this is not a hot path.
func (a *K8sAdapter) discover(kindLower string) (gvr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.Timeout)
	defer cancel()

	type list struct {
		GroupVersion string `json:"groupVersion"`
		Resources    []struct {
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Namespaced bool   `json:"namespaced"`
		} `json:"resources"`
	}
	var groups struct {
		Groups []struct {
			Name     string `json:"name"`
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if err := a.getJSON(ctx, "/apis", &groups); err != nil {
		return gvr{}, err
	}
	var versions []string
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			versions = append(versions, v.GroupVersion)
		}
	}
	versions = append(versions, "v1")

	for _, gv := range versions {
		path := "/api/" + gv
		if strings.Contains(gv, "/") {
			path = "/apis/" + gv
		}
		var l list
		if err := a.getJSON(ctx, path, &l); err != nil {
			continue
		}
		for _, r := range l.Resources {
			if strings.EqualFold(r.Kind, kindLower) || strings.EqualFold(strings.TrimSuffix(r.Name, "s"), kindLower) {
				group := ""
				if i := strings.Index(gv, "/"); i >= 0 {
					group = gv[:i]
				}
				ver := gv
				if i := strings.Index(gv, "/"); i >= 0 {
					ver = gv[i+1:]
				}
				return gvr{Group: group, Version: ver, Resource: r.Name, Namespaced: r.Namespaced}, nil
			}
		}
	}
	return gvr{}, fmt.Errorf("no API resource matched kind %q", kindLower)
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

func (a *K8sAdapter) do(ctx context.Context, method, path string, query url.Values, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(raw)
	}
	u := a.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, 0, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		ct := "application/json"
		if v := query.Get("_contentType"); v != "" {
			ct = v
			query.Del("_contentType")
		}
		req.Header.Set("Content-Type", ct)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

func (a *K8sAdapter) getJSON(ctx context.Context, path string, out any) error {
	raw, code, err := a.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return apiError(code, raw)
	}
	return json.Unmarshal(raw, out)
}

func apiError(code int, raw []byte) error {
	var st struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &st)
	msg := st.Message
	if msg == "" {
		msg = strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
	}
	return fmt.Errorf("kubernetes API returned %d: %s", code, Sanitize(msg))
}

// objectPath builds the URL for one resource.
func (a *K8sAdapter) objectPath(g gvr, namespace, name string) string {
	var b strings.Builder
	if g.Group == "" {
		b.WriteString("/api/" + g.Version)
	} else {
		b.WriteString("/apis/" + g.Group + "/" + g.Version)
	}
	if g.Namespaced && namespace != "" {
		b.WriteString("/namespaces/" + url.PathEscape(namespace))
	}
	b.WriteString("/" + g.Resource)
	if name != "" {
		b.WriteString("/" + url.PathEscape(name))
	}
	return b.String()
}

// Health probes the API server.
func (a *K8sAdapter) Health(ctx context.Context) error {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := a.getJSON(ctx, "/version", &v); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Adapter implementation
// ---------------------------------------------------------------------------

// Snapshot reads back the current object so rollback can restore it.
func (a *K8sAdapter) Snapshot(ctx context.Context, ac *action.Action) (Snapshot, error) {
	snap := Snapshot{Adapter: a.Name(), TakenAt: time.Now().UnixMilli(), Data: json.RawMessage(`{}`)}
	if ac.Verb == action.VerbRead {
		snap.Strategy = "none"
		snap.Note = "read-only action: nothing to roll back"
		return snap, nil
	}
	if ac.Verb == action.VerbExec {
		snap.Strategy = "none"
		snap.Note = "exec has no rollback: whatever the process did to the filesystem stands"
		return snap, nil
	}

	g, err := a.resolve(ac.ArgString("kind"))
	if err != nil {
		return snap, err
	}
	name := ac.Resource.Name
	if ac.Verb == action.VerbScale {
		// Scale is a patch on an existing object; the full object is the
		// simplest correct undo.
		g, err = a.resolve(ac.ArgString("kind"))
		if err != nil {
			return snap, err
		}
	}

	raw, code, err := a.do(ctx, http.MethodGet, a.objectPath(g, ac.Resource.Namespace, name), nil, nil)
	if err != nil {
		return snap, err
	}
	switch {
	case code == http.StatusNotFound:
		snap.Strategy = "delete-on-rollback"
		snap.Note = "object does not exist yet; rollback will delete whatever this creates"
		return snap, nil
	case code >= 300:
		return snap, apiError(code, raw)
	}

	snap.Strategy = "restore-object"
	snap.Data = raw
	snap.Note = "full object captured; rollback re-applies the captured manifest"
	return snap, nil
}

// Preview runs a server-side dry run.
func (a *K8sAdapter) Preview(ctx context.Context, ac *action.Action) (PreviewResult, error) {
	out := PreviewResult{Adapter: a.Name(), Supported: true}
	g, err := a.resolve(ac.ArgString("kind"))
	if err != nil {
		return out, err
	}
	dry := url.Values{"dryRun": {"All"}}
	dry.Set("fieldManager", "agentgate")
	dry.Set("_contentType", "application/apply-patch+yaml")

	switch ac.Verb {
	case action.VerbRead:
		out.Impact = "read-only: no state changes"
		return out, nil
	case action.VerbDelete:
		raw, code, err := a.do(ctx, http.MethodDelete, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), dry, nil)
		if err != nil {
			return out, err
		}
		if code >= 300 {
			return out, apiError(code, raw)
		}
		out.Impact = fmt.Sprintf("dry-run: %s/%s would be deleted", ac.Resource.Namespace, ac.Resource.Name)
		out.Findings = append(out.Findings, "admission controllers accepted the dry run")
		return out, nil
	case action.VerbScale:
		g, _ = a.resolve(ac.ArgString("kind"))
		patch := map[string]any{"spec": map[string]any{"replicas": ac.ArgInt("replicas")}}
		raw, code, err := a.do(ctx, http.MethodPatch, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), dry, patch)
		if err != nil {
			return out, err
		}
		if code >= 300 {
			return out, apiError(code, raw)
		}
		out.Impact = fmt.Sprintf("dry-run: %s/%s would scale to %d replicas", ac.Resource.Namespace, ac.Resource.Name, ac.ArgInt("replicas"))
		return out, nil
	default:
		manifest, err := manifestOf(ac)
		if err != nil {
			return out, err
		}
		// Server-side apply dry run catches immutability errors, quota
		// violations and webhook rejections before anything is written.
		raw, code, err := a.do(ctx, http.MethodPatch, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), dry, manifest)
		if err != nil {
			return out, err
		}
		if code >= 300 {
			return out, apiError(code, raw)
		}
		out.Impact = fmt.Sprintf("dry-run: %s/%s would be applied", ac.Resource.Namespace, ac.Resource.Name)
		out.Findings = append(out.Findings, "server-side apply dry run passed")
		return out, nil
	}
}

// Execute performs the action.
func (a *K8sAdapter) Execute(ctx context.Context, ac *action.Action) (Result, error) {
	g, err := a.resolve(ac.ArgString("kind"))
	if err != nil {
		return Result{Adapter: a.Name(), Status: "failed"}, err
	}

	switch ac.Verb {
	case action.VerbRead:
		raw, code, err := a.do(ctx, http.MethodGet, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), nil, nil)
		if err != nil {
			return Result{Adapter: a.Name(), Status: "failed"}, err
		}
		if code >= 300 {
			return Result{Adapter: a.Name(), Status: "failed", Summary: apiError(code, raw).Error()}, apiError(code, raw)
		}
		var obj map[string]any
		_ = json.Unmarshal(raw, &obj)
		return Result{
			Adapter: a.Name(),
			Status:  "ok",
			Summary: fmt.Sprintf("read %s/%s", ac.Resource.Namespace, ac.Resource.Name),
			Output:  Sanitize(obj),
		}, nil

	case action.VerbDelete:
		raw, code, err := a.do(ctx, http.MethodDelete, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), nil, nil)
		if err != nil {
			return Result{Adapter: a.Name(), Status: "failed"}, err
		}
		if code >= 300 {
			e := apiError(code, raw)
			return Result{Adapter: a.Name(), Status: "failed", Summary: e.Error()}, e
		}
		return Result{
			Adapter: a.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("deleted %s %s/%s", ac.ArgString("kind"), ac.Resource.Namespace, ac.Resource.Name),
		}, nil

	case action.VerbScale:
		patch := map[string]any{"spec": map[string]any{"replicas": ac.ArgInt("replicas")}}
		raw, code, err := a.do(ctx, http.MethodPatch, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), url.Values{"_contentType": {"application/merge-patch+json"}}, patch)
		if err != nil {
			return Result{Adapter: a.Name(), Status: "failed"}, err
		}
		if code >= 300 {
			e := apiError(code, raw)
			return Result{Adapter: a.Name(), Status: "failed", Summary: e.Error()}, e
		}
		return Result{
			Adapter: a.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("scaled %s/%s to %d", ac.Resource.Namespace, ac.Resource.Name, ac.ArgInt("replicas")),
		}, nil

	case action.VerbExec:
		return Result{Adapter: a.Name(), Status: "failed"}, fmt.Errorf(
			"%w: interactive exec against a live cluster is deliberately unsupported; "+
				"an LLM with a pod shell has unbounded reach and none of the gateway's controls apply inside it. "+
				"Use a non-interactive debug Job instead", ErrNotSupported)

	default:
		manifest, err := manifestOf(ac)
		if err != nil {
			return Result{Adapter: a.Name(), Status: "failed"}, err
		}
		q := url.Values{"fieldManager": {"agentgate"}, "force": {"false"}, "_contentType": {"application/apply-patch+yaml"}}
		raw, code, err := a.do(ctx, http.MethodPatch, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), q, manifest)
		if err != nil {
			return Result{Adapter: a.Name(), Status: "failed"}, err
		}
		if code >= 300 {
			e := apiError(code, raw)
			return Result{Adapter: a.Name(), Status: "failed", Summary: e.Error()}, e
		}
		return Result{
			Adapter: a.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("applied %s %s/%s", ac.ArgString("kind"), ac.Resource.Namespace, ac.Resource.Name),
		}, nil
	}
}

// Rollback re-applies the captured object or deletes what was created.
func (a *K8sAdapter) Rollback(ctx context.Context, ac *action.Action, snap Snapshot) error {
	if snap.Strategy == "none" {
		return fmt.Errorf("no rollback available: %s", snap.Note)
	}
	g, err := a.resolve(ac.ArgString("kind"))
	if err != nil {
		return err
	}
	switch snap.Strategy {
	case "delete-on-rollback":
		raw, code, err := a.do(ctx, http.MethodDelete, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), nil, nil)
		if err != nil {
			return err
		}
		if code >= 300 && code != http.StatusNotFound {
			return apiError(code, raw)
		}
		return nil
	case "restore-object":
		var obj map[string]any
		if err := json.Unmarshal(snap.Data, &obj); err != nil {
			return fmt.Errorf("rollback: snapshot is not a valid object: %w", err)
		}
		q := url.Values{"fieldManager": {"agentgate"}, "force": {"true"}, "_contentType": {"application/apply-patch+yaml"}}
		raw, code, err := a.do(ctx, http.MethodPatch, a.objectPath(g, ac.Resource.Namespace, ac.Resource.Name), q, obj)
		if err != nil {
			return err
		}
		if code >= 300 {
			return apiError(code, raw)
		}
		return nil
	default:
		return fmt.Errorf("unknown snapshot strategy %q", snap.Strategy)
	}
}

func manifestOf(ac *action.Action) (map[string]any, error) {
	// The manifest lives in Raw for apply actions; re-parse it defensively.
	raw := ac.Raw
	raw = strings.TrimPrefix(raw, "manifest=")
	if raw == "" {
		return nil, fmt.Errorf("action carries no manifest")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("action manifest did not parse: %w", err)
	}
	return m, nil
}
