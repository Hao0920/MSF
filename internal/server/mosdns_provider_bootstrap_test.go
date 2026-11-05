package server

import (
	"reflect"
	"strings"
	"testing"
)

func TestProviderBootstrapValuesFromMihomoConfig(t *testing.T) {
	content := `proxy-providers:
  zed:
    type: http
    url: "https://User:secret@SUB.Example.COM.:8443/path?token=secret"
  alpha:
    url: "http://sub.example.com/another"
  file:
    type: file
    url: "https://file.example/list"
  manual:
    type: http
    url: "https://manual.example/list"
  msf_manual:
    type: http
    url: "https://manual-provider.example/list"
  ip:
    type: http
    url: "https://192.0.2.1/list"
  invalid:
    type: http
    url: "://broken"
`
	got, err := providerBootstrapValuesFromMihomoConfig(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"full:sub.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrap values = %#v, want %#v", got, want)
	}
	if strings.Contains(providerBootstrapFileContent(got), "secret") {
		t.Fatal("bootstrap file must not contain URL credentials or query values")
	}
}

func TestProviderBootstrapMalformedYAML(t *testing.T) {
	if _, err := providerBootstrapValuesFromMihomoConfig("proxy-providers: ["); err == nil {
		t.Fatal("expected malformed YAML error")
	}
}

func TestProviderBootstrapMosDNSTemplatePlacement(t *testing.T) {
	config, ok := runtimeTemplateText("mosdns/config.yaml")
	if !ok {
		t.Fatal("missing MosDNS config template")
	}
	for _, sequence := range []string{"sequence_6666", "sequence_requery"} {
		start := strings.Index(config, "- tag: "+sequence)
		if start < 0 {
			t.Fatalf("missing %s", sequence)
		}
		end := strings.Index(config[start+1:], "\n  - tag: ")
		if end < 0 {
			end = len(config) - start - 1
		}
		block := config[start : start+1+end]
		bootstrap := strings.Index(block, "qname $provider_bootstrap")
		aaaa := strings.Index(block, "#阻止AAAA类型的dns查询")
		if bootstrap < 0 || aaaa < 0 || bootstrap > aaaa {
			t.Fatalf("%s bootstrap rule must precede AAAA rejection", sequence)
		}
	}
}
