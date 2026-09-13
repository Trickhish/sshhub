package config

import (
	"gopkg.in/yaml.v3"
	"testing"
)

func TestBackendAliases(t *testing.T) {
	c := Config{Listen: Listen{SSH: ":22", Control: ":7000"}, HostKey: "key", Backends: []Backend{{ID: "nuc8_hoster", Mode: "reverse", Aliases: "hoster  hosting\tserver"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nuc8_hoster", "hoster", "hosting", "server"} {
		if b := c.BackendByName(name); b == nil || b.ID != "nuc8_hoster" {
			t.Fatalf("failed to resolve %q", name)
		}
	}
	if c.BackendByName("unknown") != nil || c.BackendByID("hoster") != nil {
		t.Fatal("aliases must not change canonical lookup")
	}
	data, err := yaml.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Backends[0].Aliases != c.Backends[0].Aliases {
		t.Fatal("aliases lost during save/load")
	}
}

func TestBackendAliasConflicts(t *testing.T) {
	for _, backends := range [][]Backend{
		{{ID: "a", Mode: "reverse", Aliases: "x"}, {ID: "b", Mode: "reverse", Aliases: "x"}},
		{{ID: "a", Mode: "reverse", Aliases: "b"}, {ID: "b", Mode: "reverse"}},
		{{ID: "b", Mode: "reverse"}, {ID: "a", Mode: "reverse", Aliases: "b"}},
		{{ID: "a", Mode: "reverse", Aliases: "a"}},
		{{ID: "a", Mode: "reverse", Aliases: "x x"}},
	} {
		c := Config{Listen: Listen{SSH: ":22", Control: ":7000"}, HostKey: "key", Backends: backends}
		if c.Validate() == nil {
			t.Fatalf("accepted conflicting names: %+v", backends)
		}
	}
}
