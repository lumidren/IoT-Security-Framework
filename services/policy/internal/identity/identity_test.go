package identity

import (
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"
)

const (
	tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	dev    = "dev-8f3a1c2b9d4e5f60"
)

func TestIsDeviceID(t *testing.T) {
	cases := map[string]bool{
		dev:                       true,
		"dev-0123456789abcdef":    true,
		"dev-0123456789ABCDEF":    false,
		"dev-0123456789abcde":     false,
		"dev-0123456789abcdef0":   false,
		"device-0123456789abcdef": false,
		"":                        false,
		"svc-bridge":              false,
		"dev-0123456789abcdeg":    false,
	}
	for in, want := range cases {
		if got := IsDeviceID(in); got != want {
			t.Errorf("IsDeviceID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsTenantID(t *testing.T) {
	cases := map[string]bool{
		tenant:                                 true,
		"7E4B1A9C-3C2E-4A4F-9C1B-0F0D2D7A6A11": false,
		"7e4b1a9c3c2e4a4f9c1b0f0d2d7a6a11":     false,
		"":                                     false,
		"not-a-uuid":                           false,
	}
	for in, want := range cases {
		if got := IsTenantID(in); got != want {
			t.Errorf("IsTenantID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsServiceCN(t *testing.T) {
	for cn, want := range map[string]bool{"svc-bridge": true, "svc-registry": true, "svc-other": false, dev: false, "": false} {
		if got := IsServiceCN(cn); got != want {
			t.Errorf("IsServiceCN(%q) = %v, want %v", cn, got, want)
		}
	}
}

func TestParseDN(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    DN
		wantErr bool
	}{
		{
			name: "rfc4514",
			in:   "CN=" + dev + ",OU=" + tenant + ",O=IronMesh",
			want: DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant}},
		},
		{
			name: "rfc4514 with spaces and reversed order",
			in:   "O=IronMesh, OU=" + tenant + ", CN=" + dev,
			want: DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant}},
		},
		{
			name: "openssl oneline",
			in:   "/O=IronMesh/OU=" + tenant + "/CN=" + dev,
			want: DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant}},
		},
		{
			name: "multiple OU incl assurance marker",
			in:   "CN=" + dev + ",OU=" + tenant + ",OU=assurance:software,O=IronMesh",
			want: DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant, "assurance:software"}},
		},
		{
			name: "escaped comma and quoted value",
			in:   `CN=svc-bridge,O="Iron\, Mesh",OU=services`,
			want: DN{CN: "svc-bridge", O: []string{"Iron, Mesh"}, OU: []string{"services"}},
		},
		{
			name: "hex escape",
			in:   `CN=svc-bridge,O=Iron\2cMesh,OU=services`,
			want: DN{CN: "svc-bridge", O: []string{"Iron,Mesh"}, OU: []string{"services"}},
		},
		{
			name: "multi-valued rdn with plus",
			in:   "CN=svc-registry+OU=services,O=IronMesh",
			want: DN{CN: "svc-registry", O: []string{"IronMesh"}, OU: []string{"services"}},
		},
		{
			name: "oid attribute types",
			in:   "2.5.4.3=" + dev + ",2.5.4.11=" + tenant + ",2.5.4.10=IronMesh",
			want: DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant}},
		},
		{
			name: "unknown attributes ignored",
			in:   "C=DE,ST=Berlin,CN=" + dev + ",OU=" + tenant + ",O=IronMesh,emailAddress=x@y",
			want: DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant}},
		},
		{name: "empty", in: "   ", wantErr: true},
		{name: "empty rdn", in: "CN=" + dev + ",,O=IronMesh", wantErr: true},
		{name: "no attribute type", in: "CN=" + dev + ",IronMesh", wantErr: true},
		{name: "duplicate CN", in: "CN=a,CN=b", wantErr: true},
		{name: "dangling escape", in: `CN=a\`, wantErr: true},
		{name: "unterminated quote", in: `CN="a,O=b`, wantErr: true},
		{name: "bad hex escape", in: `CN=a\zz`, want: DN{CN: "azz"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDN(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDN(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDN(%q) error: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseDN(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDNFromName(t *testing.T) {
	got := DNFromName(pkix.Name{CommonName: dev, Organization: []string{"IronMesh"}, OrganizationalUnit: []string{tenant}})
	want := DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DNFromName = %+v, want %+v", got, want)
	}
}

func TestDNHelpers(t *testing.T) {
	d := DN{CN: dev, O: []string{"IronMesh"}, OU: []string{tenant, "assurance:software"}}
	if !d.HasO("IronMesh") || d.HasO("Other") {
		t.Error("HasO mismatch")
	}
	if !d.HasOU(tenant) || d.HasOU("services") {
		t.Error("HasOU mismatch")
	}
	if d.IsBootstrap() {
		t.Error("IsBootstrap should be false")
	}
	if d.Assurance() != "software" {
		t.Errorf("Assurance = %q, want software", d.Assurance())
	}
	if (DN{OU: []string{tenant}}).Assurance() != "hardware" {
		t.Error("default assurance should be hardware")
	}
	if !(DN{OU: []string{"bootstrap:" + tenant}}).IsBootstrap() {
		t.Error("IsBootstrap should be true")
	}
}

func TestDNTenant(t *testing.T) {
	cases := []struct {
		name    string
		dn      DN
		want    string
		wantErr error
	}{
		{name: "single tenant", dn: DN{OU: []string{tenant}}, want: tenant},
		{name: "tenant plus assurance", dn: DN{OU: []string{"assurance:software", tenant}}, want: tenant},
		{name: "bootstrap", dn: DN{OU: []string{"bootstrap:" + tenant}}, wantErr: ErrBootstrap},
		{name: "bootstrap and tenant", dn: DN{OU: []string{tenant, "bootstrap:" + tenant}}, wantErr: ErrBootstrap},
		{name: "none", dn: DN{OU: []string{"services"}}, wantErr: ErrNoTenant},
		{name: "empty", dn: DN{}, wantErr: ErrNoTenant},
		{name: "ambiguous", dn: DN{OU: []string{tenant, "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"}}, wantErr: ErrAmbiguousTenant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.dn.Tenant()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("tenant = %q, want %q", got, tc.want)
			}
		})
	}
}
