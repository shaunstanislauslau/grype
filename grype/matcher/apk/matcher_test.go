package apk

import (
	"github.com/anchore/grype/internal"
	"testing"

	grypeDB "github.com/anchore/grype-db/pkg/db/v3"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
)

func must(c syftPkg.CPE, e error) syftPkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

type mockStore struct {
	backend map[string]map[string][]grypeDB.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, name string) ([]grypeDB.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func TestSecDBOnlyMatch(t *testing.T) {

	secDbVuln := grypeDB.Vulnerability{
		// ID doesn't match - this is the key for comparison in the matcher
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{
			Type:          match.ExactDirectMatch,
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestBothSecdbAndNvdMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{
			Type:          match.ExactDirectMatch,
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestBothSecdbAndNvdMatches_DifferentPackageName(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		// Note: the product name is NOT the same as the target package name
		CPEs:      []string{"cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*"},
		Namespace: "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncumbrellaproject": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			// Note: the product name is NOT the same as the package name
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncumbrellaproject:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{
			Type:          match.ExactDirectMatch,
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdOnlyMatches(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []syftPkg.CPE{must(syftPkg.NewCPE(nvdVuln.CPEs[0]))}

	expected := []match.Match{
		{
			Type:          match.FuzzyMatch,
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 0.9,
					SearchedBy: common.SearchedByCPEs{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd",
					},
					Found: common.FoundCPEs{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestNvdMatchesWithSecDBFix(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "> 0.9.0, < 0.10.0", // note: this is not normal NVD configuration, but has the desired effect of a "wide net" for vulnerable indication
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11", // note: this does NOT include 0.9.11, so NVD and SecDB mismatch here... secDB should trump in this case
		VersionFormat:     "apk",
	}

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.11",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "", // note: empty value indicates that all versions are vulnerable
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.11",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestMatcherApk_matchBySourceIndirection(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    syftPkg.ApkPkg,
		Metadata: pkg.ApkMetadata{
			Source: "neutron-devel",
		},
	}

	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := matcher.matchBySourceIndirection(store, &d, p)

	assert.Len(t, actual, 2, "unexpected indirect matches count")

	foundCVEs := internal.NewStringSet()
	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		assert.Equal(t, match.ExactIndirectMatch, a.Type, "indirect match not indicated")
		assert.Equal(t, p.Name, a.Package.Name, "failed to capture original package name")
		for _, detail := range a.MatchDetails {
			assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
		}
	}

	for _, id := range []string{"CVE-2014-fake-2", "CVE-2013-fake-3"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}
	if t.Failed() {
		t.Logf("discovered CVES: %+v", foundCVEs)
	}
}
