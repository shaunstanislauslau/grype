package common

import (
	"fmt"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/jinzhu/copier"
)


func MatchBySourceIndirection(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	metadata, ok := p.Metadata.(pkg.DpkgMetadata)
	if !ok {
		return nil, nil
	}

	// ignore packages without source indirection hints
	if metadata.Source == "" {
		return []match.Match{}, nil
	}

	// use source package name for exact package name matching
	var indirectPackage pkg.Package

	err := copier.Copy(&indirectPackage, p)
	if err != nil {
		return nil, fmt.Errorf("failed to copy package: %w", err)
	}

	// use the source package name
	indirectPackage.Name = metadata.Source

	matches, err := FindMatchesByPackageDistro(store, d, indirectPackage, upstreamMatcher)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	for idx := range matches {
		matches[idx].Type = match.ExactIndirectMatch
		matches[idx].Package = p
	}

	return matches, nil
}

