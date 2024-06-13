package artifact

import (
	"github.com/anchore/syft/syft/sort"
	"reflect"
	"strings"
)

const (
	// OwnershipByFileOverlapRelationship (supports package-to-package linkages) indicates that the parent package
	// claims ownership of a child package since the parent metadata indicates overlap with a location that a
	// cataloger found the child package by. This relationship must be created only after all package cataloging
	// has been completed.
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"

	// EvidentByRelationship is a package-to-file relationship indicating the that existence of this package is evident
	// by the contents of a file. This does not necessarily mean that the package is contained within that file
	// or that it is described by it (either or both may be true). This does NOT map to an existing specific SPDX
	// relationship. Instead, this should be mapped to OTHER and the comment field be updated to show EVIDENT_BY.
	EvidentByRelationship RelationshipType = "evident-by"

	// ContainsRelationship (supports any-to-any linkages) is a proxy for the SPDX 2.2 CONTAINS relationship.
	ContainsRelationship RelationshipType = "contains"

	// DependencyOfRelationship is a proxy for the SPDX 2.2.1 DEPENDENCY_OF	relationship.
	DependencyOfRelationship RelationshipType = "dependency-of"

	// DescribedByRelationship is a proxy for the SPDX 2.2.2 DESCRIBED_BY relationship.
	DescribedByRelationship RelationshipType = "described-by"
)

func AllRelationshipTypes() []RelationshipType {
	return []RelationshipType{
		OwnershipByFileOverlapRelationship,
		ContainsRelationship,
		DependencyOfRelationship,
		DescribedByRelationship,
	}
}

type RelationshipType string

func (rel RelationshipType) Compare(other RelationshipType) int {
	return strings.Compare(string(rel), string(other))
}

type Relationship struct {
	From Identifiable
	To   Identifiable
	Type RelationshipType
	Data sort.TryComparable
}

func (rel Relationship) Compare(other Relationship) int {
	if ok, i := rel.From.TryCompare(other.From); ok {
		if i != 0 {
			return i
		}
	} else {
		if i := rel.From.ID().Compare(other.From.ID()); i != 0 {
			return i
		}
	}
	if ok, i := rel.To.TryCompare(other.To); ok {
		if i != 0 {
			return i
		}
	} else {
		if i := rel.To.ID().Compare(other.To.ID()); i != 0 {
			return i
		}
	}

	if i := rel.Type.Compare(other.Type); i != 0 {
		return i
	}

	if ok, i := rel.Data.TryCompare(other.Data); ok {
		return i
	}

	return sort.CompareOrd(reflect.ValueOf(rel.Data).Type().Name(), reflect.ValueOf(other.Data).Type().Name())
}
