package relationship

import (
	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/artifact"
	"slices"
)

// Sort takes a set of package-to-package relationships and sorts them in a stable order by name and version.
// Note: this does not consider package-to-other, other-to-package, or other-to-other relationships.
// TODO: ideally this should be replaced with a more type-agnostic sort function that resides in the artifact package.
func Sort(rels []artifact.Relationship) {
	slices.SortStableFunc(rels, cmptest.DefaultRelationshipComparer)
}
