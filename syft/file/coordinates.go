package file

import (
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sort"
)

// Coordinates contains the minimal information needed to describe how to find a file within any possible source object (e.g. image and directory sources)
type Coordinates struct {
	RealPath     string `json:"path" cyclonedx:"path"`                 // The path where all path ancestors have no hardlinks / symlinks
	FileSystemID string `json:"layerID,omitempty" cyclonedx:"layerID"` // An ID representing the filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank.
}

func NewCoordinates(realPath, fsID string) Coordinates {
	return Coordinates{
		RealPath:     realPath,
		FileSystemID: fsID,
	}
}

func (c Coordinates) ID() artifact.ID {
	f, err := artifact.IDByHash(c)
	if err != nil {
		// TODO: what to do in this case?
		log.Warnf("unable to get fingerprint of location coordinate=%+v: %+v", c, err)
		return ""
	}

	return f
}

func (c Coordinates) String() string {
	str := fmt.Sprintf("RealPath=%q", c.RealPath)

	if c.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", c.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (c Coordinates) Compare(other Coordinates) int {
	if i := sort.CompareOrd(c.RealPath, other.RealPath); i != 0 {
		return i
	}
	return sort.CompareOrd(c.FileSystemID, other.FileSystemID)
}
func (c Coordinates) TryCompare(other any) (bool, int) {
	if other, exists := other.(Coordinates); exists {
		return true, c.Compare(other)
	}
	return false, 0
}
