package fileresolver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	file1 "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
	"io"
	"net/http"
	"syscall"
)

type byteReaderCloser struct {
	reader *bytes.Reader
}

func (b byteReaderCloser) Seek(offset int64, whence int) (int64, error) {
	return b.reader.Seek(offset, whence)
}
func (b byteReaderCloser) UnreadRune() error {
	return b.reader.UnreadRune()
}
func (b byteReaderCloser) ReadRune() (ch rune, size int, err error) {
	return b.reader.ReadRune()
}
func (b byteReaderCloser) UnreadByte() error {
	return b.reader.UnreadByte()
}
func (b byteReaderCloser) ReadByte() (byte, error) {
	return b.reader.ReadByte()
}
func (b byteReaderCloser) ReadAt(b1 []byte, off int64) (n int, err error) {
	return b.reader.ReadAt(b1, off)
}
func (b byteReaderCloser) Size() int64 {
	return b.reader.Size()
}
func (b byteReaderCloser) Len() int {
	return b.reader.Len()
}
func (b byteReaderCloser) Read(p []byte) (n int, err error) {
	return b.reader.Read(p)
}
func (b byteReaderCloser) Close() error {
	return nil
}

type tarFile struct {
	header  *tar.Header
	content []byte
}
type TarFs struct {
	fs         map[string]tarFile
	accessPath string
}

func NewTarFs(tarReader *tar.Reader, accessPath string) (*TarFs, error) {
	fs := &TarFs{
		fs:         make(map[string]tarFile),
		accessPath: accessPath,
	}
	for {
		next, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fs, err
		}
		nextTarFile := tarFile{
			header: next,
		}
		fs.fs[next.Name] = nextTarFile
		// From tar.Reader.Read:
		// > Calling Read on special types like [TypeLink], [TypeSymlink], [TypeChar],
		// > [TypeBlock], [TypeDir], and [TypeFifo] returns (0, [io.EOF]) regardless of what
		// > the [Header.Size] claims.
		if next.Typeflag != tar.TypeLink &&
			next.Typeflag != tar.TypeSymlink &&
			next.Typeflag != tar.TypeChar &&
			next.Typeflag != tar.TypeBlock &&
			next.Typeflag != tar.TypeDir &&
			next.Typeflag != tar.TypeFifo {
			all, err := io.ReadAll(tarReader)
			if err != nil {
				return fs, err
			}
			nextTarFile.content = all
			fs.fs[next.Name] = nextTarFile
		}
	}
	return fs, nil
}
func NewTarGzFsFromReader(tarGzReader io.Reader, accessPath string) (*TarFs, error) {
	gzReader, err := gzip.NewReader(tarGzReader)
	if err != nil {
		return nil, err
	}

	tarFs, err := NewTarFs(tar.NewReader(gzReader), accessPath)
	_ = gzReader.Close()

	return tarFs, err
}
func NewTarFsFromGzUrl(tarGzUrl string) (*TarFs, error) {
	get, err := http.Get(tarGzUrl)
	if err != nil {
		return nil, err
	}
	tarFs, err := NewTarGzFsFromReader(get.Body, tarGzUrl)
	_ = get.Body.Close()

	return tarFs, err
}

func (t *TarFs) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	content, ok := t.fs[location.Coordinates.RealPath]
	if !ok || len(content.content) == 0 {
		return nil, syscall.ENOENT
	}
	return byteReaderCloser{
		reader: bytes.NewReader(content.content),
	}, nil
}

func (t *TarFs) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	content, ok := t.fs[location.Coordinates.RealPath]
	if !ok || content.header == nil {
		return file.Metadata{}, syscall.ENOENT
	}
	return file1.NewMetadata(*content.header, byteReaderCloser{
		reader: bytes.NewReader(content.content),
	}), nil
}

func (t *TarFs) HasPath(path string) bool {
	content, ok := t.fs[path]
	if !ok {
		return false
	}
	// Linkname is only valid for Hard and Symlinks
	if content.header.Typeflag == tar.TypeSymlink ||
		content.header.Typeflag == tar.TypeLink {
		content, ok = t.fs[content.header.Linkname]
	}

	return ok
}

func (t *TarFs) FilesByPath(paths ...string) ([]file.Location, error) {
	var locations []file.Location
	for _, path := range paths {
		content := t.getFile(path)
		if content == nil {
			continue
		}
		locations = append(locations, t.getLocation(path, *content))
	}
	return locations, nil
}

func (t *TarFs) getFile(path string) *tarFile {
	content, ok := t.fs[path]
	for {
		if !ok {
			return nil
		}
		if !(content.header.Typeflag == tar.TypeReg ||
			content.header.Typeflag == tar.TypeLink ||
			content.header.Typeflag == tar.TypeSymlink) {
			return nil
		}
		if content.header.Typeflag == tar.TypeLink || content.header.Typeflag == tar.TypeSymlink {
			content, ok = t.fs[content.header.Linkname]
			continue
		}

		return &content
	}
}

func (t *TarFs) getLocation(path string, content tarFile) file.Location {
	return file.Location{
		LocationData: file.LocationData{
			Coordinates: file.Coordinates{
				RealPath:     content.header.Name,
				FileSystemID: t.accessPath,
			},
			AccessPath: path,
		},
		LocationMetadata: file.LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

func (t *TarFs) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var results []file.Location
	for _, pattern := range patterns {
		for location := range t.fs {
			matches, err := doublestar.Match(pattern, location)
			if err != nil {
				return nil, err
			}
			if !matches {
				continue
			}
			content := t.getFile(location)
			if content == nil {
				continue
			}
			results = append(results, t.getLocation(location, *content))
		}
	}
	return results, nil
}

// FilesByMIMEType fetches a set of file references which the contents have been classified as one of the given MIME Types.
func (t *TarFs) FilesByMIMEType(types ...string) ([]file.Location, error) {
	if len(types) == 0 {
		return nil, nil
	}
	var locations []file.Location
	for location := range t.fs {
		content := t.getFile(location)
		if content == nil {
			continue
		}
		included := false
		for _, typeElement := range types {
			if typeElement == file1.MIMEType(bytes.NewReader(content.content)) {
				included = true
				break
			}
		}
		if included {
			locations = append(locations, t.getLocation(location, *content))
		}
	}
	return locations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (t *TarFs) RelativeFileByPath(_ file.Location, path string) *file.Location {
	content := t.getFile(path)
	if content == nil {
		return nil
	}
	loc := t.getLocation(path, *content)
	return &loc
}

// AllLocations returns a channel of all file references from the underlying source.
// The implementation for this may vary, however, generally the following considerations should be made:
// - NO symlink resolution should be performed on results
// - returns locations for any file or directory
func (t *TarFs) AllLocations(_ context.Context) <-chan file.Location {
	ch := make(chan file.Location)
	run := func() {
		defer close(ch)
		for path, content := range t.fs {
			ch <- t.getLocation(path, content)
		}
	}
	go run()
	return ch
}
