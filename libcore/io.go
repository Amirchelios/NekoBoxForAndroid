package libcore

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/ulikunitz/xz"
)

func Unxz(archive string, path string) error {
	i, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer i.Close()

	r, err := xz.NewReader(i)
	if err != nil {
		return err
	}

	o, err := os.Create(path)
	if err != nil {
		return err
	}
	defer o.Close()

	_, err = io.Copy(o, r)
	return err
}

func Unzip(archive string, path string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()

	err = os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}

	cleanRoot := filepath.Clean(path)
	rootPrefix := cleanRoot + string(os.PathSeparator)

	for _, file := range r.File {
		filePath := filepath.Clean(filepath.Join(cleanRoot, file.Name))
		if filePath != cleanRoot && !strings.HasPrefix(filePath, rootPrefix) {
			return E.New("zip path traversal blocked: ", file.Name)
		}

		if file.FileInfo().IsDir() {
			err = os.MkdirAll(filePath, os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}

		if file.Mode()&os.ModeSymlink != 0 {
			return E.New("zip symlink entry is not supported: ", file.Name)
		}

		err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm)
		if err != nil {
			return err
		}

		newFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode().Perm())
		if err != nil {
			return err
		}

		zipFile, err := file.Open()
		if err != nil {
			newFile.Close()
			return err
		}

		var errs error
		_, err = io.Copy(newFile, zipFile)
		errs = E.Errors(errs, err)
		errs = E.Errors(errs, common.Close(zipFile, newFile))
		if errs != nil {
			return errs
		}
	}

	return nil
}
