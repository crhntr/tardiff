package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"
	"slices"
	"strings"
)

func init() {
	log.Default().SetFlags(0)
}

func main() {
	var (
		allHeaderFields bool
	)
	flag.BoolVar(&allHeaderFields, "a", false, "check all header fields")
	flag.Parse()
	fileNameFrom := flag.Arg(0)
	if fileNameFrom == "" {
		log.Fatal("no from file name provided")
	}
	fileNameTo := flag.Arg(1)
	if fileNameTo == "" {
		log.Fatal("no to file name provided")
	}

	fileFrom, err := os.Open(fileNameFrom)
	if err != nil {
		log.Fatal(err)
	}
	defer closeAndIgnoreError(fileFrom)
	fileTo, err := os.Open(fileNameTo)
	if err != nil {
		log.Fatal(err)
	}
	var readFrom, readTo io.Reader = fileFrom, fileTo
	defer closeAndIgnoreError(fileTo)
	if isGzipped(fileNameFrom) {
		readFrom, err = gzip.NewReader(readFrom)
		if err != nil {
			log.Fatal(err)
		}
	}
	if isGzipped(fileNameTo) {
		readTo, err = gzip.NewReader(readTo)
		if err != nil {
			log.Fatal(err)
		}
	}
	readerFrom := tar.NewReader(readFrom)
	readerTo := tar.NewReader(readTo)

	filesFrom, err := readFiles(readerFrom)
	if err != nil {
		log.Fatal(err)
	}
	fileNamesFrom := fileNames(filesFrom...)
	filesTo, err := readFiles(readerTo)
	if err != nil {
		log.Fatal(err)
	}
	fileNamesTo := fileNames(filesTo...)
	check("number of files", len(filesFrom), len(filesTo))

	names := make([]string, 0, len(fileNamesFrom)+len(fileNamesTo))
	names = append(names, fileNamesFrom...)
	names = append(names, fileNamesTo...)
	slices.Sort(names)
	names = slices.Clip(slices.Compact(names))

	isSame := true
	for _, name := range names {
		find := func(file File) bool {
			return file.Header.Name == name
		}
		fromIndex := slices.IndexFunc(filesFrom, find)
		if fromIndex < 0 {
			log.Println("+ ", name)
			continue
		}
		toIndex := slices.IndexFunc(filesTo, find)
		if toIndex < 0 {
			log.Println("- ", name)
			continue
		}
		log.Println("% ", name)
		isSame = diffFiles(filesTo[toIndex], filesFrom[fromIndex], allHeaderFields) && isSame
	}
	if !isSame {
		log.Println("files are different")
		os.Exit(1)
	}
	log.Println("files are the same")
}

func readFiles(reader *tar.Reader) ([]File, error) {
	var result []File
	for index := 0; ; index++ {
		header, err := reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		sha1sum := sha1.New()
		sha256sum := sha256.New()
		w := io.MultiWriter(sha1sum, sha256sum)
		if _, err = io.Copy(w, reader); err != nil {
			log.Fatal(err)
		}
		result = append(result, File{
			Index:     index,
			Header:    *header,
			Sha1Sum:   hex.EncodeToString(sha1sum.Sum(nil)),
			SHA256Sum: hex.EncodeToString(sha256sum.Sum(nil)),
		})
	}
	return result, nil
}

type File struct {
	Index     int
	Header    tar.Header
	SHA256Sum string
	Sha1Sum   string
}

func fileNames(in ...File) []string {
	var names []string
	for _, file := range in {
		names = append(names, file.Header.Name)
	}
	return names
}

func closeAndIgnoreError(c io.Closer) {
	_ = c.Close()
}

func diffFiles(fileTo, fileFrom File, allHeaderFields bool) bool {
	isSame := true
	isSame = check("file size mismatch", fileFrom.Header.Size, fileTo.Header.Size) && isSame
	isSame = check("file sha256sum mismatch", fileFrom.SHA256Sum, fileTo.SHA256Sum) && isSame
	isSame = check("file sha1sum mismatch", fileFrom.Sha1Sum, fileTo.Sha1Sum) && isSame
	isSame = check("file mode mismatch", fileFrom.Header.Mode, fileTo.Header.Mode) && isSame
	if allHeaderFields {
		isSame = check("file mod time mismatch", fileFrom.Header.ModTime, fileTo.Header.ModTime) && isSame
		isSame = check("file type flag mismatch", fileFrom.Header.Typeflag, fileTo.Header.Typeflag) && isSame
		isSame = check("file link name mismatch", fileFrom.Header.Linkname, fileTo.Header.Linkname) && isSame
		isSame = check("file user id mismatch", fileFrom.Header.Uid, fileTo.Header.Uid) && isSame
		isSame = check("file user name mismatch", fileFrom.Header.Uname, fileTo.Header.Uname) && isSame
		isSame = check("file group name mismatch", fileFrom.Header.Gname, fileTo.Header.Gname) && isSame
		isSame = check("file group id mismatch", fileFrom.Header.Gid, fileTo.Header.Gid) && isSame
		isSame = check("file access time mismatch", fileFrom.Header.AccessTime, fileTo.Header.AccessTime) && isSame
		isSame = check("file change time mismatch", fileFrom.Header.ChangeTime, fileTo.Header.ChangeTime) && isSame
		isSame = check("file dev major mismatch", fileFrom.Header.Devmajor, fileTo.Header.Devmajor) && isSame
		isSame = check("file dev minor mismatch", fileFrom.Header.Devminor, fileTo.Header.Devminor) && isSame
		isSame = check("file index mismatch", fileFrom.Index, fileTo.Index) && isSame
	}
	return isSame
}

func isGzipped(fileName string) bool {
	return strings.HasSuffix(fileName, ".gz") ||
		strings.HasSuffix(fileName, ".tgz")
}

func check[T comparable](field string, from, to T) bool {
	isSame := to == from
	if !isSame {
		log.Println("\t", field, "mismatch\n\t\tto:", to, "\t\tfrom:", from)
	}
	return isSame
}
