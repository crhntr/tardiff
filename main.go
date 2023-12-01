package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"slices"
)

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
	defer closeAndIgnoreError(fileTo)
	gzipReaderFrom, err := gzip.NewReader(fileFrom)
	if err != nil {
		log.Fatal(err)
	}
	gzipReaderTo, err := gzip.NewReader(fileTo)
	if err != nil {
		log.Fatal(err)
	}
	readerFrom := tar.NewReader(gzipReaderFrom)
	readerTo := tar.NewReader(gzipReaderTo)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	filesFrom := readFiles(ctx, readerFrom)
	filesTo := readFiles(ctx, readerTo)

	cacheFrom := make(map[string]*File)
	cacheTo := make(map[string]*File)

	for filesFrom != nil && filesTo != nil {
		select {
		case file, ok := <-filesFrom:
			if !ok {
				filesFrom = nil
				continue
			}
			cacheFrom[file.Header.Name] = file
		case file, ok := <-filesTo:
			if !ok {
				filesFrom = nil
				continue
			}
			cacheTo[file.Header.Name] = file
		}
	}

	if len(cacheFrom) != len(cacheTo) {
		log.Println("file count mismatch from:", len(cacheFrom), "to:", len(cacheTo))
	}

	fromKeys := make([]string, 0, len(cacheFrom)+len(cacheTo))
	for key := range cacheFrom {
		fromKeys = append(fromKeys, key)
	}
	toKeys := make([]string, 0, len(cacheTo))
	for key := range cacheTo {
		toKeys = append(toKeys, key)
	}
	allKeys := append(fromKeys, toKeys...)
	slices.Sort(allKeys)
	allKeys = slices.Compact(allKeys)
	isSame := true
	for _, name := range allKeys {
		log.Println("file:", name)
		from, ok := cacheFrom[name]
		if !ok {
			log.Println("\tfile missing in to tarball:", name)
			continue
		}
		to, ok := cacheTo[name]
		if !ok {
			log.Println("\tfile missing from:", name)
			continue
		}
		isSame = isSame && diffFiles(allHeaderFields, to, from)
	}
	if err := ctx.Err(); err != nil {
		log.Fatal(ctx)
	}
	if !isSame {
		log.Println("files are different")
		os.Exit(1)
	}
	log.Println("files are the same")
}

func readFiles(ctx context.Context, reader *tar.Reader) chan *File {
	ch := make(chan *File)
	go func() {
		defer close(ch)
		for index := 0; ; index++ {
			if err := ctx.Err(); err != nil {
				return
			}
			header, err := reader.Next()
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Fatal(err)
			}
			sha1sum := sha1.New()
			sha256sum := sha256.New()
			w := io.MultiWriter(sha1sum, sha256sum)
			if _, err = io.Copy(w, reader); err != nil {
				log.Fatal(err)
			}
			ch <- &File{
				Index:     index,
				Header:    *header,
				Sha1Sum:   hex.EncodeToString(sha1sum.Sum(nil)),
				SHA256Sum: hex.EncodeToString(sha256sum.Sum(nil)),
			}
		}
	}()
	return ch
}

type File struct {
	Index     int
	Header    tar.Header
	SHA256Sum string
	Sha1Sum   string
}

func closeAndIgnoreError(c io.Closer) {
	_ = c.Close()
}

func diffFiles(allHeaderFields bool, fileTo, fileFrom *File) bool {
	isSame := true
	isSame = isSame && check("file index mismatch", fileFrom.Index, fileTo.Index)
	isSame = isSame && check("file mode mismatch", fileFrom.Header.Mode, fileTo.Header.Mode)
	isSame = isSame && check("file size mismatch", fileFrom.Header.Size, fileTo.Header.Size)
	if allHeaderFields {
		isSame = isSame && check("file mod time mismatch", fileFrom.Header.ModTime, fileTo.Header.ModTime)
		isSame = isSame && check("file type flag mismatch", fileFrom.Header.Typeflag, fileTo.Header.Typeflag)
		isSame = isSame && check("file link name mismatch", fileFrom.Header.Linkname, fileTo.Header.Linkname)
		isSame = isSame && check("file user id mismatch", fileFrom.Header.Uid, fileTo.Header.Uid)
		isSame = isSame && check("file user name mismatch", fileFrom.Header.Uname, fileTo.Header.Uname)
		isSame = isSame && check("file group name mismatch", fileFrom.Header.Gname, fileTo.Header.Gname)
		isSame = isSame && check("file group id mismatch", fileFrom.Header.Gid, fileTo.Header.Gid)
		isSame = isSame && check("file access time mismatch", fileFrom.Header.AccessTime, fileTo.Header.AccessTime)
		isSame = isSame && check("file change time mismatch", fileFrom.Header.ChangeTime, fileTo.Header.ChangeTime)
		isSame = isSame && check("file dev major mismatch", fileFrom.Header.Devmajor, fileTo.Header.Devmajor)
		isSame = isSame && check("file dev minor mismatch", fileFrom.Header.Devminor, fileTo.Header.Devminor)
	}
	isSame = isSame && check("file sha256sum mismatch", fileFrom.SHA256Sum, fileTo.SHA256Sum)
	isSame = isSame && check("file sha1sum mismatch", fileFrom.Sha1Sum, fileTo.Sha1Sum)
	return isSame
}

func check[T comparable](field string, to, from T) bool {
	isSame := to == from
	if !isSame {
		log.Println("\t", field, "mismatch\n\t\tto:", to, "\t\tfrom:", from)
	}
	return isSame
}
