package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/terawatthour/ipc-go/internal/structures"
)

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type MappingProvider[V any] struct {
	cache structures.CircularBuffer[netip.Addr, V]

	db   *maxminddb.Reader
	hash string

	dbLock sync.RWMutex

	accountId       string
	accountPassword string
}

func NewCountryProvider(accountId string, password string) MappingProvider[structures.CountryInfo] {
	return MappingProvider[structures.CountryInfo]{
		cache:           structures.NewCircularBuffer[netip.Addr, structures.CountryInfo](4096),
		dbLock:          sync.RWMutex{},
		accountId:       accountId,
		accountPassword: password,
	}
}

func CheckCorrectHash(hash []byte) bool {
	if len(hash) != 64 {
		return false
	}

	dst := make([]byte, 64)

	_, err := hex.Decode(dst, hash)
	return err == nil
}

func (p *MappingProvider[V]) LoadDatabase(hmmdbPath string) error {
	file, err := os.Open(hmmdbPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := make([]byte, 64)
	if _, err := file.Read(hash); err != nil {
		return err
	}
	if !CheckCorrectHash(hash) {
		return errors.New("hash invalid")
	}

	databaseContent, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	db, err := maxminddb.OpenBytes(databaseContent)
	if err != nil {
		return err
	}

	p.db = db
	p.hash = string(hash)

	return nil
}

func (p *MappingProvider[V]) Update(dbUrl string, hashUrl string) error {
	client := http.Client{}
	req, err := http.NewRequest("GET", hashUrl, nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(p.accountId, p.accountPassword)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	hash := make([]byte, 64)
	if _, err := res.Body.Read(hash); err != nil {
		return err
	}
	if !CheckCorrectHash(hash) {
		return errors.New("malformed hash on remote")
	}
	if p.hash == string(hash) {
		return errors.New("database already up-to date")
	}

	req, err = http.NewRequest("GET", dbUrl, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.accountId, p.accountPassword)

	res, err = client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	uncompressedStream, err := gzip.NewReader(res.Body)
	if err != nil {
		return err
	}

	archive := tar.NewReader(uncompressedStream)
	_, err = FindInArchive(archive, "GeoLite2-Country.mmdb")
	if err != nil {
		return err
	}

	database, err := io.ReadAll(archive)
	if err != nil {
		return err
	}

	databaseReader, err := maxminddb.OpenBytes(database)
	if err != nil {
		return err
	}
	defer databaseReader.Close()

	if err := databaseReader.Verify(); err != nil {
		return err
	}

	dst, err := os.OpenFile("/data/mappings.hmmdb", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer dst.Close()

	if n, err := dst.Write(hash); err != nil {
		return err
	} else if n != 64 {
		return errors.New("failed to write database hash to the file")
	}

	if _, err := io.Copy(dst, bytes.NewReader(database)); err != nil {
		return err
	}

	return p.LoadDatabase("/data/mappings.hmmdb")
}

func FindInArchive(tar *tar.Reader, needle string) (int64, error) {
	for true {
		header, err := tar.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}

		parts := strings.SplitAfterN(header.Name, "/", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[1]
		if name == needle {
			return header.Size, nil
		}
	}

	return 0, errors.New("file not found in the archive")
}

func (p *MappingProvider[V]) Lookup(ip netip.Addr) (V, error) {
	var dst V

	if cachedCountry, inCache := p.cache.Get(ip); inCache {
		return cachedCountry, nil
	}

	if err := p.db.Lookup(ip).Decode(&dst); err != nil {
		return dst, err
	}

	p.cache.Insert(ip, dst)

	return dst, nil
}

var IncorrectAddressError = ErrorResponse{Code: 4001, Message: "incorrect IP address provided"}
var InternalServerError = ErrorResponse{Code: 5001, Message: "internal server error"}
var CountryNotFoundError = ErrorResponse{Code: 4041, Message: "IP address not found in the country database"}
var NoClientKeyError = ErrorResponse{Code: 4011, Message: "client key not included in the request"}
var WrongClientKeyError = ErrorResponse{Code: 4012, Message: "incorrect client key"}
var NoAdminKeyError = ErrorResponse{Code: 4011, Message: "admin key not included in the request"}
var WrongAdminKeyError = ErrorResponse{Code: 4012, Message: "incorrect admin key"}

func ProtectClient(keys []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.Get("x-ipc-key")
		if key == "" {
			return c.Status(http.StatusUnauthorized).JSON(NoClientKeyError)
		}

		if !slices.Contains(keys, key) {
			return c.Status(http.StatusUnauthorized).JSON(WrongClientKeyError)
		}

		return c.Next()
	}
}
func ProtectAdmin(adminKey string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.Get("x-ipc-admin-key")
		if key == "" {
			return c.Status(http.StatusUnauthorized).JSON(NoClientKeyError)
		}

		if key != adminKey {
			return c.Status(http.StatusUnauthorized).JSON(WrongClientKeyError)
		}

		return c.Next()
	}
}

func main() {
	accountId := flag.String("account-id", "", "MaxMind Account ID which will used to fetch the IP databases")
	password := flag.String("password", "", "password of the account specified by the account-id flag")
	adminKey := flag.String("admin-key", "", "key used for performing admin actions")

	flag.Parse()

	keys := flag.Args()

	if *accountId == "" || *password == "" || *adminKey == "" {
		flag.Usage()
		os.Exit(1)
	}

	countryProvider := NewCountryProvider(*accountId, *password)
	if err := countryProvider.LoadDatabase("/data/countries.hmmdb"); err != nil {
		log.Println(err)
	}

	app := fiber.New()

	app.Post("/update/country", ProtectAdmin(*adminKey), func(c *fiber.Ctx) error {
		if err := countryProvider.Update("https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz", "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz.sha256"); err != nil {
			log.Println("failed updating country database:", err)
			return c.Status(http.StatusInternalServerError).JSON(InternalServerError)
		}

		return nil
	})

	app.Get("/resolve/country/:ip", ProtectClient(keys), func(c *fiber.Ctx) error {
		ip, err := netip.ParseAddr(c.Params("ip"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(IncorrectAddressError)
		}

		countryInfo, err := countryProvider.Lookup(ip)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(InternalServerError)
		}

		if countryInfo.Country.GeonameID == 0 {
			return c.Status(http.StatusNotFound).JSON(CountryNotFoundError)
		}

		return c.JSON(countryInfo)
	})

	app.Listen(":8000")
}
