package structures

type CountryInfo struct {
	Continent struct {
		Code      string            `maxminddb:"code" json:"code"`
		GeonameID int               `maxminddb:"geoname_id" json:"geoname_id"`
		Names     map[string]string `maxminddb:"names" json:"names"`
	} `maxminddb:"continent" json:"continent"`
	Country struct {
		GeonameID int               `maxminddb:"geoname_id" json:"geoname_id"`
		IsoCode   string            `maxminddb:"iso_code" json:"iso_code"`
		Names     map[string]string `maxminddb:"names" json:"names"`
	} `maxminddb:"country" json:"country"`
	RegisteredCountry struct {
		GeonameID int               `maxminddb:"geoname_id" json:"geoname_id"`
		IsoCode   string            `maxminddb:"iso_code" json:"iso_code"`
		Names     map[string]string `maxminddb:"names" json:"names"`
	} `maxminddb:"registered_country" json:"registered_country"`
}
