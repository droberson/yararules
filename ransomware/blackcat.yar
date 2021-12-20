rule blackcat_ransomware
{
	meta:
		description = "BlackCat ransomware"
		language = "rust"
		reference = "https://samples.vx-underground.org/samples/Families/BlackCatRansomware/"

	strings:
		$ = "Speed:  Mb/s, Data: Mb/Mb, Files processed: /, Files scanned: "

	condition:
		all of them
}

rule blackcat_ransomware_onion
{
	meta:
		description = ".onion domains associated with BackCat ransomware"

	strings:
		$ = "alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion" ascii wide
		$ = "mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion" ascii wide
		$ = "sty5r4hhb5oihbq2mwevrofdiqbgesi66rvxr5sr573xgvtuvr4cs5yd.onion" ascii wide
		$ = "zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion" ascii wide


	condition:
		any of them
}

rule blackcat_ransomware_public_key
{
	meta:
		description = "BlackCat ransomware public key strings"

	strings:
		$ = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt9uYkHzaizNXg/S11ncTTLybkMtqrKW8gg6TyzbGWnRNROl9O+l1VZBLG0xiMt1mZbuStl8Lt3l1vlkMa92kgLjN+UfKmq3KhBEheN2uMmR0WpwV83kceVRmzr5lug4RyQ/xA6/OXK4NptDIT4L6CUTBWMyk2mmY0Cq9HyyrjdnHeAXWAcQGFEac7W4jTjONZqI+lgScPewS+cPFnz1hAD0IAqzj5X2mZVSfFGR3tDoIe42jw5wb6W2yi8zb3mgKrGtTBbw0Ppj0UgKrmdN5iFmfUQHLEzKAakDggLcBtrW1o5+4WMaZOLw8maU5byvjXu3F3i3GdQe8SKTYcVK5OQIDAQAB"
		$ = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApw3tWdMaWJvNf2Mejy5H0Y6kuj+lstNpwFyismGDEYhWKPps9c68xl+84o6uLKfqPzNvLnSxlVa6DitcJGeKJEQkzN+C1e1KsfzM63jHybREB2hs+dHbqBq4dbamIQcTrrr4mKzuHJ7aok4mlpRx2Un1XOJaodoV7xOHO7ui5v6uK39MJ3rvitSEBvv5oI0WDlp3IFmtd6UM6r2nygY1ncAUuasalZgF1Vaz7VXOWyX2ReQHbYWWRCR1qyKMQcBtjT5POXx9B8ek1pnU4p65kGe9M794Bhhh20GN24gY5a+zwXwstaNTO9luwd4xjjRQAVsDgjrjkzti27G11ICn6wIDAQAB"

	condition:
		any of them
}
