import "hash"

rule PoisonIvy_hash15 {
    meta:
        description = "virus.exp.20146352"

	condition:
		hash.md5(0, filesize) == "19f967e27e21802fe92bc9705ae0a770"
}
