import "hash"

rule PoisonIvy_hash29 {
    meta:
        description = "PoisonIvy Configuration File"

	condition:
		hash.md5(0, filesize) == "81e1332d15b29e8a19d0e97459d0a1de"
}
