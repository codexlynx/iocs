import "hash"

rule PoisonIvy_hash19 {
    meta:
        description = "PoisonIvy Configuration File"

	condition:
		hash.md5(0, filesize) == "5ee2958b130f9cda8f5f3fc1dc5249cf"
}
