import "hash"

rule PoisonIvy_hash3 {
    meta:
        description = "Backdoor.Win32.FakeWinupdate"

	condition:
		hash.md5(0, filesize) == "b04d7fa1c7e3a8274ba81f48f06a5f4e"
}
