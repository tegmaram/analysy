/*
    YARA rules — "Linou Free" Fortnite cheat loader / payload / driver
    Author  : analysy (educational malware-analysis lab)
    Date    : 2026-11-07
    Licence : Educational Use Only — see ../LICENSE
    Ref     : ../analysis/ANALYSIS.md , ../analysis/IOCS.md

    Context : unsigned x64 console loader that elevates, kills capture/overlay
              software, drops and loads a WHQL-signed BYOVD driver, replaces an
              Easy Anti-Cheat asset and injects an embedded cheat DLL.
              See ../README.md before using this repository.

    Notes   : - Rule 1 targets the outer loader (contains all three payloads).
              - Rule 2 targets the extracted cheat DLL (also matches inside
                rule 1, because the blobs are stored unpacked in .rdata).
              - Rule 3 targets the borrowed, WHQL-signed kernel driver.
*/

rule Linou_Free_Fortnite_Loader
{
    meta:
        description      = "Linou Free - unsigned Fortnite cheat loader with embedded kernel driver and cheat DLL"
        author           = "analysy"
        date             = "2026-11-07"
        reference        = "https://github.com/tegmaram/analysy"
        sample_sha256    = "7d2c55b9d95203e966f70e5de8a04aa48daccd7a1b5ff9d0b17f5a9a06bc085a"
        family           = "Linou Free / linouservices"
        category         = "game cheat, PUP, BYOVD loader"
        licence          = "educational-use-only"

    strings:
        $pdb_loader   = "no sideload injector\\New injector\\Newinjector.pdb" ascii
        $pdb_payload  = "fortnite internal\\x64\\Release\\dll.pdb" ascii
        $url          = "https://files.catbox.moe/pvtjo9.png" ascii
        $ua           = "FortniteInjector/1.0" wide
        $console      = "linou free internal but cuter" wide
        $brand        = "linou free internal" ascii wide
        $discord      = "discord.gg/linouservices" wide
        $taunt        = "you just got kicked cutie" wide
        $meow         = "Making the cat meow" wide
        $meow_ok      = "Cat meowed successfully" wide
        $splash_tmp   = "fortnite_splash_download.png.tmp" wide
        $eac_path     = "FortniteGame\\Binaries\\Win64\\EasyAntiCheat" wide
        $splash_png   = "\\SplashScreen.png" wide
        $taskkill     = "taskkill /f /im" ascii wide
        $gobjects     = "[gobjects] wrote valid=" ascii
        $kb_drv       = "MmGetVirtualForPhysical" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            /*
               All alternatives require at least one loader-only artefact
               (its PDB path, its User-Agent, its console title or the splash
               download routine) so that the standalone cheat DLL does not
               trigger this rule.
            */
            ($pdb_loader and ($url or $ua)) or
            ($url and $ua and $splash_tmp) or
            ($console and 2 of ($meow*)) or
            ($pdb_loader and $discord and $taunt) or
            ($pdb_loader and $eac_path and $splash_png and $taskkill) or
            ($pdb_loader and 4 of ($taskkill, $gobjects, $kb_drv, $brand, $eac_path)) or
            ($ua and $splash_png and $pdb_payload)
        )
}

rule Linou_Free_Fortnite_Cheat_DLL
{
    meta:
        description    = "Linou Free / 'fortnite internal' in-process cheat DLL (UObject dumper + movement ability patches)"
        author         = "analysy"
        date           = "2026-11-07"
        sample_sha256  = "0b28f1d6a23044d5d3df258926004f9a5c1fd12c4af0517c94b7b78de36b3253"
        category       = "game cheat payload"
        licence        = "educational-use-only"

    strings:
        $pdb       = "fortnite internal\\x64\\Release\\dll.pdb" ascii
        $gobj1     = "[gobjects] wrote valid=%u empty=%u" ascii
        $gobj2     = "[gobjects] dump crashed, stopped" ascii
        $gobj3     = "[gobjects] progress %u/%u" ascii
        $kick      = "you just got kicked cutie!!" wide
        $discord   = "discord.gg/linouservices" wide
        $mv1       = "/Script/SlidingRuntime.FortMovementMode_Sliding" wide
        $mv2       = "/Script/WallJumpCodeRuntime.FortMovementMode_ExtWallJump" wide
        $mv3       = "/Script/FlyingCodeRuntime.FortMovementMode_ExtLogicFlying" wide
        $mv4       = "/ClamberingContent/Gameplay/FMM_ExtClamber.FMM_ExtClamber_C" wide
        $mv5       = "/Script/NitroGameplayRuntime.FortMovementMode_ExtLogicNitroState" wide
        $con       = "CONOUT$" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            2 of ($gobj*) or
            ($pdb and $kick) or
            ($kick and $discord) or
            (2 of ($mv*) and $con) or
            3 of ($mv*)
        )
}

rule Embeded_WHQL_Kernel_Driver_PAutel_BYOVD
{
    meta:
        description      = "KMDF unsigned-usage kernel driver with physical/process memory primitives, WHQL-signed for PAutel (BYOVD pattern)"
        author           = "analysy"
        date             = "2026-11-07"
        sample_sha256    = "01da64b789dcffbdd2f6aa44b2988ee92c707e1815124faeb6382389d1220927"
        category         = "kernel driver, BYOVD candidate"
        licence          = "educational-use-only"

    strings:
        /* vendor name is a BMPString inside the nested Authenticode blob */
        $vendor     = { 00 50 00 41 00 75 00 74 00 65 00 6C 00 20 00 49 00 6E 00 74 }
        $phys       = "MmGetVirtualForPhysical" ascii wide
        $mdl        = "MmMapLockedPagesSpecifyCache" ascii wide
        $attach     = "KeStackAttachProcess" ascii wide
        $protect    = "ZwProtectVirtualMemory" ascii wide
        $wdf        = "WdfVersionBind" ascii wide
        $kmdf       = "KmdfLibrary" wide
        $whcp       = "Microsoft Windows Hardware Compatibility Publisher" ascii
        $whql_ca    = "Microsoft Windows Third Party Component CA 2012" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        /*
           Native (kernel) subsystem or a driver-style section layout,
           plus the KMDF/system-memory import surface.
        */
        ($wdf and $kmdf) and
        (
            ($phys and $mdl) or
            ($attach and $protect) or
            $wdf
        ) and
        (
            $vendor or
            ($whcp and $whql_ca and $phys)
        )
}
